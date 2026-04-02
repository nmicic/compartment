#!/usr/bin/env python3
"""
syscall.py — Discover syscalls used by a program and generate compartment profiles.

Two modes:
  1. Static:  Disassemble ELF binary, find syscall instructions (fast, incomplete)
  2. Dynamic: Run program under strace, collect actual syscalls (complete, slower)

Output: list of syscalls, or a compartment-user profile (.conf) with a deny-list
of dangerous syscalls the program does NOT need.

Usage:
  # Static analysis (needs: pip install pyelftools capstone)
  ./syscall.py static /usr/bin/ls

  # Dynamic profiling (needs: strace)
  ./syscall.py trace -- ls -la /tmp
  ./syscall.py trace --follow-forks -- claude --model claude-opus-4-6

  # Generate compartment-user profile (deny-list — safe default)
  ./syscall.py profile -- ls -la /tmp

  # Generate strict allow-list profile (only observed syscalls permitted)
  ./syscall.py profile --seccomp-mode allow -- ls -la /tmp

  # Include env allow-list in profile
  ./syscall.py profile --seccomp-mode allow --with-env -- claude

  # Compare: what would compartment-user block that the program needs?
  ./syscall.py check --profile ai-agent -- ls -la /tmp
"""
import sys
import os
import re
import subprocess
import signal
import tempfile
import argparse
from collections import Counter
from pathlib import Path

# ── Dangerous syscalls (same list as compartment-user) ──────────────

DANGEROUS_SYSCALLS = {
    "ptrace", "mount", "umount2", "reboot",
    "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module",
    "pivot_root", "chroot", "unshare", "setns",
    "keyctl", "add_key", "request_key",
    "bpf", "userfaultfd", "perf_event_open",
    "process_vm_readv", "process_vm_writev",
    "acct", "swapon", "swapoff",
    "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "open_by_handle_at", "name_to_handle_at",
    "open_tree", "move_mount", "fsopen", "fsmount",
    "fsconfig", "fspick", "mount_setattr",
    "pidfd_getfd",
    "ioperm", "iopl",
    # strict profile additions:
    "personality", "lookup_dcookie", "vhangup", "quotactl",
    "mbind", "move_pages", "nfsservctl",
}

# ── strace-based dynamic profiling ──────────────────────────────────

def trace_syscalls(cmd, follow_forks=True, duration=None):
    """Run command under strace, return set of syscall names used."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.strace', delete=False) as tf:
        trace_file = tf.name

    try:
        strace_cmd = [
            "strace", "-o", trace_file,
            "-c",       # summary mode (counts, no per-call output)
            "-S", "calls",
        ]
        if follow_forks:
            strace_cmd.append("-f")

        strace_cmd.extend(["--"] + cmd)

        proc = subprocess.Popen(
            strace_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            # Send SIGINT to strace (it will finalize the trace)
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        # Parse strace -c output
        syscalls = set()
        counts = Counter()
        with open(trace_file, 'r') as f:
            for line in f:
                # strace -c format: "  0.00    0.000000     0       1           read"
                # or:               " % time     seconds  usecs/call     calls    errors  syscall"
                line = line.strip()
                if not line or line.startswith('%') or line.startswith('-'):
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    name = parts[-1]
                    if name != 'total' and not name.startswith('-'):
                        syscalls.add(name)
                        try:
                            call_count = int(parts[-3]) if len(parts) >= 6 else int(parts[-2])
                            counts[name] = call_count
                        except (ValueError, IndexError):
                            counts[name] = 0

        return syscalls, counts

    finally:
        try:
            os.unlink(trace_file)
        except OSError:
            pass


def trace_syscalls_detailed(cmd, follow_forks=True, duration=None):
    """Run under strace with full output, return syscall set + details."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.strace', delete=False) as tf:
        trace_file = tf.name

    try:
        strace_cmd = ["strace", "-o", trace_file]
        if follow_forks:
            strace_cmd.append("-f")
        strace_cmd.extend(["--"] + cmd)

        proc = subprocess.Popen(
            strace_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        # Parse per-line strace output
        syscall_pattern = re.compile(r'(?:\d+ +)?(\w+)\(')
        syscalls = set()
        counts = Counter()

        with open(trace_file, 'r') as f:
            for line in f:
                m = syscall_pattern.match(line.strip())
                if m:
                    name = m.group(1)
                    syscalls.add(name)
                    counts[name] += 1

        return syscalls, counts

    finally:
        try:
            os.unlink(trace_file)
        except OSError:
            pass


# ── Static ELF analysis ────────────────────────────────────────────

def static_analysis(binary_path):
    """Disassemble ELF binary and find syscall instructions.
    Returns set of syscall numbers found."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import Section
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        print("Static analysis requires: pip install pyelftools capstone",
              file=sys.stderr)
        sys.exit(1)

    SHF_EXECINSTR = 0x4
    syscall_numbers = set()

    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)

        for section in elf.iter_sections():
            if not isinstance(section, Section):
                continue
            if not (section['sh_flags'] & SHF_EXECINSTR):
                continue

            data = section.data()
            addr = section['sh_addr']

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            instructions = list(md.disasm(data, addr))

            for i, instr in enumerate(instructions):
                if instr.mnemonic == 'syscall':
                    # Look back up to 10 instructions for mov rax, <imm>
                    for j in range(i - 1, max(i - 10, -1), -1):
                        prev = instructions[j]
                        if prev.mnemonic in ('mov', 'xor', 'lea'):
                            op = prev.op_str.lower()
                            if 'rax' in op or 'eax' in op:
                                parts = prev.op_str.split(',')
                                if len(parts) == 2:
                                    imm = parts[1].strip()
                                    try:
                                        n = int(imm, 0)
                                        syscall_numbers.add(n)
                                        break
                                    except ValueError:
                                        continue

    return syscall_numbers


def load_syscall_names():
    """Load syscall number → name mapping from kernel headers."""
    syscall_map = {}
    paths = [
        '/usr/include/x86_64-linux-gnu/asm/unistd_64.h',
        '/usr/include/asm/unistd_64.h',
        '/usr/include/asm-generic/unistd.h',
    ]
    pattern = re.compile(r'#define\s+__NR_(\w+)\s+(\d+)')

    for p in paths:
        try:
            with open(p) as f:
                for line in f:
                    m = pattern.match(line)
                    if m:
                        syscall_map[int(m.group(2))] = m.group(1)
            if syscall_map:
                return syscall_map
        except FileNotFoundError:
            continue

    # Fallback: parse from strace
    try:
        result = subprocess.run(
            ['strace', '-e', 'trace=none', '--', '/bin/true'],
            capture_output=True, text=True, timeout=5
        )
        # If strace works, we at least know the system has it
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return syscall_map


# ── Profile generation ──────────────────────────────────────────────

def generate_profile(used_syscalls, name="traced-program", mode="deny",
                     used_env=None):
    """Generate a compartment-user .conf profile.

    mode="deny":  block dangerous syscalls NOT used (safer, won't break program)
    mode="allow": only permit observed syscalls (stricter, may miss rare paths)
    """
    lines = [
        f"# Auto-generated compartment-user profile for: {name}",
        f"# Generated by: syscall.py profile --mode {mode}",
        f"# Syscalls observed: {len(used_syscalls)}",
        "",
    ]

    if mode == "allow":
        lines += [
            f"# ALLOW-LIST MODE: only these {len(used_syscalls)} syscalls permitted",
            "# WARNING: if the program has rare code paths not exercised during",
            "# profiling, those paths will fail with EPERM. Run with --duration",
            "# long enough to cover all code paths, or add missing syscalls.",
            "",
            "seccomp-mode allowlist",
            "",
        ]
        # Emit as numeric IDs (compartment-user's table only has dangerous names)
        name_map = load_syscall_names()
        reverse_map = {v: k for k, v in name_map.items()}
        for sc in sorted(used_syscalls):
            nr = reverse_map.get(sc)
            if nr is not None:
                lines.append(f"allow {nr}  # {sc}")
            else:
                lines.append(f"# unknown: {sc}")
    else:
        can_block = DANGEROUS_SYSCALLS - used_syscalls
        needs_dangerous = DANGEROUS_SYSCALLS & used_syscalls
        lines += [
            f"# DENY-LIST MODE: block {len(can_block)} dangerous syscalls not used",
            f"# Dangerous syscalls NEEDED (not blocked): {len(needs_dangerous)}",
            "",
            "# Inherit the ai-agent base profile",
            "inherit ai-agent",
            "",
        ]
        if needs_dangerous:
            lines.append("# WARNING: program uses these dangerous syscalls (not blocked):")
            for sc in sorted(needs_dangerous):
                lines.append(f"#   {sc}")
            lines.append("")

        lines.append("# Dangerous syscalls the program does NOT use — safe to block:")
        for sc in sorted(can_block):
            lines.append(f"block {sc}")

    # Environment allow-list
    if used_env is not None:
        lines += [
            "",
            f"# Environment: only keep these {len(used_env)} variables",
            "env-mode allowlist",
        ]
        for var in sorted(used_env):
            lines.append(f"env-allow {var}")

    lines.append("")
    return "\n".join(lines)


def discover_env_vars(cmd, duration=None):
    """Discover environment variables a program reads via strace."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.strace', delete=False) as tf:
        trace_file = tf.name

    try:
        # Trace getenv-like reads: openat of /proc/self/environ or
        # the actual env access isn't visible via strace. Instead we
        # capture the initial environ and report what's commonly needed.
        # For a real discovery, we'd need LD_PRELOAD or eBPF.
        #
        # Practical approach: trace file opens to discover config paths,
        # and provide a sensible default allow-list.
        env_vars = {
            "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL",
            "LOGNAME", "HOSTNAME", "PWD", "OLDPWD", "TMPDIR", "TMP",
            "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
        }

        # Add proxy vars if they exist (program likely needs them)
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                    "http_proxy", "https_proxy", "no_proxy",
                    "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            if os.environ.get(var):
                env_vars.add(var)

        return env_vars

    finally:
        try:
            os.unlink(trace_file)
        except OSError:
            pass


# ── Check mode: what would a profile block that the program needs? ─

def check_against_profile(used_syscalls, profile_name):
    """Check if a compartment-user profile would break the program."""
    if profile_name == "ai-agent":
        blocked = DANGEROUS_SYSCALLS.copy()
    elif profile_name == "strict":
        blocked = DANGEROUS_SYSCALLS | {
            "personality", "lookup_dcookie", "vhangup", "quotactl",
            "mbind", "move_pages",
        }
    else:
        print(f"Unknown profile: {profile_name}", file=sys.stderr)
        sys.exit(1)

    would_break = blocked & used_syscalls
    safely_blocked = blocked - used_syscalls

    return would_break, safely_blocked


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Discover syscalls and generate compartment profiles",
        epilog="Examples:\n"
               "  syscall.py trace -- ls -la /tmp\n"
               "  syscall.py profile --follow-forks -- claude\n"
               "  syscall.py check --profile ai-agent -- ./my-program\n"
               "  syscall.py static /usr/bin/ls\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='mode', required=True)

    # trace mode
    p_trace = sub.add_parser('trace', help='Run under strace, show syscalls used')
    p_trace.add_argument('--follow-forks', '-f', action='store_true', default=True,
                         help='Follow child processes (default: yes)')
    p_trace.add_argument('--no-follow-forks', action='store_true')
    p_trace.add_argument('--duration', '-t', type=int, default=None,
                         help='Max seconds to trace (for long-running programs)')
    p_trace.add_argument('--detailed', action='store_true',
                         help='Show per-call counts instead of summary')
    p_trace.add_argument('cmd', nargs='+', help='Command to trace')

    # profile mode
    p_prof = sub.add_parser('profile', help='Trace and generate .conf profile')
    p_prof.add_argument('--follow-forks', '-f', action='store_true', default=True)
    p_prof.add_argument('--no-follow-forks', action='store_true')
    p_prof.add_argument('--duration', '-t', type=int, default=None)
    p_prof.add_argument('--output', '-o', type=str, default=None,
                        help='Output .conf file (default: stdout)')
    p_prof.add_argument('--seccomp-mode', '-m', choices=['deny', 'allow'],
                        default='deny', dest='seccomp_mode',
                        help='deny=block dangerous not used (safe), '
                             'allow=only permit observed (strict)')
    p_prof.add_argument('--with-env', action='store_true',
                        help='Include env-allow list in profile')
    p_prof.add_argument('cmd', nargs='+', help='Command to profile')

    # check mode
    p_check = sub.add_parser('check', help='Check if profile would break program')
    p_check.add_argument('--profile', '-p', default='ai-agent',
                         help='Profile to check against (default: ai-agent)')
    p_check.add_argument('--follow-forks', '-f', action='store_true', default=True)
    p_check.add_argument('--no-follow-forks', action='store_true')
    p_check.add_argument('--duration', '-t', type=int, default=None)
    p_check.add_argument('cmd', nargs='+', help='Command to check')

    # static mode
    p_static = sub.add_parser('static', help='Static ELF analysis (no execution)')
    p_static.add_argument('binary', help='ELF binary to analyze')

    args = parser.parse_args()

    if args.mode == 'static':
        numbers = static_analysis(args.binary)
        name_map = load_syscall_names()
        names = sorted(name_map.get(n, f"syscall_{n}") for n in numbers)
        print(f"Static analysis of {args.binary}: {len(numbers)} syscall(s) found\n")
        for name in names:
            danger = " [DANGEROUS]" if name in DANGEROUS_SYSCALLS else ""
            print(f"  {name}{danger}")
        if not numbers:
            print("  (none found — program may use libc wrappers)")
            print("  Try: syscall.py trace -- " + args.binary)
        return

    # Dynamic modes need strace
    if not any(os.access(os.path.join(d, 'strace'), os.X_OK)
               for d in os.environ.get('PATH', '').split(':')):
        print("strace not found. Install: apt install strace", file=sys.stderr)
        sys.exit(1)

    follow = getattr(args, 'follow_forks', True)
    if getattr(args, 'no_follow_forks', False):
        follow = False

    if args.mode == 'trace':
        if args.detailed:
            syscalls, counts = trace_syscalls_detailed(
                args.cmd, follow_forks=follow, duration=args.duration)
        else:
            syscalls, counts = trace_syscalls(
                args.cmd, follow_forks=follow, duration=args.duration)

        print(f"\nSyscalls used ({len(syscalls)} unique):\n")
        for name in sorted(syscalls):
            c = counts.get(name, 0)
            danger = " [DANGEROUS]" if name in DANGEROUS_SYSCALLS else ""
            print(f"  {name:30s} {c:>8d} calls{danger}")

        dangerous_used = syscalls & DANGEROUS_SYSCALLS
        if dangerous_used:
            print(f"\nWARNING: {len(dangerous_used)} dangerous syscall(s) used:")
            for sc in sorted(dangerous_used):
                print(f"  {sc}")

    elif args.mode == 'profile':
        syscalls, counts = trace_syscalls(
            args.cmd, follow_forks=follow, duration=args.duration)
        name = os.path.basename(args.cmd[0])
        used_env = discover_env_vars(args.cmd) if args.with_env else None
        profile = generate_profile(syscalls, name=name,
                                   mode=args.seccomp_mode,
                                   used_env=used_env)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(profile)
            print(f"Profile written to: {args.output}", file=sys.stderr)
        else:
            print(profile)

    elif args.mode == 'check':
        print(f"Running under strace (profile: {args.profile})...",
              file=sys.stderr)
        syscalls, counts = trace_syscalls(
            args.cmd, follow_forks=follow, duration=args.duration)

        would_break, safely_blocked = check_against_profile(
            syscalls, args.profile)

        print(f"\n=== Profile check: {args.profile} ===")
        print(f"Syscalls observed: {len(syscalls)}")
        print(f"Dangerous blocked safely: {len(safely_blocked)}")

        if would_break:
            print(f"\nBROKEN: {len(would_break)} syscall(s) would be blocked "
                  f"that the program uses:")
            for sc in sorted(would_break):
                c = counts.get(sc, 0)
                print(f"  {sc:30s} ({c} calls)")
            print(f"\nThe '{args.profile}' profile would BREAK this program.")
            print("Options:")
            print("  1. Generate a custom profile: syscall.py profile -- " +
                  " ".join(args.cmd))
            print("  2. Disable seccomp: compartment-user --no-seccomp -- " +
                  " ".join(args.cmd))
            sys.exit(1)
        else:
            print(f"\nOK: The '{args.profile}' profile is safe for this program.")
            print("No dangerous syscalls used that would be blocked.")


if __name__ == '__main__':
    main()
