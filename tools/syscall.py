#!/usr/bin/env python3
"""
syscall.py — Discover syscalls used by a program and generate compartment profiles.

Two modes:
  1. Static:  Disassemble ELF binary, find syscall instructions (fast, incomplete)
  2. Dynamic: Run program under strace, collect actual syscalls (complete, slower)

Output: list of syscalls, or a compartment-user profile (.conf).  Generated
profiles are self-contained: they carry their own Landlock path rules (derived
from the paths the program actually opened) and their own syscall rules, so they
load with `compartment-user --profile <file>` without any other file present.

Usage:
  # Static analysis (needs: pip install pyelftools capstone)
  ./syscall.py static /usr/bin/ls

  # Dynamic profiling (needs: strace)
  ./syscall.py trace -- ls -la /tmp
  ./syscall.py trace --follow-forks -- my-agent --flag

  # Generate compartment-user profile (deny-list — safe default)
  ./syscall.py profile -- ls -la /tmp

  # Generate strict allow-list profile (only observed syscalls permitted)
  ./syscall.py profile --seccomp-mode allow -- ls -la /tmp

  # Include env allow-list in profile
  ./syscall.py profile --seccomp-mode allow --with-env -- my-agent

  # Compare: what would compartment-user block that the program needs?
  ./syscall.py check --profile ai-agent -- ls -la /tmp

Always review a generated profile before using it.  Profiling only sees the
code paths that ran; rare paths (error handling, signal handlers, TLS
renegotiation, ...) may need syscalls or files that no trace captured.
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

# ── compartment.h introspection ─────────────────────────────────────
#
# A generated profile has to fit the limits the C parser enforces, and
# block/allow entries are easier to read — and portable across
# architectures — when written as names.  compartment-user only knows the
# names in its own syscall_table[]; anything else has to be emitted as a raw
# number.  Both facts are read out of compartment.h so this tool tracks the
# parser instead of hard-coding a snapshot of it.

DEFAULT_LIMITS = {
    "MAX_PATHS": 64,
    "MAX_BLOCKED_SC": 64,
    "MAX_ALLOWED_SC": 512,
    "MAX_ENV_VARS": 64,
}

_HEADER_CACHE = {}


def find_compartment_header():
    """Locate compartment.h (repo checkout first, then installed copies)."""
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent / "compartment.h",
        here / "compartment.h",
        Path("/usr/local/include/compartment.h"),
        Path("/usr/include/compartment.h"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def read_compartment_header():
    if "text" not in _HEADER_CACHE:
        path = find_compartment_header()
        try:
            _HEADER_CACHE["text"] = path.read_text() if path else ""
        except OSError:
            _HEADER_CACHE["text"] = ""
        _HEADER_CACHE["path"] = path
    return _HEADER_CACHE["text"]


def compartment_limits():
    """Read MAX_* limits from compartment.h, falling back to known defaults."""
    text = read_compartment_header()
    limits = dict(DEFAULT_LIMITS)
    for key in limits:
        m = re.search(r'^#define\s+%s\s+(\d+)' % key, text, re.M)
        if m:
            limits[key] = int(m.group(1))
    return limits


def known_syscall_names():
    """Names compartment-user's syscall_table[] can resolve.

    An empty set means compartment.h could not be read; callers then fall
    back to numeric syscall IDs, which resolve_syscall() also accepts."""
    text = read_compartment_header()
    m = re.search(r'syscall_table\[\]\s*=\s*\{(.*?)\n\};', text, re.S)
    if not m:
        return set()
    return set(re.findall(r'\{\s*"([a-z0-9_]+)"\s*,', m.group(1)))


# ── strace-based dynamic profiling ──────────────────────────────────

class TraceResult:
    """Outcome of one strace run.

    attempted   — every syscall name seen, regardless of result
    counts      — attempts per syscall
    succeeded   — successful calls per syscall (attempted-but-failed == 0)
    opened      — {absolute path: was it written?} for calls that succeeded
    executed    — absolute paths passed to a successful execve/execveat
    rc          — exit status of strace (i.e. of the traced program)
    timed_out   — True when --duration cut the run short
    """

    def __init__(self):
        self.attempted = set()
        self.counts = Counter()
        self.succeeded = Counter()
        self.opened = {}
        self.executed = set()
        self.rc = 0
        self.timed_out = False


def _run_strace(strace_cmd, duration):
    """Run strace, return (returncode, stderr_text, timed_out)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.strace-err',
                                     delete=False) as ef:
        err_file = ef.name
    timed_out = False
    try:
        with open(err_file, 'w') as errf:
            proc = subprocess.Popen(
                strace_cmd,
                stdout=subprocess.DEVNULL,
                stderr=errf,
            )
            try:
                proc.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                timed_out = True
                # SIGINT lets strace finalize the trace file.
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        try:
            with open(err_file) as f:
                stderr_text = f.read()
        except OSError:
            stderr_text = ""
        return proc.returncode, stderr_text, timed_out
    finally:
        try:
            os.unlink(err_file)
        except OSError:
            pass


def _abort_if_trace_failed(result, rc, stderr_text, cmd, timed_out):
    """Abort when strace never got the program running.

    Without this check a failed trace is indistinguishable from a program
    that uses no syscalls, and every caller then reports success on an empty
    syscall set."""
    if result.attempted:
        return
    msg = stderr_text.strip().splitlines()
    detail = msg[0] if msg else "no syscalls were recorded"
    print("syscall.py: trace failed for %s (strace rc=%d): %s"
          % (" ".join(cmd), rc, detail), file=sys.stderr)
    if timed_out:
        print("syscall.py: the run was cut short by --duration; "
              "increase it or drop it.", file=sys.stderr)
    sys.exit(1)


def trace_syscalls(cmd, follow_forks=True, duration=None):
    """Run command under strace -c, return a TraceResult.

    Summary mode is cheap but reports only attempts and error counts, so
    `succeeded` is derived as calls-minus-errors and no paths are collected.
    Use trace_detailed() when the caller needs paths or per-call results."""
    result = TraceResult()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.strace',
                                     delete=False) as tf:
        trace_file = tf.name

    try:
        strace_cmd = ["strace", "-o", trace_file, "-c", "-S", "calls"]
        if follow_forks:
            strace_cmd.append("-f")
        strace_cmd.extend(["--"] + cmd)

        rc, stderr_text, timed_out = _run_strace(strace_cmd, duration)
        result.rc = rc
        result.timed_out = timed_out

        # strace -c layout:
        #   % time     seconds  usecs/call     calls    errors syscall
        #     0.00    0.000000           0         1         1 access
        # The errors column is omitted entirely when a syscall never failed.
        with open(trace_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('%') or line.startswith('-'):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                name = parts[-1]
                if name == 'total' or name.startswith('-'):
                    continue
                result.attempted.add(name)
                try:
                    if len(parts) >= 6:
                        calls, errors = int(parts[-3]), int(parts[-2])
                    else:
                        calls, errors = int(parts[-2]), 0
                except (ValueError, IndexError):
                    calls, errors = 0, 0
                result.counts[name] = calls
                result.succeeded[name] = max(calls - errors, 0)

        _abort_if_trace_failed(result, rc, stderr_text, cmd, timed_out)
        return result

    finally:
        try:
            os.unlink(trace_file)
        except OSError:
            pass


# strace line: optional "<pid> " or "[pid  <n>] " prefix, then name(args) = ret
_CALL_RE = re.compile(
    r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?'
    r'(?P<name>[a-zA-Z_][A-Za-z0-9_]*)\('
    r'(?P<args>.*)\)\s+=\s+(?P<ret>.+)$'
)
_UNFINISHED_RE = re.compile(
    r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?'
    r'(?P<name>[a-zA-Z_][A-Za-z0-9_]*)\(.*<unfinished \.\.\.>\s*$'
)
_RESUMED_RE = re.compile(
    r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?'
    r'<\.\.\.\s+(?P<name>[a-zA-Z_][A-Za-z0-9_]*)\s+resumed>'
    r'(?P<args>.*)\)\s+=\s+(?P<ret>.+)$'
)
_FIRST_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

# Syscalls whose first quoted argument is a filesystem path.
_PATH_SYSCALLS = {
    "open", "openat", "openat2", "creat", "execve", "execveat",
    "stat", "lstat", "newfstatat", "statx", "access", "faccessat",
    "faccessat2", "readlink", "readlinkat", "truncate", "chdir",
    "chmod", "chown", "unlink", "unlinkat", "mkdir", "mkdirat",
    "rmdir", "rename", "renameat", "renameat2", "statfs", "utimensat",
}
_EXEC_SYSCALLS = {"execve", "execveat"}
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")
# Syscalls that only ever write: seeing one means the path is written to.
_WRITE_SYSCALLS = {
    "creat", "truncate", "chmod", "chown", "unlink", "unlinkat", "mkdir",
    "mkdirat", "rmdir", "rename", "renameat", "renameat2", "utimensat",
}


def _record_call(result, name, args, ret):
    result.attempted.add(name)
    result.counts[name] += 1
    ok = not ret.startswith('-1') and not ret.startswith('?')
    if not ok:
        return
    result.succeeded[name] += 1
    if name not in _PATH_SYSCALLS:
        return
    m = _FIRST_STR_RE.search(args)
    if not m:
        return
    path = m.group(1)
    if not path.startswith('/'):
        return
    wrote = name in _WRITE_SYSCALLS or any(f in args for f in _WRITE_FLAGS)
    result.opened[path] = result.opened.get(path, False) or wrote
    if name in _EXEC_SYSCALLS:
        result.executed.add(path)


def trace_detailed(cmd, follow_forks=True, duration=None):
    """Run under strace with full output; collect results and paths."""
    result = TraceResult()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.strace',
                                     delete=False) as tf:
        trace_file = tf.name

    try:
        strace_cmd = ["strace", "-o", trace_file]
        if follow_forks:
            strace_cmd.append("-f")
        strace_cmd.extend(["--"] + cmd)

        rc, stderr_text, timed_out = _run_strace(strace_cmd, duration)
        result.rc = rc
        result.timed_out = timed_out

        with open(trace_file, 'r') as f:
            for line in f:
                line = line.rstrip('\n')
                m = _RESUMED_RE.match(line)
                if m:
                    _record_call(result, m.group('name'), m.group('args'),
                                 m.group('ret').strip())
                    continue
                m = _UNFINISHED_RE.match(line)
                if m:
                    # Attempted; the matching "resumed" line carries the result.
                    result.attempted.add(m.group('name'))
                    continue
                m = _CALL_RE.match(line)
                if m:
                    _record_call(result, m.group('name'), m.group('args'),
                                 m.group('ret').strip())

        _abort_if_trace_failed(result, rc, stderr_text, cmd, timed_out)
        return result

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

    return syscall_map


# ── Profile generation ──────────────────────────────────────────────

# Prefixes that get one Landlock rule each instead of one per subdirectory.
# Longest match wins, so /var/lib beats /var.
_SYSTEM_PREFIXES = (
    "/usr", "/lib64", "/lib32", "/libx32", "/lib", "/bin", "/sbin",
    "/etc", "/proc", "/sys", "/dev", "/run", "/var/lib", "/opt",
)

# Characters that survive a round trip through compartment.h's line parser.
_SAFE_CONF_VALUE = re.compile(r'^[A-Za-z0-9_./$@:,+=-]+$')


def sanitize_conf_text(text):
    """Make a string safe to interpolate into a .conf comment.

    Everything after a directive is taken verbatim by the C parser, so a
    newline inside an untrusted string (a program name, say) would start a
    new directive line — `x\\nallow 101` would inject `allow ptrace` and flip
    the whole profile into allow-list mode."""
    return re.sub(r'[^\w .@%+=:,/-]', '_', text)


def _bucket_for(path, home):
    """Map an observed path to the Landlock rule that should cover it."""
    for prefix in sorted(_SYSTEM_PREFIXES, key=len, reverse=True):
        if path == prefix or path.startswith(prefix + "/"):
            return prefix
    if home and (path == home or path.startswith(home.rstrip("/") + "/")):
        return "$HOME"
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "/"
    # /home/<user>/... would otherwise hand out every user's home directory.
    depth = 2 if parts[0] in ("home", "media", "mnt") else 1
    return "/" + "/".join(parts[:depth])


def derive_path_rules(result, limits):
    """Turn observed paths into compartment-user ro/rw/rwx rules.

    Returns (rules, notes): rules is a list of (mode, path); notes is a list
    of comment lines explaining anything non-obvious."""
    home = os.environ.get("HOME") or None
    buckets = {}       # bucket -> {"write": bool, "exec": bool}
    for path, wrote in sorted(result.opened.items()):
        info = buckets.setdefault(_bucket_for(path, home),
                                  {"write": False, "exec": False})
        info["write"] = info["write"] or wrote
    for path in sorted(result.executed):
        info = buckets.setdefault(_bucket_for(path, home),
                                  {"write": False, "exec": False})
        info["exec"] = True

    notes = []
    rules = {}
    rank = {"ro": 0, "rw": 1, "rwx": 2}
    for bucket, info in sorted(buckets.items()):
        target = bucket
        if bucket != "$HOME":
            # A Landlock rule on a symlink installs nothing at all: the rule
            # is accepted and then silently matches no path.  On a merged-/usr
            # system /bin and /lib are symlinks, so use their real paths.
            real = os.path.realpath(bucket)
            if real != bucket and os.path.isdir(real):
                notes.append("# %s is a symlink to %s — a Landlock rule on a "
                             "symlink matches nothing, so the real path is used"
                             % (bucket, real))
                target = real
        if not _SAFE_CONF_VALUE.match(target):
            notes.append("# skipped unrepresentable path: %s"
                         % sanitize_conf_text(target))
            continue
        mode = "ro"
        if info["write"]:
            mode = "rwx" if info["exec"] else "rw"
        prev = rules.get(target)
        if prev is None or rank[mode] > rank[prev]:
            rules[target] = mode

    ordered = [(mode, path) for path, mode in sorted(rules.items())]
    max_paths = limits["MAX_PATHS"]
    if len(ordered) > max_paths:
        notes.append("# WARNING: %d path rules observed but compartment.h "
                     "allows %d — the rest were dropped, review this profile"
                     % (len(ordered), max_paths))
        ordered = ordered[:max_paths]
    return ordered, notes


def generate_profile(result, name="traced-program", mode="deny",
                     used_env=None, limits=None):
    """Generate a self-contained compartment-user .conf profile.

    mode="deny":  block dangerous syscalls the program never used successfully
    mode="allow": only permit observed syscalls (stricter, may miss rare paths)

    No inline comments are emitted after a directive: the C parser takes the
    whole rest of the line as the value, so "ro /usr  # libs" would look for a
    directory literally named "/usr  # libs".
    """
    limits = limits or compartment_limits()
    known = known_syscall_names()
    used_syscalls = result.attempted
    succeeded = {s for s in used_syscalls if result.succeeded.get(s, 0) > 0}
    attempted_only = used_syscalls - succeeded

    lines = [
        "# Auto-generated compartment-user profile for: %s"
        % sanitize_conf_text(name),
        "# Generated by: syscall.py profile --seccomp-mode %s" % mode,
        "# Syscalls attempted: %d (of which %d succeeded)"
        % (len(used_syscalls), len(succeeded)),
        "#",
        "# REVIEW BEFORE USE. Profiling only observes the code paths that ran.",
        "",
    ]

    path_rules, path_notes = derive_path_rules(result, limits)
    lines.append("# ── Filesystem (Landlock), derived from observed paths ──")
    lines += path_notes
    if path_rules:
        for rule_mode, path in path_rules:
            lines.append("%s %s" % (rule_mode, path))
    else:
        lines += [
            "# WARNING: the trace observed no filesystem paths. compartment-user",
            "# refuses to run with Landlock on and zero path rules, so a minimal",
            "# read-only system set is used — widen it as needed.",
            "ro /usr",
            "ro /etc",
        ]
    lines.append("")

    if mode == "allow":
        max_allowed = limits["MAX_ALLOWED_SC"]
        lines += [
            "# ── Syscalls: ALLOW-LIST (%d observed, everything else denied) ──"
            % len(used_syscalls),
            "# If the program has rare code paths that profiling did not",
            "# exercise, those paths fail with EPERM. Profile for long enough to",
            "# cover them, or add the missing syscalls by hand.",
            "",
            "seccomp-mode allowlist",
            "",
        ]
        if len(used_syscalls) > max_allowed:
            lines.append("# WARNING: %d syscalls observed but compartment.h "
                         "allows %d — list truncated"
                         % (len(used_syscalls), max_allowed))
        name_map = load_syscall_names()
        reverse_map = {v: k for k, v in name_map.items()}
        unnamed = []
        for sc in sorted(used_syscalls)[:max_allowed]:
            if sc in known:
                # Names are portable; numbers are architecture specific.
                lines.append("allow %s" % sc)
                continue
            nr = reverse_map.get(sc)
            if nr is not None:
                # resolve_syscall() accepts "<nr>  # comment" for numbers.
                lines.append("allow %d  # %s" % (nr, sc))
                unnamed.append(sc)
            else:
                lines.append("# unresolved syscall: %s" % sanitize_conf_text(sc))
        if unnamed:
            lines += [
                "",
                "# NOTE: compartment.h's syscall_table[] has no name for %d of"
                % len(unnamed),
                "# these, so they are written as raw numbers that are only valid",
                "# on this architecture (%s):" % os.uname().machine,
                "#   %s" % ", ".join(sorted(unnamed)),
            ]
    else:
        can_block = sorted(DANGEROUS_SYSCALLS - succeeded)
        needed = sorted(DANGEROUS_SYSCALLS & succeeded)
        tried_and_failed = sorted(DANGEROUS_SYSCALLS & attempted_only)
        max_blocked = limits["MAX_BLOCKED_SC"]
        lines += [
            "# ── Syscalls: DENY-LIST ──",
            "# %d dangerous syscalls blocked; %d left open because the program"
            % (min(len(can_block), max_blocked), len(needed)),
            "# used them successfully.",
        ]
        if needed:
            lines.append("#")
            lines.append("# NEEDED (not blocked — the program really uses these):")
            for sc in needed:
                lines.append("#   %s (%d successful calls)"
                             % (sc, result.succeeded.get(sc, 0)))
        if tried_and_failed:
            lines.append("#")
            lines.append("# Attempted but never succeeded — blocked anyway, since")
            lines.append("# a call that already fails loses nothing by being denied:")
            for sc in tried_and_failed:
                lines.append("#   %s (%d attempts, 0 succeeded)"
                             % (sc, result.counts.get(sc, 0)))
        lines.append("")
        if len(can_block) > max_blocked:
            lines += [
                "# WARNING: %d syscalls should be blocked but compartment.h's"
                % len(can_block),
                "# MAX_BLOCKED_SC is %d, so the list below is truncated and the"
                % max_blocked,
                "# remainder is NOT blocked. Raise MAX_BLOCKED_SC or trim by hand.",
            ]
        for sc in can_block[:max_blocked]:
            if not known or sc in known:
                lines.append("block %s" % sc)
            else:
                lines.append("# not in compartment.h syscall_table[]: %s" % sc)

    lines.append("")
    lines.append("# ── Environment ──")
    if used_env is not None:
        lines.append("# Only these %d variables survive into the program."
                     % len(used_env))
        lines.append("env-mode allowlist")
        for var in sorted(used_env):
            lines.append("env-allow %s" % var)
    else:
        lines.append("# Loader-injection vectors. compartment-user's built-in")
        lines.append("# ai-agent profile strips a longer list — see")
        lines.append("# examples/ai-agent.conf if you want all of it.")
        for var in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
                    "GLIBC_TUNABLES", "PYTHONPATH", "PYTHONHOME",
                    "PERL5LIB", "NODE_OPTIONS", "BASH_ENV", "ENV"):
            lines.append("env-deny %s" % var)

    lines += [
        "",
        "# ── Features ──",
        "landlock on",
        "seccomp on",
        "no-new-privs on",
        "env-sanitize on",
        "",
    ]
    return "\n".join(lines)


# Anything that looks like a credential never becomes an env-allow line.
SECRET_ENV_RE = re.compile(
    r'(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|CREDS|AUTH|COOKIE|'
    r'SESSION|PRIVATE|SIGNATURE|LICENSE)', re.I)

# Variables a typical program needs.  Deliberately generic: this list must
# never be widened with anything that carries a credential, because an
# env-allow line re-admits it into a sandbox whose job is to strip it.
BASE_ENV_VARS = {
    "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL",
    "LOGNAME", "HOSTNAME", "PWD", "OLDPWD", "TMPDIR", "TMP",
    "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
}
PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                  "http_proxy", "https_proxy", "no_proxy")


def discover_env_vars(cmd=None, environ=None):
    """Suggest an env allow-list.

    This is a heuristic, not a discovery: a variable read through getenv(3)
    leaves no syscall behind, so there is nothing to trace.  It returns the
    generic set above plus any proxy variables that are set, and reports
    separately the names it refused to emit because they look like secrets.

    Returns (allow, skipped)."""
    environ = os.environ if environ is None else environ
    allow = set(BASE_ENV_VARS)
    for var in PROXY_ENV_VARS:
        if environ.get(var):
            allow.add(var)
    skipped = sorted({v for v in allow if SECRET_ENV_RE.search(v)})
    allow -= set(skipped)
    return allow, skipped


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
        print("Unknown profile: %s (known: ai-agent, strict)" % profile_name,
              file=sys.stderr)
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
               "  syscall.py profile --follow-forks -- ./my-agent\n"
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
                        help='Include an env allow-list (heuristic; never '
                             'emits anything that looks like a credential)')
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
        names = sorted(name_map.get(n, "syscall_%d" % n) for n in numbers)
        print("Static analysis of %s: %d syscall(s) found\n"
              % (args.binary, len(numbers)))
        for name in names:
            danger = " [DANGEROUS]" if name in DANGEROUS_SYSCALLS else ""
            print("  %s%s" % (name, danger))
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
            result = trace_detailed(args.cmd, follow_forks=follow,
                                    duration=args.duration)
        else:
            result = trace_syscalls(args.cmd, follow_forks=follow,
                                    duration=args.duration)

        print("\nSyscalls used (%d unique):\n" % len(result.attempted))
        for name in sorted(result.attempted):
            c = result.counts.get(name, 0)
            ok = result.succeeded.get(name, 0)
            danger = " [DANGEROUS]" if name in DANGEROUS_SYSCALLS else ""
            print("  %-30s %8d calls (%d ok)%s" % (name, c, ok, danger))

        dangerous_used = result.attempted & DANGEROUS_SYSCALLS
        if dangerous_used:
            print("\nWARNING: %d dangerous syscall(s) used:" % len(dangerous_used))
            for sc in sorted(dangerous_used):
                print("  %s (%d ok of %d attempts)"
                      % (sc, result.succeeded.get(sc, 0),
                         result.counts.get(sc, 0)))
        if result.rc != 0 and not result.timed_out:
            print("\nNOTE: the traced program exited with status %d — the trace"
                  % result.rc, file=sys.stderr)
            print("      may not cover its normal code paths.", file=sys.stderr)

    elif args.mode == 'profile':
        result = trace_detailed(args.cmd, follow_forks=follow,
                                duration=args.duration)
        if result.rc != 0 and not result.timed_out:
            print("syscall.py: WARNING: the traced program exited with status "
                  "%d;" % result.rc, file=sys.stderr)
            print("            the generated profile may be incomplete.",
                  file=sys.stderr)
        name = os.path.basename(args.cmd[0])
        used_env = None
        if args.with_env:
            used_env, skipped = discover_env_vars(args.cmd)
            if skipped:
                print("syscall.py: not adding env-allow for credential-looking "
                      "variables: %s" % ", ".join(skipped), file=sys.stderr)
        profile = generate_profile(result, name=name, mode=args.seccomp_mode,
                                   used_env=used_env)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(profile)
            print("Profile written to: %s" % args.output, file=sys.stderr)
        else:
            print(profile)

    elif args.mode == 'check':
        print("Running under strace (profile: %s)..." % args.profile,
              file=sys.stderr)
        result = trace_syscalls(args.cmd, follow_forks=follow,
                                duration=args.duration)

        would_break, safely_blocked = check_against_profile(
            result.attempted, args.profile)

        print("\n=== Profile check: %s ===" % args.profile)
        print("Syscalls observed: %d" % len(result.attempted))
        print("Dangerous blocked safely: %d" % len(safely_blocked))
        if result.rc != 0 and not result.timed_out:
            print("NOTE: the traced program exited with status %d." % result.rc)

        if would_break:
            print("\nBROKEN: %d syscall(s) would be blocked that the program "
                  "uses:" % len(would_break))
            for sc in sorted(would_break):
                print("  %-30s (%d calls, %d ok)"
                      % (sc, result.counts.get(sc, 0),
                         result.succeeded.get(sc, 0)))
            print("\nThe '%s' profile would BREAK this program." % args.profile)
            print("Options:")
            print("  1. Generate a custom profile: syscall.py profile -- " +
                  " ".join(args.cmd))
            print("  2. Disable seccomp: compartment-user --no-seccomp -- " +
                  " ".join(args.cmd))
            sys.exit(1)
        else:
            print("\nOK: The '%s' profile is safe for this program."
                  % args.profile)
            print("No dangerous syscalls used that would be blocked.")


if __name__ == '__main__':
    main()
