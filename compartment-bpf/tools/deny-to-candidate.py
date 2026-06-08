#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Nenad Mićić
"""
deny-to-candidate — turn compartment-bpf DENY audit events into a candidate profile.

Option A of the deny-debuggability spike (DENY-DEBUGGABILITY-SPIKE.md): userspace-only,
no kernel change. The compartment-bpf daemon already emits a rich record per deny to its
audit stream:

    [audit] DENY_WRITE ts=.. pid=.. ppid=.. uid=.. comm=agent dev=N ino=M \
            caller_dev=C caller_ino=K [actor=name]

This tool consumes that stream (a file or stdin), bounded by --max (the "arm for N events
then stop" capture), deduplicates the distinct denies, resolves dev/ino back to a path via
the active profile, and emits a CANDIDATE profile whose suggested rules are COMMENTED OUT —
because a deny means the policy ALREADY blocked it, so you only un-comment a suggestion if
the caller is legitimate. It is the iptables "DROP LOG -> here's the ACCEPT you'd add"
helper for compartment.

Resolution: dev/ino in the audit stream is the kernel s_dev encoding ((major<<20)|minor);
profile paths are stat()'d and re-encoded the same way to reverse-map (dev,ino) -> path.

Usage:
    deny-to-candidate.py [--profile P] [--max N] [AUDITLOG]      # AUDITLOG default: stdin
    tail -f /var/log/compartment-bpf.audit | deny-to-candidate.py --profile p.conf --max 100
"""
from __future__ import annotations
import argparse
import os
import re
import sys
import time

# DENY_* actions the daemon emits (see action_name() in compartment-bpf.c).
# Map -> the seal flag whose allow-rule we suggest; None = exec-domain / structural
# deny that is usually the protection working (suggest review, not an auto-allow).
ACTION_FLAG = {
    "DENY_WRITE": "no-write",
    "DENY_UNLINK": "no-unlink",
    "DENY_RENAME": "no-rename",
    "DENY_CHMOD": "no-chmod",
    "DENY_CREATE": None,                 # dir create; needs a dir rule, manual
    "DENY_WRITE_PARENT_DIR": None,       # dir-destination seal
    "DENY_CHMOD_PARENT_DIR": None,
    # DENY_ACTOR_MISMATCH: the target is ALREADY actor-sealed (that is why the
    # caller mismatched). Suggesting a fresh `seal <path> no-write actor=<name>`
    # is wrong — it would duplicate/contradict the existing seal. This action is
    # handled as REVIEW-ONLY below (None here): we only point at the existing
    # seal's actor allowlist for the operator to extend, never emit a new rule.
    "DENY_ACTOR_MISMATCH": None,
    "DENY_STRICT_LAUNCH_MISSING": None,  # exec-domain: usually intended
    "DENY_PTRACE_ACCESS": None,
    "DENY_PTRACE_TRACEME": None,
    "DENY_PRCTL_SET_MM": None,
    "DENY_UNPIN_AUTH_FAIL": None,
}

# The daemon emits three deny line shapes: basic (uniform-deny, no caller/actor),
# +caller (actor-mismatch path), and +caller+actor. Caller and actor are OPTIONAL.
# comm is sanitized by the daemon to printable ASCII *including* 0x20 (space), so
# it can contain spaces — it must NOT be matched with \S+ (which would stop at the
# first space and drop the event).
#
# Injection hardening (P2): a process can set its own comm (PR_SET_NAME) to a string
# like `x dev=66 ino=77`, so the audit line becomes
#   [audit] DENY_WRITE ... comm=x dev=66 ino=77 dev=<real> ino=<real>
# A NON-greedy `comm=(?P<comm>.+?)\s+dev=` would bind dev=/ino= to the FIRST
# (attacker-injected) pair. We therefore match comm GREEDILY (.+) so the regex
# backtracks and binds the dev=/ino= groups to the LAST `\s+dev=…\s+ino=…` pair on
# the line — which is the REAL field the daemon appends after the attacker-controlled
# comm. The daemon never emits a bare ` dev=` other than this real field (the caller
# field is spelled `caller_dev=`/`caller_ino=`, which does not match `\s+dev=`).
#
# Hardening (P2-5): the record is ANCHORED at `[audit]` (^… after lstrip below)
# and every field is tightly bounded so a crafted suffix on a hostile line cannot
# smuggle a spurious field into a match:
#   - action is restricted to the DENY_* token alphabet ([A-Z_]+) and \b-bounded,
#     not \S+ (which would swallow arbitrary punctuation/garbage as an "action").
#   - the OPTIONAL caller/actor groups are each terminated by (?=\s|$) so a
#     partial/garbage token after them cannot be absorbed, and the whole record
#     ends with (?=\s|$) so the structure is closed.
#   - actor is bounded to a path/name token alphabet, not \S+.
AUDIT_RE = re.compile(
    r"^\[audit\]\s+(?P<action>DENY_[A-Z_]+)\b\s+ts=\d+\s+pid=(?P<pid>\d+)\s+"
    r"ppid=\d+\s+uid=\d+\s+"
    r"comm=(?P<comm>.+)\s+dev=(?P<dev>\d+)\s+ino=(?P<ino>\d+)"
    r"(?:\s+caller_dev=(?P<cdev>\d+)\s+caller_ino=(?P<cino>\d+)(?=\s|$))?"
    r"(?:\s+actor=(?P<actor>[^\s]+)(?=\s|$))?"
    # Explicitly CONSUME any trailing content to end-of-line (P2-8): a future
    # daemon field appended after the last known token is forward-compat-ignored,
    # not silently absorbed by a dangling lookahead. Nothing past here is captured.
    r"(?:\s.*)?$"
)


def safe(s) -> str:
    """Escape control bytes before emitting a value into the candidate profile.
    Defense-in-depth: a path/comm/actor carrying a newline (or other control
    char) must never break out of a comment line or inject an *active* directive
    into the generated profile. None -> ''."""
    if not s:
        return ""
    return "".join(c if 0x20 <= ord(c) < 0x7f else repr(c).strip("'") for c in str(s))


def kernel_dev(st_dev: int) -> int:
    """glibc st_dev -> kernel s_dev = (major<<20)|minor (matches the BPF hook)."""
    return (os.major(st_dev) << 20) | os.minor(st_dev)


def load_profile_maps(path: str):
    """Return (devino->seal_path, devino->actor_name) from a profile's seal/actor lines."""
    seal_by_devino: dict[tuple[int, int], str] = {}
    actor_by_devino: dict[tuple[int, int], str] = {}
    if not path:
        return seal_by_devino, actor_by_devino
    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"deny-to-candidate: cannot read profile {path}: {e}", file=sys.stderr)
        return seal_by_devino, actor_by_devino
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        try:
            if parts[0] == "seal" and len(parts) >= 2:
                p = parts[1]
                st = os.stat(p)
                seal_by_devino[(kernel_dev(st.st_dev), st.st_ino)] = p
            elif parts[0] == "actor" and "=" in s:
                # actor <name> = <path>
                name = parts[1]
                ap = s.split("=", 1)[1].strip()
                st = os.stat(ap)
                actor_by_devino[(kernel_dev(st.st_dev), st.st_ino)] = name + " (" + ap + ")"
        except (OSError, IndexError):
            continue  # path gone / malformed — skip, we'll fall back to dev/ino
    return seal_by_devino, actor_by_devino


def main() -> int:
    ap = argparse.ArgumentParser(description="DENY audit events -> candidate profile")
    ap.add_argument("auditlog", nargs="?", default="-",
                    help="audit log file (default: stdin)")
    ap.add_argument("--profile", help="active profile, to resolve dev/ino -> path")
    ap.add_argument("--max", type=int, default=0,
                    help="stop after N deny events (bounded capture; 0 = until EOF)")
    args = ap.parse_args()

    seal_map, actor_map = load_profile_maps(args.profile)

    src = sys.stdin if args.auditlog == "-" else open(args.auditlog, "r")
    # distinct deny -> {count, comm, pid, actor}
    denies: dict[tuple, dict] = {}
    seen = 0
    try:
        for ln in src:
            # Accept the raw daemon stream AND a syslog/journald-framed view
            # (e.g. "Jun 8 host compartment-bpf[123]: [audit] DENY_…") by
            # explicitly locating the `[audit]` marker and matching the anchored
            # record from there (P2-4). We strip a *recognized prefix* (everything
            # before the marker) rather than relaxing the `^\[audit\]` anchor with
            # `.*?`, which would re-open the smuggling surface. The per-field
            # bounds in AUDIT_RE still prevent any captured group from over-reading.
            idx = ln.find("[audit]")
            if idx < 0:
                continue
            m = AUDIT_RE.match(ln[idx:])
            if not m:
                continue
            action = m.group("action")
            # action is already constrained to DENY_[A-Z_]+ by the regex; this
            # is belt-and-suspenders for the closed ACTION_FLAG set below.
            if not action.startswith("DENY"):
                continue
            seen += 1
            cdev = int(m.group("cdev")) if m.group("cdev") else 0
            cino = int(m.group("cino")) if m.group("cino") else 0
            key = (action, int(m.group("dev")), int(m.group("ino")), cdev, cino)
            d = denies.setdefault(key, {"count": 0, "comm": m.group("comm"),
                                        "actor": m.group("actor")})
            d["count"] += 1
            if args.max and seen >= args.max:
                break
    finally:
        if src is not sys.stdin:
            src.close()

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = sys.stdout
    out.write("#@compartment-bpf-profile-status: candidate\n")
    out.write("# generated by compartment-bpf deny-to-candidate (deny-first bridge)\n")
    out.write(f"# generated: {ts}\n")
    out.write(f"# source: {seen} deny events, {len(denies)} distinct\n")
    out.write("# validation: candidate only — every rule below is COMMENTED OUT. A deny\n")
    out.write("#   means the policy already blocked it; un-comment a suggestion ONLY if the\n")
    out.write("#   caller is legitimate and should be allowed. exec-domain denies\n")
    out.write("#   (strict-launch / ptrace / prctl) are usually the protection working —\n")
    out.write("#   do NOT blindly allow them. Review + VM-test before --pin --allow-candidate.\n\n")

    if not denies:
        out.write("# (no DENY events found in input)\n")
        return 0

    # stable order: most frequent first. Every value that reaches the output is
    # run through safe() so a control byte (e.g. newline) in a path/comm/actor
    # can never break out of a comment and inject an ACTIVE directive (P2-10).
    for key, d in sorted(denies.items(), key=lambda kv: -kv[1]["count"]):
        action, dev, ino, cdev, cino = key
        path = seal_map.get((dev, ino))
        target = safe(path) if path else f"<dev={dev} ino={ino}>"
        caller = actor_map.get((cdev, cino))
        if caller:
            caller = safe(caller)
        else:
            caller = f"comm={safe(d['comm'])}" \
                     + (f" actor={safe(d['actor'])}" if d["actor"] else "") \
                     + f" (caller dev={cdev} ino={cino})"
        out.write(f"# [{d['count']}x] {safe(action)}  target={target}\n")
        out.write(f"#        caller: {caller}\n")
        known = action in ACTION_FLAG          # CLOSED set of actions this tool knows
        flag = ACTION_FLAG.get(action)
        if action == "DENY_ACTOR_MISMATCH":
            # REVIEW-ONLY: never emit a concrete actor/seal rule. The target is
            # already actor-sealed; the only correct fix is extending THAT seal's
            # actor allowlist — which this tool cannot synthesize safely. Point at
            # the resolved seal if we have it, otherwise just describe the deny.
            if path:
                out.write(f"#   review: caller above was denied to actor-sealed target\n")
                out.write(f"#     {safe(path)}\n")
                out.write(f"#   The target is ALREADY actor-sealed (hence the mismatch). If this\n")
                out.write(f"#   caller is legitimate, add it to the EXISTING actor allowlist for\n")
                out.write(f"#   that seal in your profile — do NOT add a new seal line.\n")
            else:
                out.write(f"#   review: caller above denied to an actor-sealed target\n")
                out.write(f"#   (dev={dev} ino={ino}; pass --profile to resolve the path). If the\n")
                out.write(f"#   caller is legitimate, extend the EXISTING actor allowlist for that\n")
                out.write(f"#   seal — no auto-rule suggested.\n")
        elif flag and path:
            out.write(f"#   to allow this caller (review!):\n")
            out.write(f"#     actor <name> = <caller-binary-path>\n")
            out.write(f"#     seal {safe(path)} {flag} actor=<name>\n")
        elif flag and not path:
            out.write(f"#   target path unresolved (pass --profile to resolve dev/ino)\n")
        elif known:
            out.write(f"#   exec-domain / structural deny — likely intended; allow only\n")
            out.write(f"#   if you understand the implication (no auto-rule suggested).\n")
        else:
            out.write(f"#   UNKNOWN deny action '{safe(action)}' — this tool may be out of\n")
            out.write(f"#   date for the running daemon; review manually, do NOT auto-allow.\n")
        out.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
