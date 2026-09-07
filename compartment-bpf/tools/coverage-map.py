#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# tools/coverage-map.py — static code-surface vs. test-witness coverage gate.
#
# Motivation (2026-06-08 coverage audit + Codex testing-coverage review, both
# independent): the test suite is broad but was not "coverage-accountable" —
# a new BPF hook, ACTION_DENY_* action, or *_total counter could land with NO
# test referencing it and CI stayed green (this is exactly how OPEN-1 and the
# recursive dir-seal doc drift slipped through). This tool makes that class of
# regression impossible by enforcing one rule:
#
#   Every enforcement/observe code surface must be referenced by at least one
#   test under tests/, OR be listed as an explicit exemption (with a reason)
#   in tests/coverage/coverage-manifest.tsv.
#
# Surfaces extracted from source (the authoritative list — no hand-maintained
# duplicate to drift):
#   - enforce LSM hooks      SEC("lsm/<hook>")           in compartment.bpf.c
#   - observe LSM hooks      SEC("lsm/<hook>")           in compartment-observe.bpf.c
#   - deny actions           ACTION_DENY_<X>             in compartment-abi.h
#   - enforce counters       } <name>_total SEC(".maps") in compartment.bpf.c
#   - observe counters       #define C_<X> <n>           in compartment-observe.bpf.c
#
# This is a STATIC, necessary-not-sufficient check (it proves a witness
# *references* the surface, not that it drives it nonzero at runtime — that is
# the live counter-longevity / counter-smoke job). Its value is preventing
# silent un-witnessed surfaces from ever landing. Pure source scan: NO root,
# NO kernel, NO build — runs on any host, wired into the default `make check`.
#
# Exit 0 = every surface covered or explicitly exempted, no stale exemptions.
# Exit 1 = an uncovered surface with no exemption, a stale exemption (surface
#          now covered or no longer exists), or a malformed manifest.

import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BPF = os.path.join(REPO, "compartment.bpf.c")
OBSERVE_BPF = os.path.join(REPO, "compartment-observe.bpf.c")
ABI = os.path.join(REPO, "compartment-abi.h")
TESTS_DIR = os.path.join(REPO, "tests")
MANIFEST = os.path.join(REPO, "tests", "coverage", "coverage-manifest.tsv")


def read(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


# ---------------------------------------------------------------------------
# What counts as a witness
# ---------------------------------------------------------------------------
#
# Until 2026-09 a hook was credited if its *bare op suffix* appeared anywhere
# in the concatenated tests/ corpus, comments included. `file_open` was
# therefore "witnessed" by the word `open` — which occurs in 52 test files —
# and `create`, `link`, `unlink`, `truncate`, `permission`, `setxattr` and
# friends behaved the same way. A hook could be deleted from the enforcement
# path entirely and this gate would stay green. The rule now is:
#
#   A hook is witnessed by a test file F when
#     (a) F names the hook EXACTLY (comments count — that is F's claim about
#         what it exercises) AND F contains, OUTSIDE COMMENTS, a token for
#         the operation that hook guards; or
#     (b) F contains, outside comments, the hook's BPF program name
#         (comp_<x> / ao_<x>), which is unique to the hook and needs no
#         separate claim.
#
#   An action or counter is witnessed when its exact name appears OUTSIDE
#   COMMENTS in some test file.
#
# So a comment that merely mentions a hook no longer witnesses it, and a bare
# op token in an unrelated file no longer witnesses it either. Both halves
# are asserted by `--selftest`.
#
# Op tokens that are not simply the hook name minus an inode_/file_ prefix.
# Deliberately tiny and explicit — each row is a reviewable claim that a test
# performing X exercises hook Y, and the co-occurrence rule still requires the
# test file to name the hook.
HOOK_OP_ALIASES = {
    "mmap_file":           [r'\bmmap\b'],
    "bprm_check_security": [r'\bexec\b', r'\bexecve\b'],
    "task_prctl":          [r'\bprctl\b'],
    "ptrace_access_check": [r'\bptrace\b'],
    "ptrace_traceme":      [r'\bptrace\b', r'\btraceme\b'],
}


def strip_c_comments(text):
    """Remove /* */ and // comments, respecting string/char literals."""
    out = []
    i, n, state = 0, len(text), None
    while i < n:
        c = text[i]
        if state is None:
            if c == '/' and i + 1 < n and text[i + 1] == '*':
                j = text.find('*/', i + 2)
                i = n if j < 0 else j + 2
                out.append(' ')
                continue
            if c == '/' and i + 1 < n and text[i + 1] == '/':
                j = text.find('\n', i)
                i = n if j < 0 else j
                continue
            if c in ('"', "'"):
                state = c
            out.append(c)
            i += 1
            continue
        if c == '\\' and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        if c == state:
            state = None
        out.append(c)
        i += 1
    return ''.join(out)


def strip_sh_comments(text):
    """Remove `#`-to-end-of-line comments from shell/conf/python-ish text.
    Quote-aware per line, and only treats `#` as a comment when it starts a
    word (so $#, ${#x} and colour codes survive)."""
    res = []
    for line in text.split('\n'):
        out = []
        sq = dq = False
        i, n = 0, len(line)
        while i < n:
            c = line[i]
            if c == '\\' and not sq and i + 1 < n:
                out.append(line[i:i + 2])
                i += 2
                continue
            if c == "'" and not dq:
                sq = not sq
            elif c == '"' and not sq:
                dq = not dq
            elif c == '#' and not sq and not dq:
                if i == 0 or line[i - 1] in ' \t;&|(':
                    break
            out.append(c)
            i += 1
        res.append(''.join(out))
    return '\n'.join(res)


def code_of(text, filename):
    if filename.endswith(('.c', '.h')):
        return strip_c_comments(text)
    return strip_sh_comments(text)


def bpf_prog_names(source):
    """hook -> [BPF program name, ...] parsed from SEC("lsm/<hook>") followed
    by int BPF_PROG(<name>, ...). Authoritative, so no hand-kept table."""
    names = {}
    for m in re.finditer(
            r'SEC\("lsm(?:\.s)?/([a-z_]+)"\)\s*\nint\s+BPF_PROG\(\s*([A-Za-z_][A-Za-z0-9_]*)',
            source):
        names.setdefault(m.group(1), []).append(m.group(2))
    return names


def hook_tokens(name, observe, prog_names=()):
    """(name_regex, [op-token regexes], [program-name regexes]).

    name_regex is matched against the RAW file (the claim); op tokens and
    program names are matched against the comment-stripped file (the code)."""
    name_re = r'\b' + re.escape(name) + r'\b'
    progs = [r'\b' + re.escape(pn) + r'\b' for pn in prog_names]
    if observe:
        # Observe hooks are witnessed ONLY by their BPF program name
        # (ao_*). Every one of them shares a kernel hook name with an
        # enforce hook, so accepting the shared op token would credit the
        # observe surface to a test that never starts `compartment-bpf
        # observe` — which is what used to happen. tests/observe/run.sh T0
        # greps `bpftool prog show` for exactly these program names, so the
        # honest witness is available and the weak one is not needed.
        # Keep the historical ao_<hook> spelling too, in case the source
        # spells a program differently from its hook.
        progs.append(r'\bao_' + re.escape(name) + r'\b')
        return name_re, [], progs
    ops = [name_re]
    # op suffix for fs hooks (inode_setxattr -> setxattr, file_truncate ->
    # truncate). Only for fs-ish prefixes; task_/mmap_ suffixes are too
    # generic ("alloc"/"free"/"file") to be a reliable proxy on their own.
    for pfx in ("inode_", "file_"):
        if name.startswith(pfx):
            ops.append(r'\b' + re.escape(name[len(pfx):]) + r'\b')
    ops += HOOK_OP_ALIASES.get(name, [])
    return name_re, ops, progs


def extract_surfaces():
    """Return ordered list of (kind, name, matcher) tuples.

    matcher is ("hook", name_re, op_res, prog_res) for LSM hooks and
    ("token", [regex, ...]) for actions and counters."""
    surfaces = []

    bpf = read(BPF)
    bpf_progs = bpf_prog_names(bpf)
    # Enforce LSM hooks. SEC("lsm/foo") and SEC("lsm.s/foo"). Dedupe (the
    # dual inode_setattr wrapper emits the same hook name twice).
    hooks = []
    for m in re.finditer(r'SEC\("lsm(?:\.s)?/([a-z_]+)"\)', bpf):
        if m.group(1) not in hooks:
            hooks.append(m.group(1))
    for h in hooks:
        name_re, ops, progs = hook_tokens(h, False, bpf_progs.get(h, []))
        surfaces.append(("enforce-hook", h, ("hook", name_re, ops, progs)))

    obs = read(OBSERVE_BPF)
    obs_progs = bpf_prog_names(obs)
    ohooks = []
    for m in re.finditer(r'SEC\("lsm(?:\.s)?/([a-z_]+)"\)', obs):
        if m.group(1) not in ohooks:
            ohooks.append(m.group(1))
    for h in ohooks:
        name_re, ops, progs = hook_tokens(h, True, obs_progs.get(h, []))
        surfaces.append(("observe-hook", h, ("hook", name_re, ops, progs)))

    abi = read(ABI)
    # Deny actions. ACTION_DENY_X enum constants. The audit stream emits the
    # bare DENY_X token, so a witness may reference either spelling.
    actions = []
    for m in re.finditer(r'\bACTION_(DENY_[A-Z_]+)\b', abi):
        if m.group(1) not in actions:
            actions.append(m.group(1))
    for a in actions:
        # token matches "ACTION_DENY_X" or audit-line "DENY_X"
        surfaces.append(("action", a, ("token", [r'\b' + re.escape(a) + r'\b'])))

    # Enforce counters: the map *definitions* only ( "} name_total SEC" ),
    # which excludes comment-only mentions of hypothetical counters.
    counters = []
    for m in re.finditer(r'^\}\s*([a-z_]+_total)\s+SEC\("\.maps"\)', bpf, re.M):
        if m.group(1) not in counters:
            counters.append(m.group(1))
    for c in counters:
        surfaces.append(("counter", c, ("token", [r'\b' + re.escape(c) + r'\b'])))

    # Observe counters: #define C_X <n>, excluding the C_MAX sentinel.
    ocounters = []
    for m in re.finditer(r'^#define\s+(C_[A-Z_]+)\s+\d+', obs, re.M):
        if m.group(1) != "C_MAX" and m.group(1) not in ocounters:
            ocounters.append(m.group(1))
    for c in ocounters:
        surfaces.append(("observe-counter", c, ("token", [r'\b' + re.escape(c) + r'\b'])))

    return surfaces


# Directories under tests/ that hold per-run artefacts rather than tests.
# tests/results/ is written by run-mesh.sh, pin-regression.sh,
# observe/run.sh and strict-launch/run.sh and is gitignored;
# tests/mesh/build/ holds compiled stub ELFs whose string tables match the
# very tokens this gate looks for. Scanning either means a surface whose
# only real in-tree witness has been deleted still reads as covered,
# because the previous run's output names it.
CORPUS_PRUNE = {"results", "build", "__pycache__"}

# Only files that contain test *logic* witness a surface. A data file that
# merely lists names — tests/expected-links.txt names all 28 links, and
# tests/release-skip-allowlist.txt names suites — would otherwise credit
# every surface it mentions, which is the same defect as crediting a
# comment: the name appears, nothing exercises it.
CORPUS_SUFFIXES = (".sh", ".bash", ".c", ".h", ".py")


def corpus_paths():
    """Tracked test sources under tests/, in a deterministic order.

    `git ls-files` is the authority: it is exactly the set that exists on
    a fresh checkout, it is already sorted, and it cannot pick up a
    gitignored artefact. The walk below is the fallback for a release
    tarball or an exported tree, and prunes the same directories in the
    same order — os.walk yields directories in filesystem order unless
    the dirnames list is sorted in place, which is why an identical tree
    produced different witness attributions on two machines."""
    rel = os.path.relpath(TESTS_DIR, REPO)
    try:
        out = subprocess.run(["git", "-C", REPO, "ls-files", "-z", "--", rel],
                             check=True, capture_output=True)
        names = [n for n in out.stdout.decode().split("\0") if n]
        if names:
            keep = []
            for n in sorted(names):
                parts = n.split(os.sep)
                if any(part in CORPUS_PRUNE for part in parts):
                    continue
                keep.append(os.path.join(REPO, n))
            return keep
    except (OSError, subprocess.CalledProcessError):
        pass

    paths = []
    for root, dirs, names in os.walk(TESTS_DIR):
        dirs[:] = sorted(d for d in dirs if d not in CORPUS_PRUNE)
        for fn in sorted(names):
            paths.append(os.path.join(root, fn))
    return sorted(paths)


def has_shebang(path):
    """An extensionless test script still counts."""
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def test_corpus():
    """Every test source under tests/ (scripts + C harnesses), excluding docs
    and the manifest itself, as a list of (path, raw_text, code_text) where
    code_text has comments removed."""
    files = []
    for p in corpus_paths():
        fn = os.path.basename(p)
        if fn.endswith(".md") or fn == "coverage-manifest.tsv":
            continue
        if not fn.endswith(CORPUS_SUFFIXES) and not has_shebang(p):
            continue
        try:
            raw = read(p)
        except OSError:
            continue
        files.append((os.path.relpath(p, REPO), raw, code_of(raw, fn)))
    return files


def witness_of(matcher, files):
    """Return the relative path of the first file that witnesses this surface,
    or None. See the rule block at the top of this file."""
    if matcher[0] == "hook":
        _kind, name_re, op_res, prog_res = matcher
        for path, raw, code in files:
            for pr in prog_res:
                if re.search(pr, code):
                    return path
            if not re.search(name_re, raw):
                continue
            for orx in op_res:
                if re.search(orx, code):
                    return path
        return None
    for path, _raw, code in files:
        for t in matcher[1]:
            if re.search(t, code):
                return path
    return None


def load_manifest():
    """Return dict (kind, name) -> reason for exemptions, and list of raw
    rows for stale detection. Format: kind<TAB>name<TAB>reason. '#' comments."""
    exemptions = {}
    if not os.path.exists(MANIFEST):
        return exemptions
    with open(MANIFEST, "r", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or not parts[2].strip():
                sys.stderr.write(
                    "manifest %s:%d malformed (need kind<TAB>name<TAB>reason): %r\n"
                    % (MANIFEST, lineno, line))
                sys.exit(1)
            kind, name, reason = parts[0].strip(), parts[1].strip(), parts[2].strip()
            exemptions[(kind, name)] = reason
    return exemptions


SELFTEST_CASES = [
    # (label, kind, hook/surface name, [(filename, text), ...], expected)
    ("C-5 regression: bare op token, file never names the hook",
     "enforce-hook", "inode_setxattr",
     [("t.sh", 'sealprobe setxattr "$T"\n')], False),
    ("comment-only mention of the hook is NOT a witness",
     "enforce-hook", "inode_setxattr",
     [("t.sh", '# exercises inode_setxattr via the mesh matrix\ntrue\n')], False),
    ("hook named (in a comment) AND its op driven in code IS a witness",
     "enforce-hook", "inode_setxattr",
     [("t.sh", '# exercises inode_setxattr\nsealprobe setxattr "$T"\n')], True),
    ("BPF program name in code alone IS a witness",
     "enforce-hook", "inode_setxattr",
     [("t.sh", 'bpftool prog show | grep comp_inode_setxattr\n')], True),
    ("C comment-only mention is NOT a witness",
     "enforce-hook", "file_truncate",
     [("t.c", '/* drives file_truncate */\nint main(void){return 0;}\n')], False),
    ("C comment claim + real call IS a witness",
     "enforce-hook", "file_truncate",
     [("t.c", '/* drives file_truncate */\nint f(void){return truncate(p,0);}\n')], True),
    ("op token inside a C comment does not count as code",
     "enforce-hook", "file_truncate",
     [("t.c", '/* file_truncate: we would call truncate here */\nint m(void){return 0;}\n')], False),
    ("observe hook is NOT witnessed by the shared op token",
     "observe-hook", "inode_create",
     [("t.sh", '# drives inode_create\nsealprobe create-in "$D"\n')], False),
    ("observe hook IS witnessed by its ao_* program name in code",
     "observe-hook", "inode_create",
     [("t.sh", 'bpftool prog show | grep ao_inode_create\n')], True),
    ("action mentioned only in a comment is NOT a witness",
     "action", "DENY_WRITE",
     [("t.sh", '# expect DENY_WRITE in the audit stream\ntrue\n')], False),
    ("action grepped in code IS a witness",
     "action", "DENY_WRITE",
     [("t.sh", 'grep -q "DENY_WRITE" "$audit"\n')], True),
]


def selftest():
    """Assert the witness rule itself. The gate is only as good as this
    definition, and the definition is the thing that silently rotted before
    (a comment mentioning a hook, or the word `open` in an unrelated file,
    used to count as coverage)."""
    surfaces = {(k, n): m for k, n, m in extract_surfaces()}
    failures = 0
    for label, kind, name, blobs, expected in SELFTEST_CASES:
        matcher = surfaces.get((kind, name))
        if matcher is None:
            print("  FAIL  %s — surface %s/%s not found in source" % (label, kind, name))
            failures += 1
            continue
        files = [(fn, text, code_of(text, fn)) for fn, text in blobs]
        got = witness_of(matcher, files) is not None
        if got == expected:
            print("  PASS  %s -> %s" % (label, "witnessed" if got else "UNWITNESSED"))
        else:
            print("  FAIL  %s -> %s (expected %s)"
                  % (label, "witnessed" if got else "UNWITNESSED",
                     "witnessed" if expected else "UNWITNESSED"))
            failures += 1
    print("== coverage-map selftest: %d/%d cases passed =="
          % (len(SELFTEST_CASES) - failures, len(SELFTEST_CASES)))
    return 1 if failures else 0


def main():
    write_matrix = None
    args = sys.argv[1:]
    if "--selftest" in args:
        return selftest()
    if "--write-matrix" in args:
        i = args.index("--write-matrix")
        write_matrix = args[i + 1]

    surfaces = extract_surfaces()
    files = test_corpus()
    exemptions = load_manifest()

    covered, gap, evidence = [], [], {}
    for kind, name, matcher in surfaces:
        w = witness_of(matcher, files)
        if w is not None:
            covered.append((kind, name))
            evidence[(kind, name)] = w
        else:
            gap.append((kind, name))

    surface_keys = {(k, n) for (k, n, _m) in surfaces}
    covered_keys = set(covered)

    errors = []

    # 1. Every gap must be an explicit exemption.
    unexempted = [g for g in gap if g not in exemptions]
    for kind, name in unexempted:
        errors.append(
            "UNWITNESSED %-16s %-32s — no test references it and no manifest "
            "exemption exists. Add a witness or a coverage-manifest.tsv row "
            "with a reason." % (kind, name))

    # 2. Stale exemptions: exemption for a surface that is now covered, or for
    #    a surface that no longer exists.
    for (kind, name), reason in sorted(exemptions.items()):
        if (kind, name) not in surface_keys:
            errors.append(
                "STALE-EXEMPTION %-16s %-32s — names a surface that no longer "
                "exists in source; remove this manifest row." % (kind, name))
        elif (kind, name) in covered_keys:
            errors.append(
                "STALE-EXEMPTION %-16s %-32s — a test now references this "
                "surface; remove the manifest exemption (ratchet down)."
                % (kind, name))

    # Report
    by_kind = {}
    for kind, name in covered:
        by_kind.setdefault(kind, [0, 0])[0] += 1
    for kind, name in gap:
        by_kind.setdefault(kind, [0, 0])[1] += 1

    print("== compartment-bpf static coverage map ==")
    print("%-16s %8s %8s %8s" % ("surface", "covered", "gap", "total"))
    tc = tg = 0
    for kind in sorted(by_kind):
        c, g = by_kind[kind]
        tc += c
        tg += g
        print("%-16s %8d %8d %8d" % (kind, c, g, c + g))
    print("%-16s %8d %8d %8d" % ("TOTAL", tc, tg, tc + tg))
    print("exemptions declared: %d" % len(exemptions))

    if gap:
        print("\n-- gaps (must be exempted) --")
        for kind, name in gap:
            tag = "exempt" if (kind, name) in exemptions else "UNWITNESSED"
            print("  [%-11s] %-16s %s" % (tag, kind, name))

    if write_matrix:
        write_matrix_file(write_matrix, surfaces, covered_keys, exemptions,
                          evidence)
        print("\nwrote coverage matrix -> %s" % write_matrix)

    if errors:
        print("\n== FAIL: %d coverage-accountability error(s) ==" % len(errors))
        for e in errors:
            print("  " + e)
        return 1

    print("\n== OK: every surface is witnessed or explicitly exempted ==")
    return 0


def write_matrix_file(path, surfaces, covered_keys, exemptions, evidence=None):
    lines = []
    lines.append("# compartment-bpf coverage matrix (generated)\n")
    lines.append("Generated by `tools/coverage-map.py --write-matrix`. "
                 "Do not edit by hand.\n")
    lines.append("\nStatus key: `witnessed` = referenced by a test under "
                 "tests/; `exempt` = accepted gap (see reason).\n")
    lines.append("\nThe note column names the FIRST witnessing file in sorted "
                 "order, not the strongest one and not the only one. A surface "
                 "is routinely referenced by several tests, and this gate is "
                 "about existence, not accuracy \u2014 the exact-delta counter "
                 "assertions are catalogued in COUNTERS.md.\n")
    evidence = evidence or {}
    cur = None
    for kind, name, _m in surfaces:
        if kind != cur:
            lines.append("\n## %s\n" % kind)
            lines.append("\n| surface | status | note |")
            lines.append("\n|---|---|---|")
            cur = kind
        if (kind, name) in covered_keys:
            status, note = "witnessed", "`%s`" % evidence.get((kind, name), "")
        elif (kind, name) in exemptions:
            status, note = "exempt", exemptions[(kind, name)]
        else:
            status, note = "**UNWITNESSED**", ""
        lines.append("\n| `%s` | %s | %s |" % (name, status, note))
    lines.append("\n")
    with open(path, "w") as f:
        f.write("".join(lines))


if __name__ == "__main__":
    sys.exit(main())
