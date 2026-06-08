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


def hook_tokens(name, observe):
    """Acceptable witness token regexes for an LSM hook. A hook is rarely
    referenced by its exact kernel hook name; witnesses drive the *operation*
    it guards (e.g. inode_setxattr is exercised as the op `setxattr` in the
    mesh matrix) or, for observe, the BPF program name `ao_<hook>`."""
    toks = [r'\b' + re.escape(name) + r'\b']
    # op suffix for fs hooks (inode_setxattr -> setxattr, file_truncate ->
    # truncate). Only for fs-ish prefixes; task_/mmap_ suffixes are too
    # generic ("alloc"/"free"/"file") to be a reliable proxy.
    for pfx in ("inode_", "file_"):
        if name.startswith(pfx):
            toks.append(r'\b' + re.escape(name[len(pfx):]) + r'\b')
    # observe program spelling — observe-hook surfaces only, so the enforce
    # task_alloc hook is not falsely credited by an observe ao_task_alloc ref.
    if observe:
        toks.append(r'\bao_' + re.escape(name) + r'\b')
    return toks


def extract_surfaces():
    """Return ordered list of (kind, name, [token_regex, ...]) tuples."""
    surfaces = []

    bpf = read(BPF)
    # Enforce LSM hooks. SEC("lsm/foo") and SEC("lsm.s/foo"). Dedupe (the
    # dual inode_setattr wrapper emits the same hook name twice).
    hooks = []
    for m in re.finditer(r'SEC\("lsm(?:\.s)?/([a-z_]+)"\)', bpf):
        if m.group(1) not in hooks:
            hooks.append(m.group(1))
    for h in hooks:
        surfaces.append(("enforce-hook", h, hook_tokens(h, observe=False)))

    obs = read(OBSERVE_BPF)
    ohooks = []
    for m in re.finditer(r'SEC\("lsm(?:\.s)?/([a-z_]+)"\)', obs):
        if m.group(1) not in ohooks:
            ohooks.append(m.group(1))
    for h in ohooks:
        surfaces.append(("observe-hook", h, hook_tokens(h, observe=True)))

    abi = read(ABI)
    # Deny actions. ACTION_DENY_X enum constants. The audit stream emits the
    # bare DENY_X token, so a witness may reference either spelling.
    actions = []
    for m in re.finditer(r'\bACTION_(DENY_[A-Z_]+)\b', abi):
        if m.group(1) not in actions:
            actions.append(m.group(1))
    for a in actions:
        # token matches "ACTION_DENY_X" or audit-line "DENY_X"
        surfaces.append(("action", a, [r'\b' + re.escape(a) + r'\b']))

    # Enforce counters: the map *definitions* only ( "} name_total SEC" ),
    # which excludes comment-only mentions of hypothetical counters.
    counters = []
    for m in re.finditer(r'^\}\s*([a-z_]+_total)\s+SEC\("\.maps"\)', bpf, re.M):
        if m.group(1) not in counters:
            counters.append(m.group(1))
    for c in counters:
        surfaces.append(("counter", c, [r'\b' + re.escape(c) + r'\b']))

    # Observe counters: #define C_X <n>, excluding the C_MAX sentinel.
    ocounters = []
    for m in re.finditer(r'^#define\s+(C_[A-Z_]+)\s+\d+', obs, re.M):
        if m.group(1) != "C_MAX" and m.group(1) not in ocounters:
            ocounters.append(m.group(1))
    for c in ocounters:
        surfaces.append(("observe-counter", c, [r'\b' + re.escape(c) + r'\b']))

    return surfaces


def test_corpus():
    """All test sources under tests/ (scripts + C harness), excluding docs
    and the manifest itself. Returns concatenated text."""
    blobs = []
    for root, _dirs, files in os.walk(TESTS_DIR):
        for fn in files:
            if fn.endswith(".md") or fn == "coverage-manifest.tsv":
                continue
            p = os.path.join(root, fn)
            try:
                blobs.append(read(p))
            except OSError:
                pass
    return "\n".join(blobs)


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


def main():
    write_matrix = None
    args = sys.argv[1:]
    if "--write-matrix" in args:
        i = args.index("--write-matrix")
        write_matrix = args[i + 1]

    surfaces = extract_surfaces()
    corpus = test_corpus()
    exemptions = load_manifest()

    covered, gap = [], []
    for kind, name, toks in surfaces:
        if any(re.search(t, corpus) for t in toks):
            covered.append((kind, name))
        else:
            gap.append((kind, name))

    surface_keys = {(k, n) for (k, n, _t) in surfaces}
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
        write_matrix_file(write_matrix, surfaces, covered_keys, exemptions)
        print("\nwrote coverage matrix -> %s" % write_matrix)

    if errors:
        print("\n== FAIL: %d coverage-accountability error(s) ==" % len(errors))
        for e in errors:
            print("  " + e)
        return 1

    print("\n== OK: every surface is witnessed or explicitly exempted ==")
    return 0


def write_matrix_file(path, surfaces, covered_keys, exemptions):
    lines = []
    lines.append("# compartment-bpf coverage matrix (generated)\n")
    lines.append("Generated by `tools/coverage-map.py --write-matrix`. "
                 "Do not edit by hand.\n")
    lines.append("\nStatus key: `witnessed` = referenced by a test under "
                 "tests/; `exempt` = accepted gap (see reason).\n")
    cur = None
    for kind, name, _t in surfaces:
        if kind != cur:
            lines.append("\n## %s\n" % kind)
            lines.append("\n| surface | status | note |")
            lines.append("\n|---|---|---|")
            cur = kind
        if (kind, name) in covered_keys:
            status, note = "witnessed", ""
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
