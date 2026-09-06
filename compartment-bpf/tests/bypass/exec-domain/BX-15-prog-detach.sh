#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-15-prog-detach.sh
# Documentation-verification witness for the LIMITATIONS.md
# "Privileged removal of the LSM links" row.
#
# The synthesis flagged the LIMITATIONS.md row at line ~128 as unwitnessed
# by any BX test. A runtime exploit witness would require live BPF + CAP_BPF
# + a real kernel attach (out of scope for the dry-run/parse-time bypass
# suite, which intentionally runs without a live module to keep coverage
# reproducible across hosts).
#
# This witness verifies two non-runtime properties so the LIMITATIONS row
# is no longer documentation-only:
#
#   1. The LIMITATIONS.md row text correctly describes the threat. We grep
#      for the distinctive strings "Privileged removal of the LSM links",
#      "EOPNOTSUPP", "unlink" and "CAP_BPF" on the same row. A future
#      doc-sweep that accidentally drops or paraphrases the row will fail
#      this witness; an operator reading the row will see the same wording
#      this witness asserts.
#
#      Terminology history. The row first said "Privileged BPF program
#      detach" / `bpftool prog detach`; that was corrected to "Privileged
#      BPF link detach" / `bpf(BPF_LINK_DETACH)` on the grounds that
#      BPF_LINK_DETACH is the UAPI for detaching a BPF link. v0.8 corrects
#      it again, because BPF_LINK_DETACH does not work here either:
#      bpf_tracing_link_lops — the link ops used by every BPF-LSM and
#      tracing link — defines .release/.dealloc/.show_fdinfo/.fill_link_info
#      and NO .detach, so link_detach() returns -EOPNOTSUPP on both 6.8 and
#      7.0. The only removal path is unlink() of the bpffs pins plus
#      dropping the last held fd. Telling an operator to harden against
#      BPF_LINK_DETACH sends them after a syscall that cannot hurt them
#      while the pin directory stays unguarded, so the row (and this
#      witness) now names the real surface.
#
#   2. Baseline: `compartment-bpf --dry-run` on a well-formed profile
#      exits 0. The LIMITATIONS row's premise is that *enforcement* can be
#      detached at runtime; this baseline confirms the loader itself
#      validates the profile cleanly, so the threat surface described in
#      the row is what would otherwise be in effect.
#
# This is a parse-time / docs witness only — NOT a runtime kernel test.
# A runtime detach test would require live BPF and CAP_BPF available in
# the bypass harness; we explicitly defer that to a future RT-* suite.
set -u
BYPASS_NAME="BX-15-prog-detach"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

# This witness needs only the daemon binary + the LIMITATIONS.md file
# under REPO; no LSM activation required. We still gate on the daemon
# being built so the dry-run witness is meaningful.
[ -x "$DAEMON" ] || bypass_skip "daemon not built"
LIMITATIONS="$REPO/LIMITATIONS.md"
[ -r "$LIMITATIONS" ] || bypass_skip "LIMITATIONS.md not present at $LIMITATIONS"

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# ----- Witness 1: LIMITATIONS.md row text is intact. -----
# All three strings must appear on the same line so a future rewrite
# that splits the row or drops one term is caught.
if ! grep -qE 'Privileged removal of the LSM links.*EOPNOTSUPP.*unlink.*CAP_BPF' "$LIMITATIONS"; then
	echo "--- LIMITATIONS.md link-removal context ---" >&2
	grep -n -i 'link detach\|removal of the LSM links\|BPF_LINK_DETACH\|CAP_BPF' "$LIMITATIONS" >&2 || true
	bypass_fail "LIMITATIONS.md link-removal row missing or paraphrased (expected 'Privileged removal of the LSM links' + 'EOPNOTSUPP' + 'unlink' + 'CAP_BPF' on the same line; v0.8 corrected this away from the BPF_LINK_DETACH wording, which names a syscall that returns -EOPNOTSUPP for LSM links)"
fi

# The row must keep saying, in so many words, that BPF_LINK_DETACH is NOT
# the removal path — that correction is the whole point of the v0.8 rewrite.
if ! grep -qE 'BPF_LINK_DETACH.*does not work|does not work.*BPF_LINK_DETACH' "$LIMITATIONS"; then
	bypass_fail "LIMITATIONS.md link-removal row no longer states that bpf(BPF_LINK_DETACH) does not work on an LSM link"
fi

# Mitigation column must still mention restricting CAP_BPF and the SIEM
# alerting path — the operator-side defense documented for v0.
if ! grep -qE 'Restrict.*CAP_BPF|CapabilityBoundingSet' "$LIMITATIONS"; then
	bypass_fail "LIMITATIONS.md link-removal row lost its CAP_BPF restriction guidance"
fi
if ! grep -qE 'SIEM|enforcement-stop|ringbuf' "$LIMITATIONS"; then
	bypass_fail "LIMITATIONS.md link-removal row lost its SIEM/ringbuf alerting guidance"
fi

# ----- Witness 2: baseline --dry-run on a well-formed profile rc=0. -----
ACTOR=$(ed_create_actor actor)
TARGET="$TMP/target"
echo content > "$TARGET"
cat > "$TMP/baseline.conf" <<EOF
actor myactor = $ACTOR
seal $ACTOR full
seal $TARGET no-write actor=myactor
EOF

OUT="$TMP/baseline.err"
"$DAEMON" --dry-run "$TMP/baseline.conf" >"$OUT" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
	cat "$OUT" >&2
	bypass_fail "baseline --dry-run on a well-formed profile failed (rc=$rc); the link-removal threat row's premise (a working loader) is not satisfied"
fi

bypass_pass "LIMITATIONS.md link-removal row text intact (BPF_LINK_DETACH correctly documented as -EOPNOTSUPP); --dry-run baseline rc=0 (parse-time witness; runtime pin-unlink deferred to RT-* suite)"
