#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-15-prog-detach.sh
# V-6 re-run #5 P2 B-4 (2026-05-16): documentation-verification witness for
# the LIMITATIONS.md "Privileged BPF program detach" row (V-6 P1-I class).
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
#      for the distinctive strings "Privileged BPF link detach",
#      "BPF_LINK_DETACH", and "CAP_BPF" on the same row. A future
#      doc-sweep that accidentally drops or paraphrases the row will fail
#      this witness; an operator reading the row will see the same wording
#      this witness asserts.
#
#      Terminology note: the row originally said "Privileged BPF program
#      detach" / "bpftool prog detach". A4-INFO-1 (hardening Tier-1,
#      2026-05-16) corrected this to "Privileged BPF link detach" /
#      "BPF_LINK_DETACH" because the latter is the actual UAPI for LSM
#      BPF link detach; `bpftool prog detach` is for legacy program-
#      array attachment. This witness is updated symmetrically so a
#      doc-sweep regression on the corrected wording is still caught.
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
if ! grep -qE 'Privileged BPF link detach.*BPF_LINK_DETACH.*CAP_BPF' "$LIMITATIONS"; then
	echo "--- LIMITATIONS.md link-detach context ---" >&2
	grep -n -i 'link detach\|BPF_LINK_DETACH\|CAP_BPF' "$LIMITATIONS" >&2 || true
	bypass_fail "LIMITATIONS.md link-detach row missing or paraphrased (expected 'Privileged BPF link detach' + 'BPF_LINK_DETACH' + 'CAP_BPF' on the same line; corrected from prog-detach wording in A4-INFO-1, 2026-05-16)"
fi

# Mitigation column must still mention restricting CAP_BPF and the SIEM
# alerting path — the operator-side defense documented for v0.
if ! grep -qE 'Restrict.*CAP_BPF|CapabilityBoundingSet' "$LIMITATIONS"; then
	bypass_fail "LIMITATIONS.md prog-detach row lost its CAP_BPF restriction guidance"
fi
if ! grep -qE 'SIEM|enforcement-stop|ringbuf' "$LIMITATIONS"; then
	bypass_fail "LIMITATIONS.md prog-detach row lost its SIEM/ringbuf alerting guidance"
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
	bypass_fail "baseline --dry-run on a well-formed profile failed (rc=$rc); the prog-detach threat row's premise (a working loader) is not satisfied"
fi

bypass_pass "LIMITATIONS.md prog-detach row text intact; --dry-run baseline rc=0 (parse-time witness; runtime detach deferred to RT-* suite)"
