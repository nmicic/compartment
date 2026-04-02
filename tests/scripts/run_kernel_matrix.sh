#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_kernel_matrix.sh — test compartment across kernel versions using virtme-ng
#
# Boots each kernel in a lightweight QEMU VM (virtme-ng), builds compartment,
# and runs tests. Uses host filesystem via 9p — fast iteration, no disk images.
#
# NOTE: Landlock filesystem tests CANNOT work under virtme-ng (9p doesn't
# support Landlock). This script tests: compilation, --verify, seccomp,
# env sanitization, graceful degradation. For full Landlock filesystem tests,
# use a real VM (KVM with disk image).
#
# Requirements:
#   pip install virtme-ng   (or: apt install virtme-ng)
#   /dev/kvm accessible     (optional: --no-kvm for TCG emulation, slower)
#
# Usage:
#   ./tests/scripts/run_kernel_matrix.sh                    # all kernels, with KVM
#   ./tests/scripts/run_kernel_matrix.sh --no-kvm           # without KVM (slower)
#   ./tests/scripts/run_kernel_matrix.sh --kernels "v5.15 v6.8"  # specific kernels
#   ./tests/scripts/run_kernel_matrix.sh --verbose          # show full output
#
# Kernels tested and what they exercise:
#   v5.4   — no Landlock at all (graceful degradation)
#   v5.10  — no Landlock (pre-5.13)
#   v5.15  — Landlock ABI v1 (needs lsm= boot param on Ubuntu mainline)
#   v6.1   — Landlock ABI v2 (REFER support)
#   v6.5   — Landlock ABI v3 (TRUNCATE support)
#   v6.8   — Landlock ABI v4 (IOCTL_DEV support)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults
USE_KVM=1
VERBOSE=0
MEMORY="2G"
CPUS=1
KERNELS="v5.4 v5.10 v5.15 v6.1 v6.5 v6.8"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-kvm)    USE_KVM=0; shift ;;
        --verbose)   VERBOSE=1; shift ;;
        --memory)    MEMORY="$2"; shift 2 ;;
        --cpus)      CPUS="$2"; shift 2 ;;
        --kernels)   KERNELS="$2"; shift 2 ;;
        --help|-h)
            head -30 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Check dependencies
if ! command -v vng >/dev/null 2>&1; then
    echo "ERROR: virtme-ng (vng) not found."
    echo "  Install: pip install virtme-ng"
    echo "       or: apt install virtme-ng"
    exit 1
fi

KVM_FLAG=""
if [[ $USE_KVM -eq 0 ]]; then
    KVM_FLAG="--disable-kvm"
    echo "NOTE: Running without KVM (TCG emulation) — tests will be slower."
elif [[ ! -w /dev/kvm ]] 2>/dev/null; then
    echo "WARNING: /dev/kvm not writable — falling back to TCG emulation."
    echo "  Fix: sudo usermod -aG kvm \$(whoami)"
    KVM_FLAG="--disable-kvm"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Compartment kernel matrix test (virtme-ng)                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Kernels: $KERNELS"
echo "KVM: ${KVM_FLAG:-enabled}"
echo "Memory: $MEMORY  CPUs: $CPUS"
echo ""

TOTAL=0
PASS=0
FAIL=0
SKIP=0
RESULTS=""

run_kernel_test() {
    local kernel="$1"
    local test_name="$2"
    local cmd="$3"
    local expect_rc="${4:-0}"   # expected exit code (0=success, 1=expected failure)
    local extra_args="${5:-}"   # extra vng args (e.g. --append for boot params)

    TOTAL=$((TOTAL + 1))
    printf "  %-12s %-40s " "$kernel" "$test_name"

    local output rc=0
    local vng_cmd="vng --run $kernel $KVM_FLAG --rw --pwd --memory $MEMORY --cpus $CPUS $extra_args --exec"

    output=$($vng_cmd "$cmd" 2>&1) || rc=$?

    if [[ $rc -eq $expect_rc ]]; then
        echo "PASS"
        PASS=$((PASS + 1))
        RESULTS="${RESULTS}PASS  $kernel  $test_name\n"
    else
        echo "FAIL (rc=$rc, expected=$expect_rc)"
        FAIL=$((FAIL + 1))
        RESULTS="${RESULTS}FAIL  $kernel  $test_name  (rc=$rc)\n"
    fi

    if [[ $VERBOSE -eq 1 ]] && [[ -n "$output" ]]; then
        echo "$output" | sed 's/^/    | /'
        echo ""
    fi
}

# ─── Test each kernel ───────────────────────────────────────────────────

for K in $KERNELS; do
    echo ""
    echo "--- Kernel: $K ---"

    # Test 1: Build (compile on this kernel's userspace)
    run_kernel_test "$K" "compile" \
        "make -C $REPO_DIR clean >/dev/null 2>&1; make -C $REPO_DIR 2>&1"

    # Test 2: --verify (system capability check)
    # Kernels < 5.13 have no Landlock — --verify should report it and fail
    # Kernels >= 5.13 with lsm= param should pass (except 9p warning)
    if [[ "$K" == "v5.4" ]] || [[ "$K" == "v5.10" ]]; then
        # No Landlock at all — verify should fail (Landlock + 9p = 2 failures)
        run_kernel_test "$K" "verify (no landlock)" \
            "$REPO_DIR/compartment-user --verify" 1
    else
        # Has Landlock but on 9p — verify fails due to fs type
        # Use lsm= boot param for 5.15 which doesn't enable Landlock by default
        boot_param=""
        if [[ "$K" == "v5.15" ]]; then
            boot_param='--append "lsm=landlock,lockdown,capability,yama,apparmor"'
        fi
        run_kernel_test "$K" "verify (landlock+9p)" \
            "$REPO_DIR/compartment-user --verify" 1 "$boot_param"
    fi

    # Test 3: seccomp enforcement (works on all kernels, independent of fs)
    run_kernel_test "$K" "seccomp deny ptrace" \
        "$REPO_DIR/compartment-user --unsecure --no-landlock --block ptrace -- /bin/true"

    # Test 4: Preflight refuses on 9p without --unsecure
    run_kernel_test "$K" "preflight refuses (9p)" \
        "$REPO_DIR/compartment-user -- /bin/true" 1

    # Test 5: --unsecure allows execution on 9p
    run_kernel_test "$K" "--unsecure proceeds" \
        "$REPO_DIR/compartment-user --unsecure -- /bin/true"

    # Test 6: --no-landlock bypasses fs check
    run_kernel_test "$K" "--no-landlock bypasses" \
        "$REPO_DIR/compartment-user --no-landlock -- /bin/true"

    # Test 7: env sanitization (works everywhere)
    run_kernel_test "$K" "env strip LD_PRELOAD" \
        "LD_PRELOAD=evil.so $REPO_DIR/compartment-user --unsecure --no-landlock --no-seccomp -- env | grep -c LD_PRELOAD" 1
done

# ─── Summary ────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  KERNEL MATRIX RESULTS                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "$RESULTS"
echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL  Skip: $SKIP"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
