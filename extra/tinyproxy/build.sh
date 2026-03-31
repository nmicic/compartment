#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# ============================================================
# build.sh — clone & compile tinyproxy into $HOME/.local
# No root needed. Tested on RHEL/CentOS/Debian/Ubuntu.
# ============================================================
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${HOME}/.local"
SRC_DIR="${BASE_DIR}/src/tinyproxy"
REPO="https://github.com/tinyproxy/tinyproxy.git"

# ── Colour helpers ──────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[FAIL]\033[0m  $*" >&2; exit 1; }

# ── Dependency check ────────────────────────────────────────
info "Checking build dependencies..."
MISSING=()
for cmd in git gcc make autoconf automake gperf; do
  command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "Missing: ${MISSING[*]}"
  echo ""
  echo "  Debian/Ubuntu:  sudo apt install -y git gcc make autoconf automake gperf"
  echo "  RHEL/CentOS 7:  sudo yum  install -y git gcc make autoconf automake gperf"
  echo "  RHEL/CentOS 8+: sudo dnf  install -y git gcc make autoconf automake gperf"
  echo "  Alpine:         apk add git gcc musl-dev make autoconf automake gperf"
  echo ""
  echo "  No sudo? Ask your sysadmin for: autoconf automake gcc make gperf"
  echo "  They are dev tools — low risk, widely available in corporate mirrors."
  die "Install missing deps then re-run build.sh"
fi
ok "All build deps present."

# ── Clone / update ──────────────────────────────────────────
if [[ -d "$SRC_DIR/.git" ]]; then
  info "Source already cloned — pulling latest..."
  git -C "$SRC_DIR" pull --ff-only
else
  info "Cloning tinyproxy..."
  mkdir -p "$(dirname "$SRC_DIR")"
  git clone --depth=1 "$REPO" "$SRC_DIR"
fi

# ── Build ───────────────────────────────────────────────────
cd "$SRC_DIR"
info "Running autogen.sh..."
./autogen.sh

info "Configuring (prefix=$PREFIX)..."
./configure \
  --prefix="$PREFIX" \
  --sysconfdir="$BASE_DIR" \
  --localstatedir="${HOME}/.local/var" \
  --disable-debug \
  2>&1 | tail -5

info "Compiling..."
make -j"$(nproc 2>/dev/null || echo 2)"

info "Installing to $PREFIX ..."
make install

# ── PATH hint ───────────────────────────────────────────────
TINYPROXY_BIN="${PREFIX}/bin/tinyproxy"
ok "Binary: $TINYPROXY_BIN"
"$TINYPROXY_BIN" --version

echo ""
if [[ ":$PATH:" != *":${PREFIX}/bin:"* ]]; then
  warn "\$HOME/.local/bin is not in your PATH."
  echo "  Add this to ~/.bashrc or ~/.profile:"
  echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

ok "Build complete. Run: ./start.sh"
