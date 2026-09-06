# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# Makefile — Companion isolation tools
#
# compartment-user  — Landlock + seccomp + env sanitize (userspace, no deps)
# compartment-root  — Full namespace + chroot container (no deps)

CC      = cc

PREFIX     = /usr/local
BINDIR     = $(PREFIX)/bin
MANDIR     = $(PREFIX)/share/man
SYSCONFDIR = /etc
CONFDIR    = $(SYSCONFDIR)/compartment

# ── Hardening ──────────────────────────────────────────────────────
#
# These flags are stated explicitly rather than inherited from the
# distribution's gcc specs.  Debian and Ubuntu enable PIE, CET and
# stack-clash probes by default; Fedora, RHEL, Alpine/musl and a
# self-built gcc do not, so a binary built there used to be measurably
# weaker than the one the project describes.
#
# Anything a toolchain might not know is probed with a real compile+link
# and dropped if it fails, so the build still works on older or
# non-x86 targets.

# GNU make splits $(call ...) arguments on commas, so a flag that contains
# one (-Wl,-z,...) has to be passed through a variable.
COMMA := ,

# cc-has FLAGS — "yes" if $(CC) compiles *and links* a trivial program with
# FLAGS and no warnings.  -Werror turns "flag accepted but unsupported here"
# diagnostics (e.g. _FORTIFY_SOURCE=3 on glibc < 2.35) into a failed probe.
cc-has = $(shell echo 'int main(void){return 0;}' | \
	 $(CC) $(1) -Werror -x c - -o /dev/null > /dev/null 2>&1 && echo yes)

HARDEN_CFLAGS  = -fstack-protector-strong -fPIE \
                 -Wformat -Wformat=2 -Werror=format-security
HARDEN_LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

# Stack-clash probes: gcc >= 8 / clang >= 11, x86 and aarch64 only.
ifeq ($(call cc-has,-fstack-clash-protection),yes)
HARDEN_CFLAGS += -fstack-clash-protection
endif

# Control-flow enforcement (CET on x86, BTI/PAC on aarch64).
ifeq ($(call cc-has,-fcf-protection=full),yes)
HARDEN_CFLAGS += -fcf-protection=full
endif

# Keep .text and the ELF headers on separate pages.
LD_SEPARATE_CODE := -Wl$(COMMA)-z$(COMMA)separate-code
ifeq ($(call cc-has,$(LD_SEPARATE_CODE)),yes)
HARDEN_LDFLAGS += $(LD_SEPARATE_CODE)
endif

# _FORTIFY_SOURCE=3 needs glibc >= 2.35 and gcc >= 12; fall back to 2, and
# to nothing at all if the libc has no fortification.  -U first: most
# distributions predefine it, and redefining is a warning.
ifeq ($(call cc-has,-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3),yes)
HARDEN_CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
else ifeq ($(call cc-has,-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2),yes)
HARDEN_CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif

BASE_CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -D_GNU_SOURCE -O2

# EXTRA_CFLAGS / EXTRA_LDFLAGS append to (rather than replace) the flags
# above, so a sanitizer or coverage build keeps the warning set and the
# feature macros:
#   make EXTRA_CFLAGS='-fsanitize=address,undefined -U_FORTIFY_SOURCE -g' #        EXTRA_LDFLAGS='-fsanitize=address,undefined'
CFLAGS  = $(BASE_CFLAGS) $(HARDEN_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS = $(HARDEN_LDFLAGS) $(EXTRA_LDFLAGS)

.PHONY: all clean test test-integration test-quick test-root hardened \
        install install-man install-profiles show-hardening \
        check check-shell check-modes

# Both tools: zero dependencies
all: compartment-user compartment-root

# Print the flags the probes selected on this toolchain.
show-hardening:
	@echo "CC      = $(CC)"
	@echo "CFLAGS  = $(CFLAGS)"
	@echo "LDFLAGS = $(LDFLAGS)"

# Hardened build: randomize REAL_SHELL_DIR so attacker can't guess path.
# Prints the generated path — you must create it and move real shells there.
# Builds both tools: compartment-root has no shell-replacement mode, so it is
# the ordinary binary, but "hardened" must not leave it unbuilt.
hardened: compartment-root
	$(eval SHELL_SUFFIX := $(shell head -c16 /dev/urandom | md5sum | head -c12))
	$(eval SHELL_DIR := /bin/.shells_$(SHELL_SUFFIX))
	$(CC) $(CFLAGS) $(LDFLAGS) -DREAL_SHELL_DIR='"$(SHELL_DIR)"' \
		-o compartment-user compartment-user.c
	@echo "Built: compartment-user (REAL_SHELL_DIR=$(SHELL_DIR))"
	@echo "Built: compartment-root"
	@echo ""
	@echo "Install: sudo mkdir -p $(SHELL_DIR)"
	@echo "         sudo mv /bin/bash $(SHELL_DIR)/bash"
	@echo "         sudo ln -sf \$$(pwd)/compartment-user /bin/bash"

compartment-user: compartment-user.c compartment.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ compartment-user.c
	@echo "Built: compartment-user (Landlock + seccomp + env sanitize, no deps)"

# compartment-root: zero dependencies (no libseccomp, no libcap)
compartment-root: compartment-root.c compartment.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ compartment-root.c
	@echo "Built: compartment-root (no deps: raw BPF seccomp, raw prctl caps)"

tests/probes/deny_probe: tests/probes/deny_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "Built: deny_probe (sandbox validation probe)"

test-integration: all tests/probes/deny_probe
	./tests/scripts/run_all.sh

test test-quick: all tests/probes/deny_probe
	./tests/scripts/run_all.sh --quick

# Root-only suites (tests/scripts/root.d/). Must be run as root:
#   sudo make test-root
test-root: all tests/probes/deny_probe
	./tests/scripts/run_root_tests.sh

# Own the installed files as root when we are root; stay silent about
# ownership otherwise so an unprivileged DESTDIR staging build still works.
INSTALL_OWNER = $(shell [ "$$(id -u)" = "0" ] && echo "-o root -g root")

install: all install-man install-profiles
	install -d -m 755 $(INSTALL_OWNER) $(DESTDIR)$(BINDIR)
	install -m 755 $(INSTALL_OWNER) compartment-user $(DESTDIR)$(BINDIR)/
	install -m 755 $(INSTALL_OWNER) compartment-root $(DESTDIR)$(BINDIR)/

install-man:
	install -d -m 755 $(INSTALL_OWNER) $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(MANDIR)/man8
	install -m 644 $(INSTALL_OWNER) man/compartment-user.1 $(DESTDIR)$(MANDIR)/man1/
	install -m 644 $(INSTALL_OWNER) man/compartment-root.8 $(DESTDIR)$(MANDIR)/man8/

# System profile directory. Both tools search /etc/compartment/<name>.conf
# (HOWTO.md "Profile Files", step 3), so it must exist and be root-owned:
# a user-writable directory here would let any local user dictate the policy
# of every sandboxed process on the machine.
install-profiles:
	install -d -m 755 $(INSTALL_OWNER) $(DESTDIR)$(CONFDIR)
	install -m 644 $(INSTALL_OWNER) examples/*.conf $(DESTDIR)$(CONFDIR)/
	@echo "Installed profiles in $(DESTDIR)$(CONFDIR)/"
	@echo "NOTE: ai-agent.conf and strict.conf shadow the built-in profiles of"
	@echo "      the same name — /etc/compartment is searched before the"
	@echo "      built-ins.  Remove them from $(DESTDIR)$(CONFDIR)/ to keep the"
	@echo "      compiled-in defaults."

# ── Repository hygiene checks (also run in CI) ─────────────────────

check: check-shell check-modes

# Shell sources of this project.  compartment-bpf/ is a separate subtree
# with its own conventions and is not gated here.
SHELL_DIRS = examples extra man scripts tests tools

check-shell:
	@command -v shellcheck > /dev/null 2>&1 || 		{ echo "check-shell: shellcheck not installed (apt install shellcheck)"; exit 1; }
	@files=$$(git ls-files '*.sh' 2>/dev/null | grep -v '^compartment-bpf/' || 		find . -name '*.sh' -not -path './compartment-bpf/*' -not -path './.git/*'); 	echo "shellcheck -S warning over $$(echo "$$files" | wc -l) files"; 	shellcheck -S warning $$files

# Every *.sh that starts with a shebang must be executable, and every one
# that does not (a sourced library) must not be: a test that ships
# non-executable is silently skipped by anything that iterates over
# executables, and a "library" that is executable invites being run.
check-modes:
	@rc=0; 	for f in $$(git ls-files $(SHELL_DIRS) sandbox.sh 2>/dev/null | grep '\.sh$$'); do 		mode=$$(git ls-files -s "$$f" | awk '{print $$1}'); 		if head -c2 "$$f" | grep -q '^#!'; then 			if [ "$$mode" != "100755" ]; then 				echo "check-modes: $$f has a shebang but is mode $$mode (want 100755)"; rc=1; 			fi; 		else 			if [ "$$mode" = "100755" ]; then 				echo "check-modes: $$f has no shebang but is executable (want 100644)"; rc=1; 			fi; 		fi; 	done; 	if [ $$rc -eq 0 ]; then echo "check-modes: all shell scripts have the right mode"; fi; 	exit $$rc

clean:
	rm -f compartment-user compartment-root tests/probes/deny_probe
