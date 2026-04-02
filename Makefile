# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# extra/Makefile — Companion isolation tools
#
# compartment-user  — Landlock + seccomp + env sanitize (userspace, no deps)
# compartment-root  — Full namespace + chroot container (no deps)

CC      = cc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -D_GNU_SOURCE -O2 \
          -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-z,relro,-z,now

PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man

.PHONY: all clean test test-integration test-quick hardened install install-man

# Both tools: zero dependencies
all: compartment-user compartment-root

# Hardened build: randomize REAL_SHELL_DIR so attacker can't guess path.
# Prints the generated path — you must create it and move real shells there.
hardened:
	$(eval SHELL_SUFFIX := $(shell head -c16 /dev/urandom | md5sum | head -c12))
	$(eval SHELL_DIR := /bin/.shells_$(SHELL_SUFFIX))
	$(CC) $(CFLAGS) $(LDFLAGS) -DREAL_SHELL_DIR='"$(SHELL_DIR)"' \
		-o compartment-user compartment-user.c
	@echo "Built: compartment-user (REAL_SHELL_DIR=$(SHELL_DIR))"
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
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: deny_probe (sandbox validation probe)"

test-integration: all tests/probes/deny_probe
	./tests/scripts/run_all.sh

test test-quick: all tests/probes/deny_probe
	./tests/scripts/run_all.sh --quick

install: all install-man
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 compartment-user $(DESTDIR)$(BINDIR)/
	install -m 755 compartment-root $(DESTDIR)$(BINDIR)/

install-man:
	install -d $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(MANDIR)/man8
	install -m 644 man/compartment-user.1 $(DESTDIR)$(MANDIR)/man1/
	install -m 644 man/compartment-root.8 $(DESTDIR)$(MANDIR)/man8/

clean:
	rm -f compartment-user compartment-root tests/probes/deny_probe
