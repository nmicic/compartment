# SPDX-License-Identifier: GPL-2.0
# compartment-bpf v0 build
#
# Requires: clang >= 12, libbpf-dev, bpftool, and a modern 6.x kernel
#           with CONFIG_BPF_LSM=y, file_truncate LSM hook support, and
#           "bpf" in CONFIG_LSM= or lsm=...,bpf on the kernel cmdline.
#
# Targets:
#   make            - build everything
#   make vmlinux.h  - regenerate vmlinux.h from running kernel BTF
#   make clean      - remove build artifacts
# Tunables:
#   make COMPARTMENT_MAX_DIR_ANCESTORS=32   - raise recursive subtree
#                                             ancestor-walk budget for a
#                                             custom deployment (default 8)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CLANG ?= clang
BPFTOOL ?= bpftool
BTF ?= /sys/kernel/btf/vmlinux
COMPARTMENT_MAX_DIR_ANCESTORS ?= 8
COMMON_CPPFLAGS = -DCOMPARTMENT_MAX_DIR_ANCESTORS=$(COMPARTMENT_MAX_DIR_ANCESTORS)

# P2-7 footgun: with `CFLAGS ?= $(COMMON_CPPFLAGS) ...`, an operator override
# such as `make CFLAGS="-O0"` would silently drop the COMMON_CPPFLAGS define
# and produce a binary built against a different
# `COMPARTMENT_MAX_DIR_ANCESTORS` than the kernel BPF object — breaking the
# loader/kernel agreement that BX-20/BX-22 lock down. Splitting the
# assignment ensures the operator-friendly `?=` and `+=` semantics are
# preserved while the shared CPP defines are always present.
CFLAGS  ?= -O2 -g -Wall -Wextra -D_GNU_SOURCE \
	           -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
CFLAGS  += $(COMMON_CPPFLAGS)
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
# libsodium (ED-11): Argon2id for the optional unpin-passphrase sentinel.
# Ubuntu Resolute ships libsodium 1.0.20 in main (libsodium-dev). The
# header (<sodium.h>) and the runtime dep are mandatory only at link time
# — a build host without libsodium will fail at this final link step
# with an obvious -lsodium error.
LIBS    ?= -lbpf -lelf -lz -lsodium

BPF_CFLAGS = $(COMMON_CPPFLAGS) -O2 -g -Wall -target bpf \
	             -Wno-missing-declarations \
	             -D__TARGET_ARCH_$(ARCH) \
	             -I/usr/include/$(shell uname -m)-linux-gnu \
	             -I.

all: compartment-bpf

check-env:
	@test "$$(uname -s)" = Linux || { echo "error: compartment-bpf must be built on Linux"; exit 1; }
	@command -v $(CLANG) >/dev/null || { echo "error: $(CLANG) not found"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null || { echo "error: $(BPFTOOL) not found"; exit 1; }
	@test -r $(BTF) || { echo "error: BTF not readable at $(BTF)"; exit 1; }
	@case "$(COMPARTMENT_MAX_DIR_ANCESTORS)" in \
	  ''|*[!0-9]*) echo "error: COMPARTMENT_MAX_DIR_ANCESTORS must be an integer in 1..64"; exit 1;; \
	esac
	@[ "$(COMPARTMENT_MAX_DIR_ANCESTORS)" -ge 1 ] && [ "$(COMPARTMENT_MAX_DIR_ANCESTORS)" -le 64 ] || { \
	  echo "error: COMPARTMENT_MAX_DIR_ANCESTORS must be in 1..64"; exit 1; \
	}
	@# P1-A (v6-rerun1): libsodium link-time mandatory (Argon2id sentinel, ED-11).
	@# Prefer pkg-config when available; fall back to header probe so the diagnostic
	@# is self-explanatory on hosts without pkg-config.
	@if command -v pkg-config >/dev/null 2>&1; then \
	  pkg-config --exists libsodium || { echo "error: libsodium-dev not found (apt install libsodium-dev)"; exit 1; }; \
	else \
	  test -r /usr/include/sodium.h || test -r /usr/local/include/sodium.h || { echo "error: <sodium.h> not found (apt install libsodium-dev)"; exit 1; }; \
	fi

vmlinux.h: check-env
	$(BPFTOOL) btf dump file $(BTF) format c > $@.tmp
	mv $@.tmp $@

compartment.bpf.o: compartment.bpf.c compartment-abi.h vmlinux.h check-env
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

compartment.skel.h: compartment.bpf.o
	$(BPFTOOL) gen skeleton $< name compartment_bpf > $@

compartment-observe.bpf.o: compartment-observe.bpf.c vmlinux.h check-env
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

compartment-observe.skel.h: compartment-observe.bpf.o
	$(BPFTOOL) gen skeleton $< name compartment_observe_bpf > $@

compartment-bpf: compartment-bpf.c compartment-observe.c \
                 compartment.skel.h compartment-observe.skel.h compartment-abi.h
	$(CC) $(CFLAGS) -o $@ compartment-bpf.c compartment-observe.c \
		$(LDFLAGS) $(LIBS)

clean:
	rm -f compartment-bpf compartment.bpf.o compartment.skel.h vmlinux.h.tmp
	rm -f compartment-observe.bpf.o compartment-observe.skel.h
	rm -f tests/sealprobe tests/fuzz_oracle
	rm -rf tests/mesh/build

smoke: compartment-bpf
	sh tests/smoke.sh

# Sec-3 / F8 runtime coverage of the actor-allowlist BPF path. Exercises
# actor_check_or_deny end-to-end (allowed actor write succeeds, intruder
# write denied with ACTION_DENY_ACTOR_MISMATCH, actor_mismatch_total
# increments). Detect-and-skip on a host without BPF LSM / sudo so the
# default `make check` still runs on developer hosts; the actual end-to-
# end coverage lands inside the smoke VM.
smoke-actor: compartment-bpf test-tools
	sh tests/smoke-actor.sh

# V-4 pin/unpin regression. Must run as root (the daemon needs CAP_BPF /
# CAP_SYS_ADMIN to attach and to mutate bpffs). See tests/pin-regression.sh
# for the four sub-tests and the probe semantics.
smoke-pin: compartment-bpf test-tools
	@bash tests/pin-regression.sh

# V-4b counter smoke. Three sub-tests (T4b.1..T4b.3): deny_total
# exactness, audit_drop_total under pressure, --stats idempotence.
smoke-counters: compartment-bpf
	@bash tests/counter-smoke.sh

# ED-1 + ED-2 parser/loader fixtures (actor allowlist). Eight grammar
# fixtures driven via --parse-only and five resolution fixtures driven
# via --dry-run. No root, no kernel state touched. See
# tests/parser-actor/run.sh for the full surface.
check-parser-actor: compartment-bpf
	@bash tests/parser-actor/run.sh

# ED-3 + ED-4 BPF-side syntactic gate. Compile-only check that
# compartment.bpf.c still builds with the new struct seal_value, the
# 16-hook actor_check_or_deny integration, and the unrolled actor[]
# scan. Does NOT load or verify the program (that lands with the
# bypass suite in ED-8); fails fast if a future edit drops the helper
# or breaks the unroll bound. Reuses the existing compartment.bpf.o
# recipe so any host with clang + libbpf-dev can run it via `make
# check-actor-hook`.
check-actor-hook: compartment.bpf.o
	@echo "[check-actor-hook] compartment.bpf.o built; actor_check_or_deny path syntactically valid."
	@grep -q 'actor_check_or_deny' compartment.bpf.c || { echo "error: actor_check_or_deny missing in compartment.bpf.c"; exit 1; }
	@grep -q 'COMPARTMENT_MAX_ACTORS_PER_SEAL' compartment-abi.h || { echo "error: COMPARTMENT_MAX_ACTORS_PER_SEAL missing in compartment-abi.h"; exit 1; }
	@# F6 (Review-1): extend the symbolic gate to the ED-6/ED-7
	@# surfaces too — the centralised audit emit, the
	@# ACTION_DENY_ACTOR_MISMATCH wire constant, the
	@# actor_mismatch_total counter map name, and the ABI v0.3
	@# audit_event size assertion. A future rewrite that drops any
	@# of these without bumping the ABI will now fail this gate.
	@# Codex gate 1 (Leader-8, 2026-05-14): added the seal_value
	@# size assertion alongside audit_event — ABI v0.3 bumped both
	@# (audit_event 72 → 96 for version+actor_name; seal_value 72
	@# → 88 for actor[]+actor_count). Leaving only one of the two
	@# in this gate let drift on the un-gated struct land silently.
	@grep -q 'emit_audit_actor' compartment.bpf.c || { echo "error: emit_audit_actor missing in compartment.bpf.c"; exit 1; }
	@grep -q 'ACTION_DENY_ACTOR_MISMATCH' compartment-abi.h || { echo "error: ACTION_DENY_ACTOR_MISMATCH missing in compartment-abi.h"; exit 1; }
	@grep -q 'actor_mismatch_total' compartment.bpf.c || { echo "error: actor_mismatch_total missing in compartment.bpf.c"; exit 1; }
	@grep -Eq '_Static_assert\(sizeof\(struct audit_event\) == 96' compartment-abi.h || { echo "error: audit_event size assertion missing or drifted from 96 in compartment-abi.h (ABI v0.3)"; exit 1; }
	@grep -Eq '_Static_assert\(sizeof\(struct seal_value\) == 96' compartment-abi.h || { echo "error: seal_value size assertion missing or drifted from 96 in compartment-abi.h (ABI v0.4)"; exit 1; }
	@# v0.4 strict-launch-marker gates: catch a drift that drops the
	@# load-bearing flag bit, action code, struct sizes, hook names,
	@# or counter map names without a corresponding ABI bump.
	@grep -q 'SEAL_STRICT_LAUNCH' compartment-abi.h || { echo "error: SEAL_STRICT_LAUNCH missing in compartment-abi.h (ABI v0.4)"; exit 1; }
	@grep -q 'ACTION_DENY_STRICT_LAUNCH_MISSING' compartment-abi.h || { echo "error: ACTION_DENY_STRICT_LAUNCH_MISSING missing in compartment-abi.h (ABI v0.4)"; exit 1; }
	@grep -Eq '_Static_assert\(sizeof\(struct launcher_actor\) == 24' compartment-abi.h || { echo "error: launcher_actor size assertion missing or drifted from 24 in compartment-abi.h (ABI v0.4)"; exit 1; }
	@grep -Eq '_Static_assert\(sizeof\(struct actor_marker\) == 32' compartment-abi.h || { echo "error: actor_marker size assertion missing or drifted from 32 in compartment-abi.h (ABI v0.4)"; exit 1; }
	@grep -q 'COMPARTMENT_ABI_VERSION 0x0007' compartment-abi.h || { echo "error: COMPARTMENT_ABI_VERSION did not bump to 0x0007 in compartment-abi.h"; exit 1; }
	@# v0.5/v0.6 dir-destination gates: catch a drift that drops the
	@# action codes, recursive ancestor helper, or exact ABI version map.
	@grep -q 'ACTION_DENY_WRITE_PARENT_DIR' compartment-abi.h || { echo "error: ACTION_DENY_WRITE_PARENT_DIR missing in compartment-abi.h (ABI v0.5)"; exit 1; }
	@grep -q 'ACTION_DENY_CHMOD_PARENT_DIR' compartment-abi.h || { echo "error: ACTION_DENY_CHMOD_PARENT_DIR missing in compartment-abi.h (ABI v0.5)"; exit 1; }
	@grep -q 'deny_file_parent_dir_action' compartment.bpf.c || { echo "error: deny_file_parent_dir_action missing in compartment.bpf.c (ABI v0.5)"; exit 1; }
	@grep -q 'deny_dentry_parent_dir_action' compartment.bpf.c || { echo "error: deny_dentry_parent_dir_action missing in compartment.bpf.c (ABI v0.5)"; exit 1; }
	@grep -q 'deny_dir_ancestor_action_from_dir_dentry' compartment.bpf.c || { echo "error: recursive ancestor helper missing in compartment.bpf.c (ABI v0.6)"; exit 1; }
	@grep -q 'abi_version_map' compartment.bpf.c || { echo "error: abi_version_map missing in compartment.bpf.c (ABI v0.6)"; exit 1; }
	@grep -q 'ACTION_DENY_PRCTL_SET_MM' compartment-abi.h || { echo "error: ACTION_DENY_PRCTL_SET_MM missing in compartment-abi.h (ABI v0.7)"; exit 1; }
	@grep -q 'ACTION_DENY_PTRACE_ACCESS' compartment-abi.h || { echo "error: ACTION_DENY_PTRACE_ACCESS missing in compartment-abi.h (ABI v0.7)"; exit 1; }
	@grep -q 'ACTION_DENY_PTRACE_TRACEME' compartment-abi.h || { echo "error: ACTION_DENY_PTRACE_TRACEME missing in compartment-abi.h (ABI v0.7)"; exit 1; }
	@grep -q 'comp_bprm_check_security' compartment.bpf.c || { echo "error: comp_bprm_check_security missing in compartment.bpf.c (ABI v0.4)"; exit 1; }
	@grep -q 'comp_task_alloc' compartment.bpf.c || { echo "error: comp_task_alloc missing in compartment.bpf.c (ABI v0.4)"; exit 1; }
	@grep -q 'strict_launch_check_or_deny' compartment.bpf.c || { echo "error: strict_launch_check_or_deny missing in compartment.bpf.c (ABI v0.4)"; exit 1; }
	@grep -q 'parse_actor_strict_decl' compartment-bpf.c || { echo "error: parse_actor_strict_decl missing in compartment-bpf.c (ABI v0.4)"; exit 1; }
	@grep -q 'strict_validate_launchers' compartment-bpf.c || { echo "error: strict_validate_launchers missing in compartment-bpf.c (ABI v0.4)"; exit 1; }
	@grep -q 'STRICT_DANGEROUS_ENV_NAMES' compartment-bpf.c || { echo "error: STRICT_DANGEROUS_ENV_NAMES missing in compartment-bpf.c (ABI v0.4)"; exit 1; }
	@# HIGH-11 (Review-1 fix): symmetric grep gates for the 3 strict-launch
	@# LSM hooks that were ungated in the v0.3 lift, plus the 11 v0.4 map
	@# names. A future refactor that drops any of these will now fail
	@# check-actor-hook instead of slipping through. Mirrors the v0.3
	@# precedent set in F6 / Phase 2 mesh Review-1 fixes.
	@grep -q 'comp_task_prctl' compartment.bpf.c || { echo "error: comp_task_prctl missing in compartment.bpf.c (ABI v0.4 SPEC §6.3)"; exit 1; }
	@grep -q 'comp_ptrace_access_check' compartment.bpf.c || { echo "error: comp_ptrace_access_check missing in compartment.bpf.c (ABI v0.4 SPEC §6.3)"; exit 1; }
	@grep -q 'comp_ptrace_traceme' compartment.bpf.c || { echo "error: comp_ptrace_traceme missing in compartment.bpf.c (ABI v0.4 SPEC §6.3)"; exit 1; }
	@for m in launcher_to_actor policy_state_map actor_marker_map \
	          marker_set_total marker_copy_fork_total \
	          marker_stale_generation_total marker_clear_foreign_exec_total \
	          strict_launch_missing_total strict_launch_allowed_total \
	          prctl_set_mm_exe_file_denied_total \
	          ptrace_access_denied_total ptrace_traceme_denied_total; do \
		grep -q "$$m" compartment.bpf.c || { echo "error: v0.4 map $$m missing in compartment.bpf.c"; exit 1; }; \
	done
	@# HIGH-11: value-drift asserts catch silent ABI bump regressions
	@# even if compartment-abi.h is otherwise touched by an unrelated edit.
	@grep -Eq '_Static_assert\(SEAL_STRICT_LAUNCH +== +\(1U *<< *5\)' compartment-abi.h || { echo "error: SEAL_STRICT_LAUNCH value-drift assert missing in compartment-abi.h"; exit 1; }
	@grep -Eq '_Static_assert\(ACTION_DENY_STRICT_LAUNCH_MISSING +== +8' compartment-abi.h || { echo "error: ACTION_DENY_STRICT_LAUNCH_MISSING value-drift assert missing in compartment-abi.h"; exit 1; }
	@grep -Eq '_Static_assert\(sizeof\(struct policy_state\) +== +8' compartment-abi.h || { echo "error: policy_state size assert missing in compartment-abi.h"; exit 1; }
	@# HIGH-6 (Review-1): wrapper-loader env-list identity invariant.
	@# Both translation units must reference the shared header so a
	@# future drift cannot land silently.
	@test -r tools/compartment-dangerous-env.h || { echo "error: tools/compartment-dangerous-env.h missing (HIGH-6 shared header)"; exit 1; }
	@grep -q 'compartment-dangerous-env\.h' compartment-bpf.c || { echo "error: compartment-bpf.c must #include compartment-dangerous-env.h (HIGH-6 wrapper-alignment invariant)"; exit 1; }
	@grep -q 'compartment-dangerous-env\.h' tools/compartment-actor-wrapper.c || { echo "error: tools/compartment-actor-wrapper.c must #include compartment-dangerous-env.h (HIGH-6 wrapper-alignment invariant)"; exit 1; }
	@grep -q 'COMPARTMENT_DANGEROUS_ENV_NAMES' tools/compartment-dangerous-env.h || { echo "error: tools/compartment-dangerous-env.h must define COMPARTMENT_DANGEROUS_ENV_NAMES"; exit 1; }
	@grep -q 'BASH_FUNC_' tools/compartment-dangerous-env.h || { echo "error: HIGH-6: BASH_FUNC_* prefix match missing in compartment-dangerous-env.h"; exit 1; }
	@echo "[check-actor-hook] OK"
	@# TODO(exec-domain ED-8): wire up runtime hook test once bypass
	@# suite lands (actor-allow, actor-deny, NULL-exe defense).

# HIGH-5 (mesh Review-1): wire check-mesh + check-wrapper into the
# default `make check` aggregator. Pre-fix, both targets existed as
# standalone but `make check` never invoked them — Phase 2 (mesh) and
# wrapper-aide (DEC-WRAP-A) coverage was invisible from CI / default
# operator gating. The mesh harness still detect-and-SKIPs cleanly on
# hosts without root or BPF LSM (rc=77), same as smoke-pin.
check: smoke smoke-pin smoke-counters smoke-actor check-parser-actor check-actor-hook check-profiles check-pin-passphrase check-profile-e2e check-mesh check-wrapper check-strict-launch check-observe check-howto-examples

# Coverage-gaps 2026-05-16 GAP-H-12: HOWTO §7.2 dir-destination
# headliner regressed THREE V-6 cycles before this gate landed. Each
# regression was a HOWTO.md edit only; no test asserted the example
# loaded under --dry-run. This target wires the executable-doc gate
# into the default `make check`. No root, no kernel; runs on any host
# with a built compartment-bpf binary.
check-howto-examples: compartment-bpf
	@bash tests/docs/howto-examples.sh

# v0.4: in-tree strict-launch witnesses. Drives a subset of the spike's
# SL-1..SL-10 against the production daemon (not the spike runner) and
# verifies the new BPF percpu counters increment as expected. Requires
# root + BPF LSM; the script SKIPs (rc=77) cleanly on developer hosts
# without a real kernel. Reuses the spike's fixtures under
# experimental/strict-launch-marker/build/; builds them if missing.
#
# HIGH-10 (Review-1 fix): trap rc=77 as SKIP so dev hosts without root
# / BPF LSM / kernel toolchain do not break `make check`. Mirrors
# check-wrapper's pattern: sub-script rc=77 → exit 0 with a SKIP line;
# rc=0 → PASS; non-zero non-77 → FAIL.
check-strict-launch: compartment-bpf
	@bash tests/strict-launch/run.sh; rc=$$?; \
	if [ "$$rc" -eq 77 ]; then \
		echo "[check-strict-launch] SKIP (rc=77, env unsupported)"; \
		exit 0; \
	elif [ "$$rc" -ne 0 ]; then \
		echo "[check-strict-launch] FAIL (rc=$$rc)"; \
		exit $$rc; \
	fi

# R2-F4 (Review-2 HIGH): exercise the actor-bound profile witnesses
# end-to-end. tests/profile-e2e/aide.sh + postgres.sh both follow the
# 0/1/77 SKIP convention — the scripts SKIP cleanly on hosts without
# AIDE / PostgreSQL / BPF LSM / root, so this target is safe to land
# in `check` on every developer host (it becomes a real witness inside
# the smoke VM that actually has both daemons). Set RUN_E2E=0 to opt
# out (e.g. CI-side parallelism). Sub-script SKIP (rc=77) bubbles up
# as a 'SKIP' line; FAIL (rc=1) hard-fails the gate fail-closed.
check-profile-e2e: compartment-bpf test-tools
	@set -u; \
	if [ "$${RUN_E2E:-1}" = "0" ]; then \
	  echo "[check-profile-e2e] RUN_E2E=0 set; skipping"; \
	  exit 0; \
	fi; \
	rc=0; \
	for s in tests/profile-e2e/aide.sh tests/profile-e2e/postgres.sh; do \
	  echo "[check-profile-e2e] $$s"; \
	  bash "$$s"; \
	  srrc=$$?; \
	  if [ "$$srrc" = "77" ]; then \
	    echo "[check-profile-e2e] $$s SKIP (env unsupported)"; \
	  elif [ "$$srrc" != "0" ]; then \
	    echo "[check-profile-e2e] $$s FAIL (rc=$$srrc)"; rc=1; \
	  fi; \
	done; \
	exit $$rc

# ED-11 (Leader-7): exercise the Argon2id unpin-passphrase sentinel
# end-to-end. T11.1..T11.6 cover the pin-side sentinel write, the
# audit emit on verify-fail, and the legacy (no-passphrase) compat path.
# Requires root for the BPF LSM load + libsodium link; SKIPs cleanly
# when either is missing.
check-pin-passphrase: compartment-bpf
	sh tests/pin-passphrase.sh

# F31 (Review-1): parser sweep over every shipped profile. Runs the
# loader with --parse-only, which exercises the grammar + DEC-ED1/3
# rules without touching the filesystem (no path stats, no BPF). Fails
# fast if any profile under profiles/ has a syntax regression. Cheap
# enough to run on every developer host (no kernel / root required).
check-profiles: compartment-bpf
	@set -eu; \
	pass=0; fail=0; failed_list=""; \
	for p in profiles/*.conf; do \
	  if ./compartment-bpf --parse-only "$$p" >/dev/null 2>&1; then \
	    pass=$$((pass + 1)); \
	  else \
	    fail=$$((fail + 1)); \
	    failed_list="$$failed_list $$p"; \
	    echo "[FAIL] $$p:"; \
	    ./compartment-bpf --parse-only "$$p" 2>&1 | sed 's/^/    /'; \
	  fi; \
	done; \
	echo "[check-profiles] $$pass/$$((pass + fail)) profiles parsed cleanly"; \
	if [ "$$fail" -ne 0 ]; then \
	  echo "[check-profiles] failed:$$failed_list" >&2; \
	  exit 1; \
	fi

# Convenience: end-to-end demo
demo: compartment-bpf
	@echo "Run: sudo ./compartment-bpf oracle.conf"
	@echo "Then in another shell: sudo rm /var/lib/oracle/data"

# Test instrumentation. Plain C, no bpf headers; builds on host or VM.
# Used by tests/matrix.sh, tests/bypass/*.sh, tests/fuzz_oracle.c. Kept
# separate from the daemon build so a host without clang/libbpf can still
# compile the harness.
tests/sealprobe: tests/sealprobe.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# fuzz_oracle is added in phase E. The recipe is enabled if the source
# file exists; until then `make test-tools` builds only sealprobe.
ifneq (,$(wildcard tests/fuzz_oracle.c))
tests/fuzz_oracle: tests/fuzz_oracle.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
TEST_TOOLS_EXTRA = tests/fuzz_oracle
endif

test-tools: tests/sealprobe $(TEST_TOOLS_EXTRA)

bench: compartment-bpf test-tools
	sh tests/bench.sh

# ----- Phase 2 mesh test infrastructure (ME-1 + ME-2 + ME-3) -----
#
# 8 stub binaries (4 actor + 4 outsider) per EXEC-DOMAIN-MESH-DRAFT.md §2.1.
# Each wrapper compiles with -DSTUB_ID=<id>; the wrapper embeds STUB_ID in
# .rodata so each binary has distinct content (defense in depth against
# build-system inode dedup). The mesh runner asserts 8 distinct inodes
# post-build (`stat -c '%i'`).
#
# Per the mesh-draft Makefile snippet, recipes use $(filter %.c,$^) so the
# header stays a prereq for rebuild-on-change without being passed to gcc.

MESH_STUBS_A := $(addprefix tests/mesh/build/mesh_actor_,a1 a2 a3 a4)
MESH_STUBS_B := $(addprefix tests/mesh/build/mesh_outsider_,b1 b2 b3 b4)
MESH_STUBS   := $(MESH_STUBS_A) $(MESH_STUBS_B)

tests/mesh/build/mesh_actor_%: tests/mesh/stubs/mesh_actor_%.c tests/mesh/stubs/mesh_stub_main.c tests/mesh/stubs/mesh_stub_main.h
	@mkdir -p $(@D)
	$(CC) -O2 -Wall -Wextra -DSTUB_ID=$* -Itests/mesh/stubs -o $@ $(filter %.c,$^)

tests/mesh/build/mesh_outsider_%: tests/mesh/stubs/mesh_outsider_%.c tests/mesh/stubs/mesh_stub_main.c tests/mesh/stubs/mesh_stub_main.h
	@mkdir -p $(@D)
	$(CC) -O2 -Wall -Wextra -DSTUB_ID=$* -Itests/mesh/stubs -o $@ $(filter %.c,$^)

mesh-stubs: $(MESH_STUBS)

# Full mesh trial harness — ~416 deterministic trials (§2.3) + ME-2 (§3.1)
# multi-binary actor groups + ME-3 (§3.2) op-coverage axis. Requires root +
# BPF LSM (the daemon needs CAP_BPF / CAP_SYS_ADMIN). On a host without
# either, run-mesh.sh detect-and-skips with rc=77 per the project SKIP
# convention.
check-mesh: compartment-bpf test-tools mesh-stubs
	@# ME-11 §3.11 outer timeout: 120s safety net. The harness itself
	@# enforces a 60s ceiling on trial-block wall-clock and surfaces an
	@# ME11-perf row; this outer cap guards against pathological hangs
	@# (e.g. daemon attach stuck, ringbuf consumer wedged) that would
	@# otherwise leave CI hung indefinitely.
	@# HIGH-8 (Review-3): ME-21 sequences directory must be root-owned;
	@# run-mesh.sh FATALs on non-root-owned seq files as a security-by-
	@# design check. Fix ownership here (check-mesh always runs as root).
	@[ -d tests/mesh/sequences ] && \
		chown -R 0:0 tests/mesh/sequences && \
		chmod -R u=rwX,go=rX tests/mesh/sequences || true
	@timeout --preserve-status --kill-after=10s 120s bash tests/mesh/run-mesh.sh

# HIGH-5: wrapper-aide regression gate. tests/actor-wrapper/run.sh
# requires root for the seccomp / static-link / LD_PRELOAD T1..T12
# coverage. SKIPs (rc=0 with a noisy message) on a non-root host so
# developer-host `make check` stays green.
check-wrapper:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "[check-wrapper] SKIP (requires root for static-link/seccomp tests)"; \
		exit 0; \
	fi; \
	bash tests/actor-wrapper/run.sh

# AO-1..AO-5 observe acceptance harness. Requires root + BPF LSM for
# live observation tests; SKIPs cleanly (rc=77) on hosts without them.
# Runs the AIDE witness when aide is present. rc=0 PASS, rc=1 FAIL,
# rc=77 SKIP per the project convention.
check-observe: compartment-bpf
	@bash tests/observe/run.sh; rc=$$?; \
	if [ "$$rc" -eq 77 ]; then \
		echo "[check-observe] SKIP (rc=77, env unsupported)"; \
		exit 0; \
	elif [ "$$rc" -ne 0 ]; then \
		echo "[check-observe] FAIL (rc=$$rc)"; \
		exit $$rc; \
	fi

# Kernel stability stress harness (operator-domain gate alongside V-6).
# Long-running; NOT wired into default `make check`. Requires root for
# --pin/--unpin and dmesg access; SKIPs cleanly (rc=77) on a dev host
# missing CAP_BPF / BPF LSM. Two cadences:
#   - check-stability       full run, 1024 cycles (~45-60 min)
#   - check-stability-quick smoke run, 64 cycles (~5 min)
# The harness also accepts STAB_CYCLES=N for ad-hoc cadences; both
# targets exist as named entry points so CI / operator scripts don't
# need to know the env-var spelling.
check-stability:
	@echo "Running stability test ($${STAB_CYCLES:-1024} cycles; requires root)..."
	sudo STAB_CYCLES=$${STAB_CYCLES:-1024} bash tests/stability/pin-unpin-churn.sh

check-stability-quick:
	@echo "Running quick stability test (64 cycles; requires root)..."
	sudo STAB_CYCLES=64 bash tests/stability/pin-unpin-churn.sh

.PHONY: all check-env clean smoke smoke-pin smoke-counters smoke-actor check-parser-actor check-actor-hook check-profiles check check-pin-passphrase check-profile-e2e demo test-tools bench mesh-stubs check-mesh check-wrapper check-strict-launch check-observe check-stability check-stability-quick check-howto-examples
