// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// compartment-bpf userspace loader.
// Reads a profile (.conf) with `seal <path> <flags>` directives,
// populates the sealed_inodes / sealed_dirs maps, attaches the BPF LSM
// program, optionally pins to bpffs, then tails the audit ringbuf.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <dirent.h>
#include <ftw.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/file.h>  /* flock(2) on pin lifecycle */
#include <sys/time.h>  /* clock_gettime() for unpin-auth ts_ns */
#include <time.h>      /* clock_gettime() POSIX declaration */
#include <syslog.h>    /* openlog/syslog for unpin-auth audit */
#include <termios.h>   /* interactive passphrase prompt (no echo) */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>   /* vmlinux BTF probe: inode_setattr hook arg-count */
#include <sodium.h>    /* Argon2id passphrase hashing */

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#include "compartment.skel.h"
#include "compartment-abi.h"
/* Shared dangerous-env-name list between
 * the loader and the static actor wrapper. Single source of truth so a
 * future drift cannot land silently. */
#include "tools/compartment-dangerous-env.h"

#define PIN_ROOT "/sys/fs/bpf/compartment"

// The unpin-auth Argon2id sentinel cannot live under PIN_ROOT
// because bpffs (the filesystem PIN_ROOT lives on) does not permit
// regular-file creation — only BPF object pins. We use a parallel
// tmpfs directory under /run with the same boot-bound lifecycle (both
// bpffs pins and /run tmpfs are recreated empty on every reboot).
#define SENTINEL_DIR  "/run/compartment-bpf"
#define SENTINEL_PATH SENTINEL_DIR "/unpin-sentinel"

static volatile sig_atomic_t running = 1;
static void on_sigint(int s) { (void)s; running = 0; }

// Helper used in the --pin attach→pin window to abort
// early on a trappable signal (SIGINT / SIGTERM). The handler above
// flips `running` to 0; this wrapper centralises the diagnostic so
// every rollback site emits the same operator-facing line. SIGKILL is
// fundamentally untrappable. With the pin lifecycle lock
// and the BPF link lifetime model, a SIGKILL'd loader still
// has its kernel link refs dropped synchronously by do_exit(), so
// enforcement evaporates rather than persisting in a stuck state;
// the lock auto-releases on the same path.
static int pin_window_aborted(const char *site)
{
	if (running)
		return 0;
	fprintf(stderr,
		"%s: SIGTERM/SIGINT received during --pin window; "
		"rolling back partial pin state and exiting.\n",
		site);
	return 1;
}

// Held O_PATH fds, opened during map-populate and kept for the DAEMON'S
// WHOLE LIFETIME. Each successful seal_path() pushes its fd here; these
// fds are NOT released after attach — they are held until the daemon
// exits. Holding the inode reference for the entire run prevents inum
// reuse for as long as the seal is enforced: an attacker who unlinks the
// path and creates a new file at the same name cannot alias onto our
// (dev, ino) map key, because the kernel cannot reuse the inum while our
// fd pins the inode struct.
//
// DO NOT add a held_fds_release() after compartment_bpf__attach() (or at
// any point during the load window). An earlier version released these
// fds once attach returned; that reopened the inode-reuse window — after
// release, the kernel is free to recycle the inum behind a sealed
// (dev, ino) key while enforcement is still live. The fds are
// intentionally leaked for the process lifetime and reclaimed by the
// kernel only on daemon exit.
struct held_fds {
	int *buf;
	size_t cap;
	size_t n;
};

static int held_fds_push(struct held_fds *h, int fd)
{
	if (h->n == h->cap) {
		size_t nc = h->cap ? h->cap * 2 : 16;
		int *nb = realloc(h->buf, nc * sizeof(int));
		if (!nb) {
			fprintf(stderr, "held_fds: realloc to %zu: %s\n",
				nc, strerror(errno));
			return -1;
		}
		h->buf = nb;
		h->cap = nc;
	}
	h->buf[h->n++] = fd;
	return 0;
}

static void held_fds_release(struct held_fds *h)
{
	for (size_t i = 0; i < h->n; i++)
		close(h->buf[i]);
	free(h->buf);
	h->buf = NULL;
	h->n = h->cap = 0;
}

/*
 * Exec-domain (actor allowlist) profile state — parse + resolution per
 * experimental/EXEC-DOMAIN-SPEC.md §3, §9. The loader plumbs (dev, ino)
 * pairs into the BPF maps via struct seal_value; the BPF side enforces
 * them at hook time.
 *
 * Caps:
 *   actor NAME length ≤ 32 bytes incl. NUL.
 *   ≤ 4 paths per actor group; unified with the ABI cap
 *   COMPARTMENT_MAX_ACTORS_PER_SEAL (replaces an earlier 8-path cap so
 *   the limit is surfaced at parse time, not at load time).
 */
// Unify ACTOR_NAME_MAX with the ABI's
// audit_event.actor_name[16] / seal_value.actor_name[16] slot. The
// loader previously accepted names up to 31 chars at parse time but
// the audit emit then truncated to 15 chars (sizeof(actor_name)-1)
// silently; SIEM saw a different name than the operator typed.
// Reject the over-long name at parse time so the user sees the
// limit up front. The constant intentionally matches
// sizeof(((struct audit_event*)0)->actor_name) so a future ABI
// widening drives both sides together via _Static_assert below.
#define ACTOR_NAME_MAX  16
_Static_assert(ACTOR_NAME_MAX == sizeof(((struct audit_event*)0)->actor_name),
	"ACTOR_NAME_MAX must match ABI audit_event.actor_name[] size");
_Static_assert(ACTOR_NAME_MAX == sizeof(((struct seal_value*)0)->actor_name),
	"ACTOR_NAME_MAX must match ABI seal_value.actor_name[] size");
// Parser path cap unified with the BPF seal_value
// actor[] inline array cap (COMPARTMENT_MAX_ACTORS_PER_SEAL == 4).
// An earlier design allowed 8 paths per group at parse time;
// this lowers it to 4 so the parse-time error message
// surfaces the limit to profile authors instead of a load-time
// failure. The two caps are now a single source of truth (compile-
// asserted below to fail loud if either drifts).
#define ACTOR_MAX_PATHS COMPARTMENT_MAX_ACTORS_PER_SEAL
_Static_assert(ACTOR_MAX_PATHS == 4,
	"parser actor cap must match ABI seal_value actor[] capacity");

// actor_binary was a userspace-local duplicate of the
// ABI's struct actor_id (both: __u64 dev; __u64 ino;). Collapsing onto
// the single shared type removes the duplicate and keeps the loader's
// resolved-state shape identical to the on-wire shape carried into
// seal_value.actor[]. The fields are byte-identical; the only call
// site (actor_group.bin) treats it as POD with explicit field access,
// so no caller depends on the separate type.

struct actor_group {
	char *name;
	size_t n_paths;
	char **paths;            /* declared, before resolution */
	struct actor_id *bin;    /* resolved (dev, ino); n_paths long.
	                          * Was struct actor_binary; collapsed onto
	                          * the ABI's actor_id since they were
	                          * byte-identical. May be NULL in
	                          * parse-only mode. */
	int sealed_in_profile;   /* informational; set by seal_path() when a sealed path matches one of `bin`. */

	/* v0.4: strict-launch-marker metadata. Populated only by
	 * `actor-strict NAME = TARGET launcher=PATH`; zero-init for plain
	 * `actor NAME = PATH ...` declarations. When `is_strict` is set,
	 * the loader's post-parse pass:
	 *  (a) validates the launcher binary (regular file, statically
	 *      linked: no PT_INTERP, ELF only);
	 *  (b) requires the launcher path to be sealed `full` in the same
	 *      profile (cross-checked against ps->seals);
	 *  (c) requires the target path to be sealed `full` too;
	 *  (d) assigns a stable `strict_slot` (1-based monotonic) used by
	 *      the BPF strict-launch check;
	 *  (e) populates the `launcher_to_actor` BPF map with
	 *      { target=bin[0], actor_slot=strict_slot, generation }.
	 *
	 * `n_paths` is always 1 for actor-strict (a single TARGET), so
	 * bin[0] is the actor target. Env policy is sourced from the
	 * wrapper (`tools/compartment-actor-wrapper.c` +
	 * `compartment-actor-build.sh`); v0.4 does not carry env directives
	 * on the actor_group. See HOWTO.md §6.4 for the wrapper-as-single-source-
	 * of-env-policy invariant.
	 */
	int is_strict;
	char *launcher_path;
	__u64 launcher_dev;
	__u64 launcher_ino;
	__u32 strict_slot;
};

/*
 * In-memory shadow of every seal directive successfully applied
 * to a (dev, ino). Used by enforce_actor_binaries_sealed() after parse
 * + actor-resolution to verify every actor binary is also sealed with
 * the SEAL_FULL flag set. Tracks UNION-of-flags when the same path is
 * sealed twice in one profile (matches seal_path's prev-flags merge so
 * the strict-mode check sees the same flags the kernel will enforce).
 *
 * Populated in both --dry-run and real-load (skel != NULL); skipped in
 * --parse-only since actor paths are not resolved there.
 */
struct seal_entry {
	__u64 dev;
	__u64 ino;
	__u32 flags;
	int has_actor;   /* track for in-memory merge-refusal */
	char *path;      /* declared path string for strict-mode
	                  * path-equivalence check (hardlink at a different
	                  * declared path must not satisfy E-6). strdup'd
	                  * from the profile line; freed in
	                  * profile_state_release. May be NULL if recording
	                  * was best-effort under OOM, in which case
	                  * strict-mode falls back fail-closed. */
};

struct profile_state {
	struct actor_group **actors;
	size_t n_actors;
	size_t cap_actors;
	struct seal_entry *seals;
	size_t n_seals;
	size_t cap_seals;
	/* v0.4: the actor-strict pending context. While parsing the
	 * lines that follow an `actor-strict NAME = ...` directive, `env
	 * NAME=VALUE` / `env NAME=*` lines bind to this open declaration.
	 * Reset to NULL by any non-env top-level directive. */
	struct actor_group *strict_open;
	/* v0.4: monotonic 1-based slot id assigned to each actor-strict
	 * group as they are declared. Slot 0 means "not strict-launch".
	 * Used as the value in seal_value.strict_actor_slot and
	 * launcher_actor.actor_slot, and matches actor_marker.actor_slot
	 * at runtime. */
	__u32 next_strict_slot;
	/* v0.4: the policy_generation written into policy_state_map.
	 * Currently fixed to 1 at load time; future reload paths bump it
	 * to invalidate stale markers (SPEC §3 prop 5).  */
	__u32 generation;
};

/* v0.4: SPEC §4 wrapper-alignment invariant — the dangerous env name
 * list is sourced from `tools/compartment-dangerous-env.h`.
 * After the loader's `env` directive parser was removed,
 * this symbol is retained solely as the
 * wrapper-alignment witness: both the loader translation unit and the
 * wrapper translation unit must reference the same shared header so a
 * future drift cannot land silently. The grep gate in
 * `make check-actor-hook` asserts the symbol exists in compartment-bpf.c.
 *
 * STRICT_DANGEROUS_ENV_NAMES is a #define alias for the shared symbol
 * to preserve the historical name (and the existing check-actor-hook
 * grep). __attribute__((used)) keeps the array alive under -Wunused-
 * variable even though the v0.4 parser no longer dispatches on it. */
#define STRICT_DANGEROUS_ENV_NAMES COMPARTMENT_DANGEROUS_ENV_NAMES
static const char *const *const _strict_dangerous_env_alias
	__attribute__((used)) = STRICT_DANGEROUS_ENV_NAMES;

static int actor_name_valid(const char *name)
{
	size_t n;

	if (!name || !*name)
		return 0;
	n = strlen(name);
	if (n + 1 > ACTOR_NAME_MAX)
		return 0;
	/* [a-zA-Z_][a-zA-Z0-9_-]* per SPEC §3. */
	if (!(isalpha((unsigned char)name[0]) || name[0] == '_'))
		return 0;
	for (size_t i = 1; i < n; i++) {
		unsigned char c = (unsigned char)name[i];
		if (!(isalnum(c) || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

static struct actor_group *profile_find_actor(const struct profile_state *ps,
					      const char *name)
{
	for (size_t i = 0; i < ps->n_actors; i++) {
		if (strcmp(ps->actors[i]->name, name) == 0)
			return ps->actors[i];
	}
	return NULL;
}

static void actor_group_free(struct actor_group *ag)
{
	if (!ag)
		return;
	free(ag->name);
	for (size_t i = 0; i < ag->n_paths; i++)
		free(ag->paths[i]);
	free(ag->paths);
	free(ag->bin);
	free(ag->launcher_path);
	free(ag);
}

static void profile_state_release(struct profile_state *ps)
{
	for (size_t i = 0; i < ps->n_actors; i++)
		actor_group_free(ps->actors[i]);
	free(ps->actors);
	ps->actors = NULL;
	ps->n_actors = ps->cap_actors = 0;
	// Release per-entry declared-path strings before freeing
	// the backing array.
	for (size_t i = 0; i < ps->n_seals; i++)
		free(ps->seals[i].path);
	free(ps->seals);
	ps->seals = NULL;
	ps->n_seals = ps->cap_seals = 0;
}

static int path_list_contains_exact(const char *list, const char *path)
{
	if (!list || !path)
		return 0;
	size_t path_len = strlen(path);
	const char *cur = list;
	while (*cur) {
		const char *nl = strchr(cur, '\n');
		size_t span = nl ? (size_t)(nl - cur) : strlen(cur);
		if (span == path_len && memcmp(cur, path, path_len) == 0)
			return 1;
		if (!nl)
			break;
		cur = nl + 1;
	}
	return 0;
}

/*
 * Append (or OR-merge) a successful seal entry into ps->seals.
 * Matches seal_path's merge discipline: if (dev, ino) is already
 * tracked, OR the flag bits into the existing record. The caller is
 * responsible for refusing actor-merge collisions before
 * invoking this — `has_actor` is recorded so subsequent checks can
 * see the binding without re-walking the actor table. Returns 0 on
 * success, -1 on OOM.
 */
static int profile_state_record_seal(struct profile_state *ps,
				     __u64 dev, __u64 ino, __u32 flags,
				     int has_actor, const char *path)
{
	for (size_t i = 0; i < ps->n_seals; i++) {
		if (ps->seals[i].dev == dev && ps->seals[i].ino == ino) {
			ps->seals[i].flags |= flags;
			if (has_actor)
				ps->seals[i].has_actor = 1;
			// A hardlink seal at a different declared
			// path arrives as a second record_seal call with the
			// same (dev, ino) but a different path string. Keep
			// BOTH paths discoverable: store as 'p1\0p2\0...' so
			// strict-mode can find a match against any declared
			// path under this inode. The merged path string is
			// rebuilt as "$old\n$new" — newline-separated so a
			// future split is unambiguous (path strings cannot
			// contain newlines after the line-overlong reject).
			if (path && ps->seals[i].path &&
			    !path_list_contains_exact(ps->seals[i].path, path)) {
				size_t old_len = strlen(ps->seals[i].path);
				size_t add_len = strlen(path);
				char *grown = realloc(ps->seals[i].path,
						      old_len + 1 + add_len + 1);
				if (grown) {
					grown[old_len] = '\n';
					memcpy(grown + old_len + 1, path,
					       add_len + 1);
					ps->seals[i].path = grown;
				} else {
					/* Emit an
					 * operator-visible warn on this OOM
					 * path. Behaviour is still fail-closed
					 * (strict-mode will not match the new
					 * declared path), but a silent failure
					 * here makes "why isn't my new seal
					 * path enforced?" un-diagnosable. */
					fprintf(stderr,
						"warn: path-merge realloc failed for %s under OOM; new path will not match strict-mode (fail-closed)\n",
						path);
				}
			}
			return 0;
		}
	}
	if (ps->n_seals == ps->cap_seals) {
		size_t nc = ps->cap_seals ? ps->cap_seals * 2 : 8;
		struct seal_entry *nb = realloc(ps->seals,
						nc * sizeof(*nb));
		if (!nb)
			return -1;
		ps->seals = nb;
		ps->cap_seals = nc;
	}
	ps->seals[ps->n_seals].dev = dev;
	ps->seals[ps->n_seals].ino = ino;
	ps->seals[ps->n_seals].flags = flags;
	ps->seals[ps->n_seals].has_actor = has_actor ? 1 : 0;
	ps->seals[ps->n_seals].path = path ? strdup(path) : NULL;
	ps->n_seals++;
	return 0;
}

// Returns true iff `declared` is one of the newline-separated
// declared paths recorded against this seal entry. The contract is path-
// string equivalence, not realpath canonicalisation: the threat model is
// "seal at a different declared path satisfies a different declared path",
// not symlink/realpath aliasing (E-5 already rejects symlink leaves).
static int seal_entry_matches_declared(const struct seal_entry *se,
				       const char *declared)
{
	return path_list_contains_exact(se->path, declared);
}

static int profile_state_add_actor(struct profile_state *ps,
				   struct actor_group *ag)
{
	if (ps->n_actors == ps->cap_actors) {
		size_t nc = ps->cap_actors ? ps->cap_actors * 2 : 4;
		struct actor_group **nb = realloc(ps->actors,
						  nc * sizeof(*nb));
		if (!nb)
			return -1;
		ps->actors = nb;
		ps->cap_actors = nc;
	}
	ps->actors[ps->n_actors++] = ag;
	return 0;
}

/*
 * Parse a single `actor NAME = PATH [PATH ...]` declaration line.
 * `rest` is the line content AFTER the leading "actor" keyword has
 * been consumed (i.e. starting at the NAME). The line is already
 * comment-stripped and trimmed by the caller.
 *
 * Rejected (each emits a clear 1-line stderr message):
 *   - missing NAME / bad NAME charset / NAME too long.
 *   - missing `=` after NAME.
 *   - empty RHS (no paths after `=`).
 *   - non-absolute path (must begin with `/`).
 *   - paths > ACTOR_MAX_PATHS.
 *   - duplicate actor name in the same profile.
 *
 * On success, appends a new struct actor_group to `ps` and returns 0.
 * Path resolution (O_PATH+fstat) is NOT performed here; that happens
 * later for each actor group.
 */
static int parse_actor_decl(char *rest, int line_no, struct profile_state *ps)
{
	char *save = NULL;
	char *name_tok;
	char *eq_tok;
	char *path_tok;
	struct actor_group *ag;
	size_t cap = 0;

	name_tok = strtok_r(rest, " \t\r\n", &save);
	if (!name_tok) {
		fprintf(stderr,
			"%d: actor declaration missing NAME\n", line_no);
		return -1;
	}
	if (!actor_name_valid(name_tok)) {
		fprintf(stderr,
			"%d: malformed actor name '%s' (max %d chars, [a-zA-Z_][a-zA-Z0-9_-]*)\n",
			line_no, name_tok, ACTOR_NAME_MAX - 1);
		return -1;
	}
	if (profile_find_actor(ps, name_tok)) {
		fprintf(stderr,
			"%d: duplicate actor declaration '%s'\n",
			line_no, name_tok);
		return -1;
	}
	eq_tok = strtok_r(NULL, " \t\r\n", &save);
	if (!eq_tok || strcmp(eq_tok, "=") != 0) {
		fprintf(stderr,
			"%d: actor declaration missing '=' after NAME '%s'\n",
			line_no, name_tok);
		return -1;
	}

	ag = calloc(1, sizeof(*ag));
	if (!ag)
		goto enomem;
	ag->name = strdup(name_tok);
	if (!ag->name)
		goto enomem;

	while ((path_tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
		if (path_tok[0] != '/') {
			fprintf(stderr,
				"%d: actor %s: path '%s' must be absolute\n",
				line_no, name_tok, path_tok);
			goto fail;
		}
		if (ag->n_paths >= ACTOR_MAX_PATHS) {
			fprintf(stderr,
				"%d: actor %s: too many paths (cap=%d)\n",
				line_no, name_tok, ACTOR_MAX_PATHS);
			goto fail;
		}
		if (ag->n_paths == cap) {
			size_t nc = cap ? cap * 2 : 2;
			char **nb = realloc(ag->paths, nc * sizeof(char *));
			if (!nb)
				goto enomem;
			ag->paths = nb;
			cap = nc;
		}
		ag->paths[ag->n_paths] = strdup(path_tok);
		if (!ag->paths[ag->n_paths])
			goto enomem;
		ag->n_paths++;
	}

	if (ag->n_paths == 0) {
		fprintf(stderr,
			"%d: actor %s: empty RHS (no paths after '=')\n",
			line_no, name_tok);
		goto fail;
	}

	if (profile_state_add_actor(ps, ag) < 0)
		goto enomem;
	return 0;

enomem:
	fprintf(stderr, "%d: oom parsing actor declaration\n", line_no);
fail:
	actor_group_free(ag);
	return -1;
}

/*
 * v0.4: Parse a single `actor-strict NAME = TARGET launcher=PATH`
 * declaration line. `rest` is the line content AFTER the leading
 * "actor-strict" keyword has been consumed. Comment-stripped, trimmed.
 *
 * Differences from `parse_actor_decl`:
 *  - exactly ONE target path (not a path list);
 *  - mandatory `launcher=PATH` clause after the target;
 *  - the resulting actor_group is marked `is_strict = 1` and gets a
 *    stable `strict_slot` (monotonic 1-based, assigned by ps);
 *  - the declaration opens a "nested" context so subsequent `env`
 *    lines bind to it; ps->strict_open holds the pointer until any
 *    non-env top-level directive resets it.
 *
 * SPEC §4: `actor-strict NAME = TARGET launcher=PATH`.
 */
static int parse_actor_strict_decl(char *rest, int line_no,
				   struct profile_state *ps)
{
	char *save = NULL;
	char *name_tok, *eq_tok, *tgt_tok, *l_tok;
	const char *launcher;
	struct actor_group *ag;

	name_tok = strtok_r(rest, " \t\r\n", &save);
	if (!name_tok) {
		fprintf(stderr, "%d: actor-strict missing NAME\n", line_no);
		return -1;
	}
	if (!actor_name_valid(name_tok)) {
		fprintf(stderr,
			"%d: malformed actor-strict name '%s' (max %d chars, [a-zA-Z_][a-zA-Z0-9_-]*)\n",
			line_no, name_tok, ACTOR_NAME_MAX - 1);
		return -1;
	}
	if (profile_find_actor(ps, name_tok)) {
		fprintf(stderr,
			"%d: duplicate actor declaration '%s' (actor / actor-strict share the name space)\n",
			line_no, name_tok);
		return -1;
	}
	eq_tok = strtok_r(NULL, " \t\r\n", &save);
	if (!eq_tok || strcmp(eq_tok, "=") != 0) {
		fprintf(stderr,
			"%d: actor-strict %s: missing '=' after NAME\n",
			line_no, name_tok);
		return -1;
	}
	tgt_tok = strtok_r(NULL, " \t\r\n", &save);
	if (!tgt_tok) {
		fprintf(stderr,
			"%d: actor-strict %s: missing TARGET path\n",
			line_no, name_tok);
		return -1;
	}
	if (tgt_tok[0] != '/') {
		fprintf(stderr,
			"%d: actor-strict %s: TARGET '%s' must be absolute\n",
			line_no, name_tok, tgt_tok);
		return -1;
	}
	l_tok = strtok_r(NULL, " \t\r\n", &save);
	if (!l_tok || strncmp(l_tok, "launcher=", 9) != 0) {
		fprintf(stderr,
			"%d: actor-strict %s: missing 'launcher=PATH' clause\n",
			line_no, name_tok);
		return -1;
	}
	launcher = l_tok + 9;
	if (!*launcher || launcher[0] != '/') {
		fprintf(stderr,
			"%d: actor-strict %s: launcher path must be absolute and non-empty\n",
			line_no, name_tok);
		return -1;
	}
	if (strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr,
			"%d: actor-strict %s: trailing tokens after launcher=...\n",
			line_no, name_tok);
		return -1;
	}

	ag = calloc(1, sizeof(*ag));
	if (!ag) goto enomem;
	ag->name = strdup(name_tok);
	if (!ag->name) goto enomem;
	ag->paths = calloc(1, sizeof(char *));
	if (!ag->paths) goto enomem;
	ag->paths[0] = strdup(tgt_tok);
	if (!ag->paths[0]) goto enomem;
	ag->n_paths = 1;
	ag->launcher_path = strdup(launcher);
	if (!ag->launcher_path) goto enomem;
	ag->is_strict = 1;
	ag->strict_slot = ++ps->next_strict_slot;
	if (profile_state_add_actor(ps, ag) < 0) goto enomem;

	/* Open the nested context for subsequent `env` lines. */
	ps->strict_open = ag;
	return 0;

enomem:
	fprintf(stderr, "%d: oom parsing actor-strict\n", line_no);
	actor_group_free(ag);
	return -1;
}

/*
 * v0.4: `env NAME=VALUE`
 * / `env NAME=*` directives have been removed from the v0.4 loader
 * grammar. Env policy is the wrapper's responsibility
 * (`tools/compartment-actor-wrapper.c` +
 * `tools/compartment-actor-build.sh`'s `--allow-env NAME` flags).
 * Storing env directives on the loader side while the wrapper builds
 * with its own env policy from build-time inputs was a silent-drop
 * contract bug: operators writing `env TZ=*` in a profile saw it
 * accepted by the parser but the wrapper was unaware of it. See
 * `HOWTO.md` §6.4 for the
 * wrapper-as-single-source-of-env-policy invariant.
 *
 * The function below now emits a clear loader rejection pointing the
 * operator at HOWTO.md, so legacy profiles surface the change at
 * load time rather than failing silently. The `STRICT_DANGEROUS_ENV_NAMES`
 * table is retained as the wrapper-alignment invariant (shared
 * header); only the directive parser + per-actor env storage are gone.
 */
static int parse_env_decl(char *rest, int line_no, struct profile_state *ps)
{
	(void)rest;
	(void)ps;
	fprintf(stderr,
		"%d: 'env' directive removed in v0.4 (v0.4+); "
		"env policy is sourced from the wrapper. "
		"Use `tools/compartment-actor-build.sh --allow-env NAME` to "
		"customize the wrapper's env allowlist. See HOWTO.md §6.4.\n",
		line_no);
	return -1;
}

/*
 * Fail-closed gate against anon_bdev superblocks.
 *
 * btrfs, overlayfs, and FUSE assign an anonymous block device to each
 * mount (s_dev != backing block device). The BPF LSM hook reads
 * inode->i_sb->s_dev which yields the real subvolume / mount s_dev,
 * while userspace fstat() returns the anon_bdev value — the two never
 * match, so seal_inodes lookup misses silently and every write through
 * a sealed path is ALLOWED.
 *
 * Bi-directional: caller_id_resolve_locked() (compartment.bpf.c) also
 * reads exe->f_inode->i_sb->s_dev, so an actor binary on btrfs gets
 * silently DENIED (no actor inode matches).
 *
 * v0 fix: refuse to seal a path (or resolve an actor binary) that
 * resides on one of these filesystems. Operator-facing diagnostic
 * points at LIMITATIONS.md / SIDEBAR-btrfs-anon_bdev-gap-20260515.md /
 * SIDEBAR-overlay-copyup-gap-20260515.md. v1 will fix the BPF-side
 * resolution instead.
 */
#define COMPARTMENT_BTRFS_SUPER_MAGIC      0x9123683eUL
#define COMPARTMENT_OVERLAYFS_SUPER_MAGIC  0x794c7630UL
#define COMPARTMENT_FUSE_SUPER_MAGIC       0x65735546UL

/* v0.4: minimal ELF static-link check. Reads e_ident + program headers
 * via pread(); returns 1 if the binary has PT_INTERP set (dynamic),
 * 0 if static, -1 on parse error. Used to enforce SPEC §7 requirement
 * that strict-launch launchers be statically linked. */
#include <elf.h>
static int elf_has_interp(int fd, const char *path)
{
	unsigned char ident[EI_NIDENT];
	if (pread(fd, ident, EI_NIDENT, 0) != EI_NIDENT) {
		fprintf(stderr, "launcher %s: short ELF read\n", path);
		return -1;
	}
	if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' ||
	    ident[3] != 'F') {
		fprintf(stderr, "launcher %s: not an ELF binary\n", path);
		return -1;
	}
	if (ident[EI_CLASS] != ELFCLASS64) {
		/* For minimal viable v0.4 we only support ELF64. A 32-bit
		 * launcher on a 64-bit host is operationally pointless. */
		fprintf(stderr,
			"launcher %s: only ELF64 launchers supported in v0.4\n",
			path);
		return -1;
	}
	Elf64_Ehdr eh;
	if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) {
		fprintf(stderr, "launcher %s: short Ehdr read\n", path);
		return -1;
	}
	if (eh.e_phoff == 0 || eh.e_phnum == 0 ||
	    eh.e_phentsize != sizeof(Elf64_Phdr)) {
		fprintf(stderr, "launcher %s: no program headers\n", path);
		return -1;
	}
	if (eh.e_phnum > 256) {
		fprintf(stderr,
			"launcher %s: e_phnum=%u is unreasonably large; refusing\n",
			path, eh.e_phnum);
		return -1;
	}
	for (unsigned i = 0; i < eh.e_phnum; i++) {
		Elf64_Phdr ph;
		off_t off = (off_t)eh.e_phoff + (off_t)i * sizeof(ph);
		if (pread(fd, &ph, sizeof(ph), off) != (ssize_t)sizeof(ph)) {
			fprintf(stderr, "launcher %s: short Phdr[%u] read\n",
				path, i);
			return -1;
		}
		if (ph.p_type == PT_INTERP)
			return 1;  /* dynamic */
	}
	return 0;  /* static */
}

static int anon_bdev_refuse(int pfd, const char *path, const char *ctx)
{
	struct statfs sfs;
	if (fstatfs(pfd, &sfs) != 0) {
		fprintf(stderr,
			"%s %s: fstatfs: %s — refusing fail-closed "
			"(cannot verify filesystem type for anon_bdev gate)\n",
			ctx, path, strerror(errno));
		return -1;
	}
	const char *fsname = NULL;
	switch ((unsigned long)sfs.f_type) {
	case COMPARTMENT_BTRFS_SUPER_MAGIC:     fsname = "btrfs";     break;
	case COMPARTMENT_OVERLAYFS_SUPER_MAGIC: fsname = "overlayfs"; break;
	case COMPARTMENT_FUSE_SUPER_MAGIC:      fsname = "fuse";      break;
	}
	if (!fsname)
		return 0;
	fprintf(stderr,
		"%s %s: ERROR: filesystem type 0x%lx (%s) uses anon_bdev "
		"superblocks — compartment-bpf v0 cannot enforce seals here "
		"because the BPF hook reads inode->i_sb->s_dev (real) while "
		"userspace stat returns the anon_bdev (mismatch → silent "
		"fail-open). Refusing to load. Move sealed paths and actor "
		"binaries to ext4 / xfs / tmpfs. See LIMITATIONS.md and "
		"experimental/exec-domain-mesh/sidebars/SIDEBAR-btrfs-anon_bdev-gap-20260515.md / "
		"SIDEBAR-overlay-copyup-gap-20260515.md.\n",
		ctx, path, (unsigned long)sfs.f_type, fsname);
	return -1;
}

/*
 * Resolve every path declared for `ag` to (dev, ino) via the same
 * two-phase O_PATH+fstat primitive seal_path uses, with the additional
 * security checks SPEC §4 E-7 mandates:
 *   - O_NOFOLLOW + S_ISLNK check (symlink leaf rejected).
 *   - S_ISREG check (non-regular files rejected: dirs, devices, fifos).
 *   - !S_IWOTH check (world-writable actor binary rejected — without
 *     this an attacker with write to the actor binary defeats the
 *     entire exec-domain property; NEW check vs seal_path).
 *   - 0-byte file rejected (a freshly-truncated actor binary cannot be
 *     the actor; refuse rather than locking in a placeholder).
 *
 * The O_PATH fd is retained in `held` for the same lifetime as
 * seal-target fds: the DAEMON'S WHOLE LIFETIME (NOT released after
 * compartment_bpf__attach(); see the held_fds struct comment). This
 * closes the resolve→seal TOCTOU window that the original
 * close-after-fstat path opened: an attacker who could swap the actor
 * binary between fstat() here and load-time seal could otherwise present
 * a different inode to E-6's strict-mode check than what runtime hooks
 * observe via bpf_get_current_task_btf->exe. Pinning the inode for the
 * whole run forces the kernel to keep the same inode struct alive while
 * the seal is enforced. `held` may be NULL in parse-only mode (no fds
 * retained).
 */
// Partial-resolve diagnostic semantics. On ANY failure the function
// returns -1 with `ag->bin` reset to NULL — never partly-filled. This
// matters because the caller eats the error and continues parsing the
// rest of the profile; downstream consumers (enforce_actor_binaries_
// sealed, actor_log_inode_collisions) all special-case `ag->bin == NULL`
// as "unresolved, skip", so leaving a half-filled bin[] would let them
// emit confusing partial output or apply strict-mode against garbage
// entries. The free-and-NULL discipline is uniform across every error
// branch; a stale fd from a half-written iteration is closed before we
// take the goto.
static int actor_resolve_paths(struct actor_group *ag, struct held_fds *held)
{
	if (ag->n_paths == 0)
		return 0;
	if (!ag->bin) {
		ag->bin = calloc(ag->n_paths, sizeof(*ag->bin));
		if (!ag->bin) {
			fprintf(stderr,
				"actor %s: oom resolving paths\n", ag->name);
			return -1;
		}
	}
	for (size_t i = 0; i < ag->n_paths; i++) {
		const char *path = ag->paths[i];
		struct stat st;
		unsigned int ma, mi;
		__u64 dev;
		int pfd;

		pfd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
		if (pfd < 0) {
			fprintf(stderr,
				"actor %s: open %s: %s\n",
				ag->name, path, strerror(errno));
			if (errno == EMFILE || errno == ENFILE)
				fprintf(stderr,
					"  hint: compartment holds one O_PATH fd per sealed inode for the\n"
					"  daemon's lifetime (inode-reuse safety); a large policy can exceed\n"
					"  RLIMIT_NOFILE. Raise the fd limit (e.g. `ulimit -n` / systemd\n"
					"  LimitNOFILE=) above the seal count and retry.\n");
			goto fail_partial;
		}
		if (fstat(pfd, &st) < 0) {
			fprintf(stderr,
				"actor %s: fstat %s: %s\n",
				ag->name, path, strerror(errno));
			close(pfd);
			goto fail_partial;
		}
		/* Bi-directional anon_bdev refuse — actor binaries on
		 * btrfs/overlay/FUSE would silently DENY at runtime (BPF reads
		 * real s_dev; userspace resolves anon_bdev → caller-id miss).
		 */
		{
			char ctx[64];
			snprintf(ctx, sizeof(ctx), "actor %.32s", ag->name);
			if (anon_bdev_refuse(pfd, path, ctx) < 0) {
				close(pfd);
				goto fail_partial;
			}
		}
		if (S_ISLNK(st.st_mode)) {
			fprintf(stderr,
				"actor %s: refusing %s: symlink leaf (O_NOFOLLOW). "
				"Pass the resolved binary path explicitly.\n",
				ag->name, path);
			close(pfd);
			goto fail_partial;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr,
				"actor %s: refusing %s: not a regular file "
				"(mode=0%o)\n",
				ag->name, path,
				(unsigned int)(st.st_mode & 07777));
			close(pfd);
			goto fail_partial;
		}
		// Extend to S_IWGRP too. The original check
		// only rejected world-writable binaries, but a group-writable
		// binary is equally bypass-prone if the group includes any
		// unprivileged user (and on Ubuntu the `adm` group routinely
		// does). The diagnostic names which side fired so the
		// operator knows what to lock down.
		if (st.st_mode & (S_IWOTH | S_IWGRP)) {
			const char *which =
				(st.st_mode & S_IWOTH) ? "world-writable"
						       : "group-writable";
			fprintf(stderr,
				"actor %s: refusing %s: %s binary "
				"(mode=0%o); an attacker with write access "
				"to the actor binary defeats the exec-domain "
				"property. Lock down to mode 0755 or 0750.\n",
				ag->name, path, which,
				(unsigned int)(st.st_mode & 07777));
			close(pfd);
			goto fail_partial;
		}
		// Also reject when the leaf parent directory is
		// world- or group-writable. A vendor /opt/<vendor>/bin with
		// unprivileged-user-owned parent lets an attacker swap the
		// binary file (unlink + recreate at the same name) before
		// loader resolution — the on-disk binary mode does not
		// protect against that. The check happens at resolve time
		// while the O_PATH fd above pins the inode; combined with
		// the resolve→seal pin, the parent-writable window is
		// closed.
		{
			char dbuf[PATH_MAX];
			size_t n = strlen(path);
			if (n >= sizeof(dbuf)) {
				fprintf(stderr,
					"actor %s: refusing %s: path too long for parent-dir check\n",
					ag->name, path);
				close(pfd);
				goto fail_partial;
			}
			memcpy(dbuf, path, n + 1);
			char *slash = strrchr(dbuf, '/');
			const char *parent = "/";
			if (slash == dbuf) {
				parent = "/";
			} else if (slash) {
				*slash = '\0';
				parent = dbuf;
			} else {
				/* paths are absolute (we enforce '/' earlier
				 * for seal targets; actor paths are similarly
				 * absolute by SPEC §3). Refuse otherwise. */
				fprintf(stderr,
					"actor %s: refusing %s: not an absolute path\n",
					ag->name, path);
				close(pfd);
				goto fail_partial;
			}
			struct stat pst;
			int dfd = open(parent,
				       O_PATH | O_DIRECTORY | O_NOFOLLOW
				       | O_CLOEXEC);
			if (dfd < 0) {
				fprintf(stderr,
					"actor %s: open parent %s: %s\n",
					ag->name, parent, strerror(errno));
				close(pfd);
				goto fail_partial;
			}
			if (fstat(dfd, &pst) < 0) {
				fprintf(stderr,
					"actor %s: fstat parent %s: %s\n",
					ag->name, parent, strerror(errno));
				close(dfd);
				close(pfd);
				goto fail_partial;
			}
			close(dfd);
			if (pst.st_mode & (S_IWOTH | S_IWGRP)) {
				fprintf(stderr,
					"actor %s: refusing %s: parent dir %s is "
					"world- or group-writable (mode=0%o); an "
					"unprivileged user with write to the parent "
					"can swap the binary before resolution. "
					"Lock down the parent (mode 0755 / 0750) "
					"or move the binary. SPEC §4 E-7, "
					"\n",
					ag->name, path, parent,
					(unsigned int)(pst.st_mode & 07777));
				close(pfd);
				goto fail_partial;
			}
		}
		if (st.st_size == 0) {
			fprintf(stderr,
				"actor %s: refusing %s: 0-byte file\n",
				ag->name, path);
			close(pfd);
			goto fail_partial;
		}
		// Actor binary must be executable. A non-
		// executable file at the declared path means the operator
		// pointed the profile at the wrong file, OR (worse) the
		// binary is a stub waiting to be replaced. Either way the
		// runtime hook will never observe this file as the caller
		// exe — strict-mode would pass loosely while the seal's
		// allowlist never matches anyone. Refuse at load time.
		if (!(st.st_mode & 0111)) {
			fprintf(stderr,
				"actor %s: refusing %s: not executable "
				"(mode=0%o); runtime hooks observe the "
				"caller's exe inode — a non-executable file "
				"can never be that exe.\n",
				ag->name, path,
				(unsigned int)(st.st_mode & 07777));
			close(pfd);
			goto fail_partial;
		}
		ma = major(st.st_dev);
		mi = minor(st.st_dev);
		if (ma >= (1U << 12) || mi >= (1U << 20)) {
			fprintf(stderr,
				"actor %s: refusing %s: dev %u:%u does not fit kernel dev_t\n",
				ag->name, path, ma, mi);
			close(pfd);
			goto fail_partial;
		}
		dev = ((__u64)ma << 20) | mi;
		if (dev == 0) {
			fprintf(stderr,
				"actor %s: refusing %s: dev=0 (anon inode)\n",
				ag->name, path);
			close(pfd);
			goto fail_partial;
		}
		ag->bin[i].dev = dev;
		ag->bin[i].ino = (__u64)st.st_ino;
		// Retain the O_PATH fd in `held` so the inode
		// reference outlives attach. parse-only callers pass NULL
		// (no fds to hold across an attach that won't happen).
		if (held) {
			if (held_fds_push(held, pfd) < 0) {
				close(pfd);
				goto fail_partial;
			}
		} else {
			close(pfd);
		}
	}
	return 0;

fail_partial:
	// Never leave ag->bin partly filled. Downstream consumers
	// special-case bin == NULL as "unresolved, skip"; a half-filled
	// array would let them apply strict-mode against garbage entries
	// or emit confusing partial output.
	free(ag->bin);
	ag->bin = NULL;
	return -1;
}

/*
 * A (dev, ino) collision across actor groups is allowed
 * (per-binary actor group membership is intentional; postgres-style
 * shared binary). Log once per collision pair.
 */
static void actor_log_inode_collisions(const struct profile_state *ps)
{
	for (size_t i = 0; i < ps->n_actors; i++) {
		struct actor_group *a = ps->actors[i];
		if (!a->bin)
			continue;
		for (size_t k = 0; k < a->n_paths; k++) {
			for (size_t j = i + 1; j < ps->n_actors; j++) {
				struct actor_group *b = ps->actors[j];
				if (!b->bin)
					continue;
				for (size_t m = 0; m < b->n_paths; m++) {
					if (a->bin[k].dev == b->bin[m].dev &&
					    a->bin[k].ino == b->bin[m].ino) {
						fprintf(stderr,
							"[actor] %s and %s share inode %llu (dev=0x%llx); inode-keyed dedup applies at hook time\n",
							a->name, b->name,
							(unsigned long long)a->bin[k].ino,
							(unsigned long long)a->bin[k].dev);
					}
				}
			}
		}
	}
}

static char *trim(char *s)
{
	char *end;

	while (isspace((unsigned char)*s))
		s++;

	if (*s == '\0')
		return s;

	end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';

	return s;
}

/*
 * v0.4+: validate and resolve every actor-strict declaration after the
 * profile has finished parsing. For each `is_strict` actor_group:
 *   1. Open the launcher path (O_PATH+fstat, anon_bdev refuse).
 *   2. Verify the launcher is a regular file, mode 0755-ish (no
 *      group/world writable parent, same checks as actor_resolve_paths
 *      apply via fstat).
 *   3. Verify the launcher is statically linked (no PT_INTERP).
 *   4. Record launcher_dev / launcher_ino.
 *   5. Verify the launcher path AND the target path are both sealed
 *      `full` in the same profile (cross-checked against ps->seals).
 *
 * Returns 0 on success, -1 on any failure. Called after the strict-mode
 * actor-binary check in load_conf so the launcher diagnostics come
 * after the actor-binary diagnostics; the ordering keeps a single
 * profile-author error from cascading into many partial errors.
 */
static int strict_validate_launchers(struct profile_state *ps,
				     struct held_fds *held)
{
	const __u32 required_full = SEAL_NO_WRITE | SEAL_NO_UNLINK
	                          | SEAL_NO_RENAME | SEAL_NO_CHMOD;
	int errs = 0;
	for (size_t i = 0; i < ps->n_actors; i++) {
		struct actor_group *ag = ps->actors[i];
		if (!ag->is_strict)
			continue;
		if (!ag->launcher_path) {
			fprintf(stderr,
				"actor-strict %s: missing launcher_path (internal)\n",
				ag->name);
			errs++;
			continue;
		}
		int lfd = open(ag->launcher_path,
		               O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (lfd < 0) {
			fprintf(stderr,
				"actor-strict %s: open launcher %s: %s\n",
				ag->name, ag->launcher_path, strerror(errno));
			if (errno == EMFILE || errno == ENFILE)
				fprintf(stderr,
					"  hint: compartment holds one O_PATH fd per sealed inode for the\n"
					"  daemon's lifetime (inode-reuse safety); a large policy can exceed\n"
					"  RLIMIT_NOFILE. Raise the fd limit (e.g. `ulimit -n` / systemd\n"
					"  LimitNOFILE=) above the seal count and retry.\n");
			errs++;
			continue;
		}
		struct stat lst;
		if (fstat(lfd, &lst) < 0) {
			fprintf(stderr,
				"actor-strict %s: fstat launcher %s: %s\n",
				ag->name, ag->launcher_path, strerror(errno));
			close(lfd);
			errs++;
			continue;
		}
		char ctx[80];
		snprintf(ctx, sizeof(ctx), "actor-strict %.32s launcher",
		         ag->name);
		if (anon_bdev_refuse(lfd, ag->launcher_path, ctx) < 0) {
			close(lfd);
			errs++;
			continue;
		}
		if (!S_ISREG(lst.st_mode)) {
			fprintf(stderr,
				"actor-strict %s: launcher %s is not a regular file\n",
				ag->name, ag->launcher_path);
			close(lfd);
			errs++;
			continue;
		}
		if (lst.st_mode & (S_IWGRP | S_IWOTH)) {
			fprintf(stderr,
				"actor-strict %s: launcher %s is group- or world-writable (mode=0%o); refusing\n",
				ag->name, ag->launcher_path,
				(unsigned)(lst.st_mode & 07777));
			close(lfd);
			errs++;
			continue;
		}
		int has_interp = elf_has_interp(lfd, ag->launcher_path);
		if (has_interp < 0) {
			close(lfd);
			errs++;
			continue;
		}
		if (has_interp == 1) {
			fprintf(stderr,
				"actor-strict %s: launcher %s is dynamically linked (PT_INTERP present); refusing — strict-launch requires a statically-linked launcher (SPEC §7 / FEASIBILITY hard caveat). Use tools/compartment-actor-wrapper.c built with -static and -DWRAPPER_GENERATED.\n",
				ag->name, ag->launcher_path);
			close(lfd);
			errs++;
			continue;
		}
		unsigned int ma = major(lst.st_dev);
		unsigned int mi = minor(lst.st_dev);
		__u64 ldev = ((__u64)ma << 20) | mi;
		__u64 lino = (__u64)lst.st_ino;
		ag->launcher_dev = ldev;
		ag->launcher_ino = lino;

		/* Launcher must not be the actor's target binary.
		 * If they share (dev,ino), the strict-launch gate is hollow:
		 * the "launcher" execve and the "actor" exec are the same
		 * file, so any execve of that binary is its own launcher and
		 * the actor-identity bind is meaningless. */
		if (ag->bin && ag->n_paths >= 1 &&
		    ldev == ag->bin[0].dev && lino == ag->bin[0].ino) {
			fprintf(stderr,
				"actor-strict '%s': launcher '%s' and target '%s' resolve to the same (dev=0x%llx ino=%llu); "
				"a launcher must be a distinct binary (SPEC §7 strict-launch model)\n",
				ag->name, ag->launcher_path, ag->paths[0],
				(unsigned long long)ldev,
				(unsigned long long)lino);
			close(lfd);
			errs++;
			continue;
		}

		/* Cross-check: launcher path is sealed `full` in this profile.
		 * Cross-check: target path is sealed `full` in this profile.
		 *
		 * The launcher match is by
		 * (dev,ino) only — the loader resolved `ag->launcher_path`
		 * above via O_NOFOLLOW open + fstat, so the (dev,ino) pair
		 * names exactly the launcher inode the strict-launch hook
		 * will see at runtime. The target match (below, and in
		 * enforce_actor_binaries_sealed) uses seal_entry_matches_declared
		 * (path + flags) to defend the hardlink-equivalent
		 * class. The asymmetry is intentional: the launcher's
		 * (dev,ino) is the pre-validated resolution of the declared
		 * launcher_path, while the target-side path-equivalence check
		 * needs the declared-path component because a sealed hardlink
		 * at an unrelated path must NOT satisfy E-6 for this actor.
		 * Functional security holds in both directions. */
		const struct seal_entry *lmatch = NULL;
		int target_sealed_full = 0;
		for (size_t s = 0; s < ps->n_seals; s++) {
			__u32 f = ps->seals[s].flags;
			if (ps->seals[s].dev == ldev &&
			    ps->seals[s].ino == lino &&
			    (f & required_full) == required_full)
				lmatch = &ps->seals[s];
			if (ag->bin && ag->n_paths >= 1 &&
			    ps->seals[s].dev == ag->bin[0].dev &&
			    ps->seals[s].ino == ag->bin[0].ino &&
			    (f & required_full) == required_full)
				target_sealed_full = 1;
		}
		if (!lmatch) {
			fprintf(stderr,
				"actor-strict %s: launcher %s is not sealed `full` in this profile; refusing. Add `seal %s full` to the profile.\n",
				ag->name, ag->launcher_path,
				ag->launcher_path);
			close(lfd);
			errs++;
			continue;
		}
		/* Defense-in-depth — the launcher seal
		 * must NOT carry `actor=`. If it does, the actor would land in
		 * its own launcher's seal allowlist and could overwrite the
		 * launcher bytes in place (preserving (dev,ino)). The
		 * enforce_actor_binaries_sealed() pass also rejects this for
		 * unification with the target-binary check, but we guard here
		 * too so a future caller reordering does not bypass it.
		 * (Symmetric to the target-binary self-modification guard; SPEC §7.1 E-6.) */
		if (lmatch->has_actor) {
			fprintf(stderr,
				"actor-strict '%s' launcher '%s' seal must not carry actor= "
				"(would allow actor-identity confusion: any actor in the launcher's "
				"allowlist could overwrite the launcher bytes in place; "
				"SPEC §7.1 E-6)\n",
				ag->name, ag->launcher_path);
			close(lfd);
			errs++;
			continue;
		}
		if (!target_sealed_full) {
			fprintf(stderr,
				"actor-strict %s: target %s is not sealed `full` in this profile; refusing. Add `seal %s full` to the profile.\n",
				ag->name, ag->paths[0], ag->paths[0]);
			close(lfd);
			errs++;
			continue;
		}

		/* Retain the launcher O_RDONLY fd alongside the seal/actor
		 * pin set so the inode stays anchored across attach. */
		if (held) {
			if (held_fds_push(held, lfd) < 0) {
				close(lfd);
				errs++;
				continue;
			}
		} else {
			close(lfd);
		}

		fprintf(stderr,
			"[strict-launch] %s validated: launcher=%s (dev=0x%llx ino=%llu) target=%s slot=%u\n",
			ag->name, ag->launcher_path,
			(unsigned long long)ldev, (unsigned long long)lino,
			ag->paths[0], ag->strict_slot);
	}
	return errs ? -1 : 0;
}

/*
 * v0.4/v0.6: populate the launcher_to_actor + runtime state BPF maps from
 * the parsed profile state. Called from load_conf in real-load mode
 * after the launcher validation pass succeeds and the seal maps have
 * been populated.
 *
 * Counter: strict_loaded == 1 iff at least one is_strict actor_group
 * was declared. The BPF hooks (task_prctl, ptrace_*) early-out when
 * strict_loaded == 0 so a v0.3-style profile pays no strict-mode cost.
 */
static int strict_populate_maps(struct compartment_bpf *skel,
				struct profile_state *ps)
{
	if (!skel || !skel->maps.launcher_to_actor ||
	    !skel->maps.policy_state_map || !skel->maps.abi_version_map)
		return -1;
	int la_fd = bpf_map__fd(skel->maps.launcher_to_actor);
	int ps_fd = bpf_map__fd(skel->maps.policy_state_map);
	int abi_fd = bpf_map__fd(skel->maps.abi_version_map);
	if (la_fd < 0 || ps_fd < 0 || abi_fd < 0) {
		fprintf(stderr, "strict_populate_maps: runtime map fd unavailable\n");
		return -1;
	}
	__u32 strict_loaded = 0;
	for (size_t i = 0; i < ps->n_actors; i++) {
		struct actor_group *ag = ps->actors[i];
		if (!ag->is_strict)
			continue;
		if (!ag->bin || ag->n_paths == 0) {
			fprintf(stderr,
				"strict_populate_maps: actor-strict %s missing resolved target\n",
				ag->name);
			return -1;
		}
		struct inode_key k = { .dev = ag->launcher_dev,
		                       .ino = ag->launcher_ino };
		struct launcher_actor v = {
			.target = { .dev = ag->bin[0].dev,
			            .ino = ag->bin[0].ino },
			.actor_slot = ag->strict_slot,
			.policy_generation = ps->generation,
		};
		if (bpf_map_update_elem(la_fd, &k, &v, BPF_ANY) < 0) {
			fprintf(stderr,
				"launcher_to_actor update for %s: %s\n",
				ag->name, strerror(errno));
			return -1;
		}
		strict_loaded = 1;
	}
	__u32 zero = 0;
	struct policy_state pv = {
		.generation = ps->generation,
		.strict_loaded = strict_loaded,
	};
	if (bpf_map_update_elem(ps_fd, &zero, &pv, BPF_ANY) < 0) {
		fprintf(stderr, "policy_state update: %s\n", strerror(errno));
		return -1;
	}
	__u32 abi_version = COMPARTMENT_ABI_VERSION;
	if (bpf_map_update_elem(abi_fd, &zero, &abi_version, BPF_ANY) < 0) {
		fprintf(stderr, "abi_version_map update: %s\n", strerror(errno));
		return -1;
	}
	fprintf(stderr,
		"[strict-launch] runtime state populated: generation=%u strict_loaded=%u abi=0x%04x\n",
		ps->generation, strict_loaded, abi_version);
	return 0;
}

/*
 * Parse the trailing flag-spec of a `seal` directive. Recognized tokens:
 *   full | no-unlink | no-rename | no-write | no-chmod
 *   actor=NAME             — optional, at most one per seal line.
 *
 * If `actor_name_out` is non-NULL and an `actor=NAME` clause is present,
 * NAME is copied into the buffer (must be at least ACTOR_NAME_MAX wide).
 * Absent: the buffer is left as the empty string. `actor_name_out` MAY
 * be NULL for callers that do not support actor= syntax (none today,
 * but cheap to keep optional).
 *
 * A seal with `actor=NAME` MUST also carry ≥1 flag — combining
 * actor= with no flags is rejected as a profile-author error.
 * `seal /p full actor=NAME` is allowed (and recommended) —
 * `full` is a valid flag.
 */
static int parse_flagspec(char *s, __u32 *flags_out, char *actor_name_out,
			  size_t actor_name_sz, int line_no)
{
	__u32 flags = 0;
	char *save = NULL;
	char *tok;
	int saw_actor_eq = 0;
	int saw_flag_token = 0;

	if (actor_name_out && actor_name_sz)
		actor_name_out[0] = '\0';

	s = trim(s);
	if (*s == '\0') {
		*flags_out = SEAL_FULL;
		return 0;
	}

	for (tok = strtok_r(s, ", \t\r\n", &save);
	     tok;
	     tok = strtok_r(NULL, ", \t\r\n", &save)) {
		if (!strncmp(tok, "actor=", 6)) {
			const char *name = tok + 6;
			if (saw_actor_eq) {
				fprintf(stderr,
					"%d: multiple actor= clauses on a single seal directive\n",
					line_no);
				return -1;
			}
			if (!actor_name_out) {
				fprintf(stderr,
					"%d: actor= clause not supported in this context\n",
					line_no);
				return -1;
			}
			if (*name == '\0') {
				fprintf(stderr,
					"%d: malformed actor= clause (empty NAME)\n",
					line_no);
				return -1;
			}
			if (!actor_name_valid(name)) {
				fprintf(stderr,
					"%d: malformed actor= clause: invalid NAME '%s' (max %d chars, [a-zA-Z_][a-zA-Z0-9_-]*)\n",
					line_no, name, ACTOR_NAME_MAX - 1);
				return -1;
			}
			if (strlen(name) + 1 > actor_name_sz) {
				fprintf(stderr,
					"%d: actor= NAME too long\n", line_no);
				return -1;
			}
			memcpy(actor_name_out, name, strlen(name) + 1);
			saw_actor_eq = 1;
			continue;
		}
		if (!strcmp(tok, "full")) {
			flags |= SEAL_FULL;
		} else if (!strcmp(tok, "no-unlink")) {
			flags |= SEAL_NO_UNLINK;
		} else if (!strcmp(tok, "no-rename")) {
			flags |= SEAL_NO_RENAME;
		} else if (!strcmp(tok, "no-write")) {
			flags |= SEAL_NO_WRITE;
		} else if (!strcmp(tok, "no-chmod")) {
			flags |= SEAL_NO_CHMOD;
		} else if (!strcmp(tok, "strict-launch")) {
			/* v0.4: strict-launch is an additive flag — independent
			 * of `full`. Validation that the seal also has actor=
			 * bound to an actor-strict declaration runs at seal
			 * application time (seal_path), not here. */
			flags |= SEAL_STRICT_LAUNCH;
		} else {
			fprintf(stderr, "%d: unknown seal flag '%s'\n", line_no, tok);
			return -1;
		}
		saw_flag_token = 1;
	}

	/* This must fire BEFORE the generic empty-flags check so
	 * that `seal /etc/a actor=a` reports "must specify at least one
	 * flag before actor= clause" (the actionable diagnostic) rather
	 * than "empty seal flags" (the misleading generic one). The two
	 * checks are mutually exclusive on a well-formed line; ordering
	 * matters only on the malformed-with-actor= case. */
	if (saw_actor_eq && !saw_flag_token) {
		fprintf(stderr,
			"%d: seal directive must specify at least one flag before actor= clause\n",
			line_no);
		return -1;
	}
	if (!flags) {
		fprintf(stderr, "%d: empty seal flags\n", line_no);
		return -1;
	}
	/* `strict-launch` is a modifier on top
	 * of an op-flag — a seal that carries SEAL_STRICT_LAUNCH but no
	 * other op-flag enforces nothing, so the new strict-launch
	 * counters fire zero on every protected op. False-green class:
	 * profile passes parse, witnesses appear to PASS, ships
	 * unprotected. Reject vacuously-strict seals at parse time so the
	 * operator gets an actionable diagnostic instead.
	 */
	if (flags == SEAL_STRICT_LAUNCH) {
		fprintf(stderr,
			"%d: strict-launch is a modifier; declare at least one op-flag "
			"(e.g., no-write, no-unlink, no-rename, no-chmod, or full) for "
			"the seal to enforce. A seal that carries only `strict-launch` "
			"would deny nothing.\n",
			line_no);
		return -1;
	}

	*flags_out = flags;
	return 0;
}

static const char *action_name(__u32 a)
{
	switch (a) {
	case ACTION_DENY_UNLINK:         return "DENY_UNLINK";
	case ACTION_DENY_RENAME:         return "DENY_RENAME";
	case ACTION_DENY_WRITE:          return "DENY_WRITE";
	case ACTION_DENY_ACTOR_MISMATCH: return "DENY_ACTOR_MISMATCH";
	case ACTION_DENY_CHMOD:          return "DENY_CHMOD";
	case ACTION_DENY_CREATE:         return "DENY_CREATE";
	case ACTION_DENY_UNPIN_AUTH_FAIL: return "DENY_UNPIN_AUTH_FAIL";
	case ACTION_DENY_STRICT_LAUNCH_MISSING: return "DENY_STRICT_LAUNCH_MISSING";
	case ACTION_DENY_WRITE_PARENT_DIR:      return "DENY_WRITE_PARENT_DIR";
	case ACTION_DENY_CHMOD_PARENT_DIR:      return "DENY_CHMOD_PARENT_DIR";
	case ACTION_DENY_PRCTL_SET_MM:          return "DENY_PRCTL_SET_MM";
	case ACTION_DENY_PTRACE_ACCESS:         return "DENY_PTRACE_ACCESS";
	case ACTION_DENY_PTRACE_TRACEME:        return "DENY_PTRACE_TRACEME";
	default: return "?";
	}
}

// Render flag bitmask as a human-readable comma-separated list. Used by
// --dry-run output so an operator can read off the policy without decoding
// the hex.
static const char *fmt_flags(__u32 flags, char *buf, size_t bufsz)
{
	int n = 0;
	const char *sep = "";

	if (bufsz == 0)
		return buf;
	buf[0] = '\0';

	if (flags == SEAL_FULL) {
		snprintf(buf, bufsz, "full");
		return buf;
	}

// Clamp n after each snprintf so bufsz-n cannot underflow in size_t.
#define ADD(name, bit) do { \
	if ((flags) & (bit) && n >= 0 && (size_t)n < bufsz) { \
		int r = snprintf(buf + n, bufsz - n, "%s" name, sep); \
		if (r < 0) break; \
		n = ((size_t)(n + r) >= bufsz) ? (int)(bufsz - 1) : (n + r); \
		sep = ","; \
	} \
} while (0)

	ADD("no-unlink", SEAL_NO_UNLINK);
	ADD("no-rename", SEAL_NO_RENAME);
	ADD("no-write",  SEAL_NO_WRITE);
	ADD("no-chmod",  SEAL_NO_CHMOD);
#undef ADD

	return buf;
}

// Strict-mode enforcement. After all seal directives have been
// applied and all actor groups resolved, every actor binary MUST itself
// be sealed with the full SEAL_NO_WRITE | SEAL_NO_UNLINK | SEAL_NO_RENAME
// | SEAL_NO_CHMOD set; otherwise the exec-domain property is trivially
// bypassed by overwriting the actor binary out-of-band. This is a
// mandatory v0.x default per SPEC §7.1 E-6 — no opt-out
// flag.
//
// Returns 0 on success (every actor binary is fully sealed, or there
// are no actor groups), -1 on the first failure (with a stderr line
// naming the actor, the binary path, and the missing flag(s)).
//
// Called from load_conf after parse + resolution and BEFORE main()
// attaches the BPF programs; a failure here returns -1 from load_conf
// so the maps written so far are simply abandoned (skeleton release in
// main()).
static int enforce_actor_binaries_sealed(const struct profile_state *ps)
{
	const __u32 required = SEAL_NO_WRITE | SEAL_NO_UNLINK
	                     | SEAL_NO_RENAME | SEAL_NO_CHMOD;

	// Ground the strict-mode result in the
	// actual actor count. A profile with n_actors == 0 (no actors
	// declared) trivially "passes" strict-mode — but the silent
	// pass is indistinguishable from "all N actors checked and
	// sealed". Annotate up front so the operator sees the set size.
	fprintf(stderr,
		"[strict-mode] checking actor-binary seals: n_actors=%zu\n",
		ps->n_actors);

	for (size_t g = 0; g < ps->n_actors; g++) {
		const struct actor_group *ag = ps->actors[g];
		if (!ag || !ag->bin)
			continue;  // parse-only / unresolved; skipped above.
		for (size_t b = 0; b < ag->n_paths; b++) {
			__u64 a_dev = ag->bin[b].dev;
			__u64 a_ino = ag->bin[b].ino;
			const char *bpath = ag->paths[b];
			// Require path-equivalence on top of
			// (dev, ino) — a hardlink seal at an unrelated
			// declared path must NOT satisfy E-6 for this actor.
			// The match is: a seal entry whose (dev, ino) matches
			// AND whose declared-path list contains this actor's
			// declared path. Anything weaker permits the hardlink
			// bypass.
			const struct seal_entry *match = NULL;
			for (size_t s = 0; s < ps->n_seals; s++) {
				if (ps->seals[s].dev == a_dev &&
				    ps->seals[s].ino == a_ino &&
				    seal_entry_matches_declared(
					    &ps->seals[s], bpath)) {
					match = &ps->seals[s];
					break;
				}
			}
			if (!match) {
				fprintf(stderr,
					"actor '%s' binary '%s' is not sealed at its declared path "
					"(strict-mode requires a seal at this exact path with "
					"no-write,no-unlink,no-rename,no-chmod; a seal at a "
					"hardlink-equivalent path does NOT satisfy — "
					"SPEC §7.1 E-6)\n",
					ag->name, bpath);
				return -1;
			}
			__u32 missing = required & ~match->flags;
			if (missing) {
				char buf[64];
				fprintf(stderr,
					"actor '%s' binary '%s' is sealed but missing flags [%s] "
					"(strict-mode requires no-write,no-unlink,no-rename,no-chmod; "
					"SPEC §7.1 E-6)\n",
					ag->name, bpath,
					fmt_flags(missing, buf, sizeof buf));
				return -1;
			}
			// The actor-binary seal must NOT carry
			// `actor=` itself. If it does, the actor process would
			// appear in its own seal allowlist and `actor_check_or_deny`
			// would return ALLOW for writes/renames/etc to its own
			// binary, defeating E-6 (the actor can overwrite its
			// own bytes in-place, preserving (dev,ino)). Reject
			// loader-side so the foot-gun never reaches the kernel.
			if (match->has_actor) {
				fprintf(stderr,
					"actor '%s' binary path '%s' seal must not carry actor= "
					"(prevents self-modification gate; SPEC §7.1 E-6, V-6 P1-C)\n",
					ag->name, bpath);
				return -1;
			}
		}
	}

	// For strict actors, the launcher seal must
	// not carry `actor=` (symmetric to the target-binary check above).
	// `enforce_actor_binaries_sealed` runs BEFORE `strict_validate_launchers`,
	// so `ag->launcher_dev`/`launcher_ino` are still calloc-zero here —
	// match by declared launcher_path. Defense-in-depth: the launcher
	// resolve in strict_validate_launchers() guards the same property
	// against an independent seal entry; one foot-gun, two gates.
	for (size_t g = 0; g < ps->n_actors; g++) {
		const struct actor_group *ag = ps->actors[g];
		if (!ag || !ag->is_strict || !ag->launcher_path)
			continue;
		const struct seal_entry *lmatch = NULL;
		for (size_t s = 0; s < ps->n_seals; s++) {
			if (seal_entry_matches_declared(
				    &ps->seals[s], ag->launcher_path)) {
				lmatch = &ps->seals[s];
				break;
			}
		}
		if (!lmatch)
			continue;  // strict_validate_launchers will reject.
		if (lmatch->has_actor) {
			fprintf(stderr,
				"actor-strict '%s' launcher seal '%s' must not carry actor= "
				"(would allow any actor in the launcher's allowlist to overwrite "
				"the launcher bytes in place; SPEC §7.1 E-6)\n",
				ag->name, ag->launcher_path);
			return -1;
		}
	}

	fprintf(stderr,
		"[strict-mode] OK: %zu actor%s sealed at declared paths\n",
		ps->n_actors, ps->n_actors == 1 ? "" : "s");
	return 0;
}

struct dir_subtree_check_ctx {
	const char *root;
	int failed;
};

/* NOT re-entrant: nftw(3) provides no user-data argument, so the callback
 * context is passed via this file-scope pointer. validate_recursive_dir_seal()
 * is only called from the single-threaded loader; concurrent callers would
 * race on this pointer. */
static struct dir_subtree_check_ctx *g_dir_subtree_check_ctx;

static int dir_subtree_check_cb(const char *fpath, const struct stat *sb,
				int typeflag, struct FTW *ftwbuf)
{
	struct dir_subtree_check_ctx *ctx = g_dir_subtree_check_ctx;
	int is_dir = sb && S_ISDIR(sb->st_mode);

	if (!ctx)
		return 1;
	if (ftwbuf && ftwbuf->level == 0)
		return 0;
	if (typeflag == FTW_NS) {
		fprintf(stderr,
			"seal %s: subtree stat failed at %s: %s\n",
			ctx->root, fpath, strerror(errno));
		ctx->failed = 1;
		return 1;
	}
	if (typeflag == FTW_DNR) {
		fprintf(stderr,
			"seal %s: subtree read failed at %s\n",
			ctx->root, fpath);
		ctx->failed = 1;
		return 1;
	}
	/* Runtime enforcement can cover files whose parent directory is within
	 * COMPARTMENT_MAX_DIR_ANCESTORS ancestor hops of the sealed root. To keep
	 * recursive subtree seals fail-closed, reject any live subtree that already
	 * contains:
	 *   - a directory at depth >= cap (new children below it would outrun the
	 *     ancestor walk), or
	 *   - a non-directory entry deeper than the cap (its parent is already too
	 *     deep for the root seal to be found).
	 */
	if (ftwbuf &&
	    ((is_dir && ftwbuf->level >= COMPARTMENT_MAX_DIR_ANCESTORS) ||
	     (!is_dir && ftwbuf->level > COMPARTMENT_MAX_DIR_ANCESTORS))) {
		fprintf(stderr,
			"seal %s: refusing recursive directory seal: subtree entry "
			"'%s' exceeds the compiled depth cap "
			"(COMPARTMENT_MAX_DIR_ANCESTORS=%d). Split the subtree "
			"into intermediate seal rules or rebuild with a larger cap.\n",
			ctx->root, fpath, COMPARTMENT_MAX_DIR_ANCESTORS);
		ctx->failed = 1;
		return 1;
	}
	if ((typeflag == FTW_SL) || (sb && S_ISLNK(sb->st_mode))) {
		fprintf(stderr,
			"seal %s: refusing recursive directory seal: subtree entry "
			"'%s' is a symlink. Replace it with a real file/directory "
			"or seal the target path explicitly.\n",
			ctx->root, fpath);
		ctx->failed = 1;
		return 1;
	}
	if (sb && !S_ISDIR(sb->st_mode) && sb->st_nlink > 1) {
		fprintf(stderr,
			"seal %s: refusing recursive directory seal: subtree entry "
			"'%s' has %llu hardlinks (st_nlink > 1). Replace it with "
			"a copy or seal every alias parent.\n",
			ctx->root, fpath, (unsigned long long)sb->st_nlink);
		ctx->failed = 1;
		return 1;
	}
	return 0;
}

static int validate_recursive_dir_seal(const char *path)
{
	struct dir_subtree_check_ctx ctx = {
		.root = path,
		.failed = 0,
	};
	int rc;
	int saved_errno = 0;

	g_dir_subtree_check_ctx = &ctx;
	errno = 0;
	rc = nftw(path, dir_subtree_check_cb, 32, FTW_PHYS | FTW_MOUNT);
	saved_errno = errno;
	g_dir_subtree_check_ctx = NULL;
	if (ctx.failed)
		return -1;
	if (rc < 0) {
		fprintf(stderr, "seal %s: recursive subtree scan: %s\n",
			path, strerror(saved_errno));
		return -1;
	}
	return 0;
}

// Resolve a seal directive against the live filesystem and either populate
// the BPF map (skel != NULL) or print the resolved key as a dry-run line
// (skel == NULL). All path / dev / inode validation runs in both modes,
// so --dry-run catches the same parser/stat errors as a real run.
//
// Two-phase resolution closes a hostile path-swap race during policy
// load. There is still a residual window between the last
// bpf_map_update_elem and compartment_bpf__attach during which the kernel
// is not yet enforcing; the `held` fd buffer narrows that window further
// by holding O_PATH fds open. Those fds are then kept for the DAEMON'S
// WHOLE LIFETIME (NOT released after attach), so the inum-reuse
// protection persists for as long as the seal is enforced (see the
// held_fds struct comment — do not add a release-after-attach).
// Run early, before protected services, for the strongest guarantee.
//
//   1. open(path, O_PATH | O_NOFOLLOW) -- pins an fd on the named entry.
//      With O_PATH, O_NOFOLLOW does NOT cause ELOOP on a symlink leaf
//      (per `man 2 open`); instead it opens the symlink itself, so we
//      detect S_ISLNK after fstat and reject explicitly. Symlinks deeper
//      in the path resolve normally; the hardening is at the seal target.
//   2. fstat(fd) -- read dev/ino/mode through the anchored fd.
//   3. bpf_map_update_elem -- (dev, ino) -> flags into sealed_{inodes,dirs}.
//   4. Push pfd onto `held` (transferring ownership). main() keeps
//      these fds open for the daemon's whole lifetime — they are NOT
//      released after compartment_bpf__attach() returns (releasing them
//      would reopen the inode-reuse window; see the held_fds comment).
//
// On any error path we close pfd here. On dry-run we close pfd here.
//
// Symlink semantics changed vs. v0: previously stat() followed symlinks at
// the leaf, so "seal /usr/bin/python" sealed whatever python pointed to
// (e.g. python3.13). Now we refuse a symlink leaf and tell the operator
// to pass the target path explicitly. The README documents this.
static int seal_path(struct compartment_bpf *skel, const char *path,
		     __u32 flags, const struct actor_group *actor_ref,
		     struct held_fds *held, struct profile_state *ps)
{
	struct stat st;
	unsigned int ma, mi;
	__u64 dev;
	int is_dir;
	int pfd;

	if (path[0] != '/') {
		fprintf(stderr, "seal %s: path must be absolute\n", path);
		return -1;
	}

	// Refuse a
	// seal that references an actor group whose ->bin is NULL. This
	// happens when actor-binary path resolution failed silently
	// upstream (the actor_group exists but its (dev, ino) array is
	// unfilled). Pre-this, the seal would still load with an
	// actor_name suffix but actor_check_or_deny would see
	// actor_count=0 and uniform-deny — surprising operator behaviour
	// for a seal that *appeared* actor-bound at parse time.
	if (actor_ref && !actor_ref->bin) {
		fprintf(stderr,
			"seal %s: actor '%s' has no resolved binaries "
			"(parse-time resolution failed); refusing fail-closed. "
			"Check the actor PATH list for typos / missing files / "
			"world-writable hits.\n",
			path, actor_ref->name);
		return -1;
	}

	pfd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (pfd < 0) {
		fprintf(stderr, "seal %s: open: %s\n",
			path, strerror(errno));
		if (errno == EMFILE || errno == ENFILE)
			fprintf(stderr,
				"  hint: compartment holds one O_PATH fd per sealed inode for the\n"
				"  daemon's lifetime (inode-reuse safety); a large policy can exceed\n"
				"  RLIMIT_NOFILE. Raise the fd limit (e.g. `ulimit -n` / systemd\n"
				"  LimitNOFILE=) above the seal count and retry.\n");
		return -1;
	}

	if (fstat(pfd, &st) < 0) {
		fprintf(stderr, "seal %s: fstat: %s\n", path, strerror(errno));
		close(pfd);
		return -1;
	}

	/* anon_bdev refuse — btrfs/overlay/FUSE seals are silent
	 * fail-open in v0 because the BPF hook reads inode->i_sb->s_dev
	 * (real subvolume / lower s_dev) while userspace fstat() returns
	 * the anon_bdev. Refuse at load time; v1 will fix BPF-side.
	 */
	if (anon_bdev_refuse(pfd, path, "seal") < 0) {
		close(pfd);
		return -1;
	}

	if (S_ISLNK(st.st_mode)) {
		fprintf(stderr,
			"seal %s: refusing to seal a symlink leaf. "
			"Pass the target path explicitly.\n",
			path);
		close(pfd);
		return -1;
	}

	// Kernel s_dev encoding: MKDEV(major, minor). Match it on userspace
	// side to keep keys identical to what BPF_CORE_READ sees.
	ma = major(st.st_dev);
	mi = minor(st.st_dev);
	if (ma >= (1U << 12) || mi >= (1U << 20)) {
		fprintf(stderr, "seal %s: dev %u:%u does not fit kernel dev_t\n",
			path, ma, mi);
		close(pfd);
		return -1;
	}

	dev = ((__u64)ma << 20) | mi;
	// Reject dev == 0 outright. The BPF sentinel-skip in
	// lookup_inode_flags treats (dev, ino) == (0, 0) as "no key", but
	// anonymous-superblock inodes (sockets, pipes, anon_inode) have
	// dev == 0 with nonzero ino — those entries would silently land in
	// the maps and lookup successfully, while parent-dir checks short
	// on (0, 0) only. v0 does not define semantics for sealing anon
	// inodes; refuse them at policy-load time.
	if (dev == 0) {
		fprintf(stderr,
			"seal %s: refusing dev=0 (anon inode, ino=%llu)\n",
			path, (unsigned long long)st.st_ino);
		close(pfd);
		return -1;
	}

	is_dir = S_ISDIR(st.st_mode) ? 1 : 0;

	// v0.6: recursive subtree loader invariants. For every sealed
	// directory, scan the full subtree and refuse if:
	//   (a) any descendant is a symlink — path resolution escapes the
	//       sealed ancestor before the LSM hook sees the final dentry;
	//   (b) any non-directory descendant has st_nlink > 1 — a hardlink
	//       alias outside the sealed subtree can still write the inode
	//       through an unsealed path; or
	//   (c) any descendant already exceeds the compiled recursive depth
	//       budget — otherwise the seal would silently fail-open beyond
	//       COMPARTMENT_MAX_DIR_ANCESTORS.
	// Both checks are hard failures before attach.
	if (is_dir) {
		if (validate_recursive_dir_seal(path) < 0) {
			close(pfd);
			return -1;
		}
	}

	if (!skel) {
		// Merge-refusal applied in dry-run too: real-load enforces
		// merge-refusal via the BPF map readback below, but dry-run
		// never touches the map. Mirror the check at the in-memory
		// shadow level so the rejection fires in both modes.
		if (ps) {
			int prior_has_actor = 0;
			int prior_exists = 0;
			for (size_t i = 0; i < ps->n_seals; i++) {
				if (ps->seals[i].dev == dev &&
				    ps->seals[i].ino == (__u64)st.st_ino) {
					prior_exists = 1;
					prior_has_actor = ps->seals[i].has_actor;
					break;
				}
			}
			int new_has_actor = (actor_ref != NULL);
			if (prior_exists && (prior_has_actor || new_has_actor)) {
				fprintf(stderr,
					"seal %s: refusing to merge seal lines on the same path when either carries actor= (fail-closed). "
					"Combine flags into one seal line.\n",
					path);
				close(pfd);
				return -1;
			}
		}
		char fb[64];
		fprintf(stderr,
			"[dry-run] %s%s dev=0x%llx (%u:%u) ino=%llu flags=0x%x (%s) actor=%s\n",
			is_dir ? "[d] " : "    ",
			path,
			(unsigned long long)dev, ma, mi,
			(unsigned long long)st.st_ino, flags,
			fmt_flags(flags, fb, sizeof(fb)),
			actor_ref ? actor_ref->name : "(none)");
		close(pfd);
		// Record the (dev, ino, flags) so strict-mode
		// enforcement sees the resolved profile in dry-run mode too.
		if (ps && profile_state_record_seal(ps, dev,
						    (__u64)st.st_ino, flags,
						    actor_ref != NULL,
						    path) < 0) {
			fprintf(stderr, "seal %s: oom recording seal\n", path);
			return -1;
		}
		return 0;
	}

	struct inode_key k = { .dev = dev, .ino = (__u64)st.st_ino };

	int mfd = is_dir
		? bpf_map__fd(skel->maps.sealed_dirs)
		: bpf_map__fd(skel->maps.sealed_inodes);
	if (mfd < 0) {
		fprintf(stderr, "seal %s: map fd unavailable\n", path);
		close(pfd);
		return -1;
	}

	// Build the v0.1 seal_value the kernel will read. actor_count == 0
	// preserves v0 uniform-deny semantics for seals without actor=NAME.
	// Actor cap: the parser already rejected actor groups
	// with > COMPARTMENT_MAX_ACTORS_PER_SEAL paths; the assert below is
	// the last line of defense against drift.
	struct seal_value sv = { 0 };
	sv.flags = flags;
	/* v0.4: strict-launch sanity. SEAL_STRICT_LAUNCH is only meaningful
	 * when actor=NAME is bound to an `actor-strict` declaration (since
	 * the BPF strict-launch check compares marker.actor_slot against
	 * seal_value.strict_actor_slot, which is derived from the actor-
	 * strict slot id). Refuse loudly if the operator combined
	 * strict-launch with `actor` (legacy) or without `actor=`.
	 */
	if (flags & SEAL_STRICT_LAUNCH) {
		if (!actor_ref) {
			fprintf(stderr,
				"seal %s: strict-launch requires `actor=NAME` bound to an `actor-strict` declaration\n",
				path);
			close(pfd);
			return -1;
		}
		if (!actor_ref->is_strict) {
			fprintf(stderr,
				"seal %s: strict-launch flag references actor '%s' which was declared via `actor` (legacy, binary-identity only). Re-declare as `actor-strict NAME = TARGET launcher=PATH` to enable clean-launch enforcement.\n",
				path, actor_ref->name);
			close(pfd);
			return -1;
		}
		sv.strict_actor_slot = actor_ref->strict_slot;
		sv.strict_generation = ps ? ps->generation : 1;
	}
	if (actor_ref && actor_ref->bin) {
		if (actor_ref->n_paths > COMPARTMENT_MAX_ACTORS_PER_SEAL) {
			// Parser should have caught this; refuse the load
			// rather than silently truncate (fail-closed).
			fprintf(stderr,
				"seal %s: actor %s has %zu paths but seal_value cap is %d\n",
				path, actor_ref->name,
				actor_ref->n_paths,
				COMPARTMENT_MAX_ACTORS_PER_SEAL);
			close(pfd);
			return -1;
		}
		sv.actor_count = (__u8)actor_ref->n_paths;
		for (size_t i = 0; i < actor_ref->n_paths; i++) {
			sv.actor[i].dev = actor_ref->bin[i].dev;
			sv.actor[i].ino = actor_ref->bin[i].ino;
		}
		// v0.3: copy actor-group name into seal_value so
		// the BPF program can carry it into the audit_event on the
		// actor-mismatch path WITHOUT a userspace lookup table. The
		// ABI slot is 16 bytes; we truncate to 15 + NUL. Names are
		// already validated by actor_name_valid (parser only accepts
		// printable [A-Za-z0-9_-] within ACTOR_NAME_MAX=32), so the
		// truncation can only lose trailing characters, never inject
		// control bytes downstream.
		if (actor_ref->name) {
			size_t cap = sizeof(sv.actor_name);
			size_t n = strnlen(actor_ref->name, cap - 1);
			memcpy(sv.actor_name, actor_ref->name, n);
			sv.actor_name[n] = '\0';
		}
	}

	// Merge with any existing entry under the same (dev, ino). A profile
	// is allowed to name the same path twice with different flags --
	// `seal /tmp/x no-write` then `seal /tmp/x no-unlink` should leave
	// BOTH bits set. An earlier version used BPF_ANY with new flags,
	// silently dropping prior bits. The OR merge below preserves the
	// legacy behavior when neither side carries an actor=.
	//
	// Fail-closed: if either side has actor_count > 0 (an actor=
	// allowlist), refuse to merge. Combining two seal lines that carry
	// different actor sets is ambiguous (intersection? union? per-flag
	// actor binding?); the safest answer is to refuse and tell the
	// author to collapse the two lines into one.
	struct seal_value prev = { 0 };
	int have_prev = 0;
	if (bpf_map_lookup_elem(mfd, &k, &prev) == 0) {
		have_prev = 1;
	} else if (errno != ENOENT) {
		fprintf(stderr, "seal %s: map lookup before merge: %s\n",
			path, strerror(errno));
		close(pfd);
		return -1;
	}

	if (have_prev) {
		if (prev.actor_count != 0 || sv.actor_count != 0) {
			fprintf(stderr,
				"seal %s: refusing to merge seal lines on the same path when either carries actor= (fail-closed). "
				"Combine flags into one seal line.\n",
				path);
			close(pfd);
			return -1;
		}
		sv.flags |= prev.flags;
		// Both sides actor_count == 0; sv.actor[] remains zeroed.
	}

	if (bpf_map_update_elem(mfd, &k, &sv, BPF_ANY) < 0) {
		fprintf(stderr, "seal %s: map update: %s\n", path, strerror(errno));
		close(pfd);
		return -1;
	}

	// Record the merged flags into ps->seals so the post-resolve
	// strict-mode pass sees the same flag set the kernel just wrote.
	if (ps && profile_state_record_seal(ps, dev, (__u64)st.st_ino,
					    sv.flags,
					    actor_ref != NULL, path) < 0) {
		fprintf(stderr, "seal %s: oom recording seal\n", path);
		close(pfd);
		return -1;
	}

	// Transfer pfd ownership to held; main() holds these O_PATH fds for the
	// daemon's whole lifetime (inode-reuse pin), NOT just across attach.
	if (held_fds_push(held, pfd) < 0) {
		close(pfd);
		return -1;
	}

	fprintf(stderr, "[seal] %s%s ino=%llu flags=0x%x actor=%s (n=%u)\n",
		is_dir ? "[d] " : "    ",
		path, (unsigned long long)st.st_ino, sv.flags,
		actor_ref ? actor_ref->name : "(none)",
		(unsigned)sv.actor_count);
	return 0;
}

// Conf parser. Recognises:
//   seal <path> <flag-spec> [actor=NAME]
//   actor NAME = PATH [PATH ...]
// Comments start with '#'. Fail-closed on unknown directives or flags.
//
// When skel == NULL, we are in dry-run mode: every directive is parsed and
// stat'd, every error fires as it would in a real run, but no BPF map is
// touched. A summary line is printed at end-of-file.
//
// When `parse_only` is non-zero, neither BPF maps nor the filesystem are
// touched: only grammar is checked (used by tests/parser-actor/01..08 to
// drive deterministic parser fixtures without requiring real paths to
// exist or have specific modes).
//
// `held` collects the O_PATH fds opened by seal_path; the caller (main)
// holds them for the daemon's whole lifetime to pin sealed inodes against
// number reuse (NOT just across attach). May be NULL in
// dry-run / parse-only modes (seal_path closes its fd locally in that
// path).
//
// `allow_empty` lets a profile with zero seal directives load anyway.
// Default behavior is fail-closed: an empty or
// comment-only profile would otherwise attach with no rules, leaving
// the daemon enforcing nothing -- a fail-OPEN posture indistinguishable
// from "policy not loaded yet". Soak runs that intentionally want a
// no-op load pass --allow-empty.
//
// Actor-allowlist:
//   - `actor NAME = PATH [PATH ...]` declares a named actor group;
//     declarations are local to a profile, MUST precede any seal that
//     references them (forward references rejected with "unknown actor").
//   - `seal <path> <flags> actor=NAME` binds a seal to that actor group.
//     At hook time the seal will deny unless the calling task's
//     exe inode matches one of the group's resolved binaries.
//   - During parse the actor pointer is recorded but NOT propagated
//     into BPF maps; that happens at map-population time.
/* `pin_enforce_path` is 1 when load_conf is called from
 * the `--pin` enforcement-enabling code path; 0 for --dry-run / --parse-only.
 * `allow_candidate` is 1 when the operator passed `--allow-candidate` to
 * acknowledge they want to load a candidate-marked profile under --pin.
 * When pin_enforce_path && profile_is_candidate && !allow_candidate, load_conf
 * fails closed (returns -1) before the loader proceeds to freeze + attach. */
static int load_conf(struct compartment_bpf *skel, const char *path,
		     struct held_fds *held, int allow_empty, int parse_only,
		     int pin_enforce_path, int allow_candidate)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}

	struct profile_state ps = {0};
	ps.generation = 1;  /* v0.4 fixed at first load; reload bumps */
	char line[2048];
	int errs = 0;
	int sealed = 0;
	int line_no = 0;
	/* Detect the candidate-profile marker BEFORE the
	 * `#`-strip line below collapses it to an empty comment. A
	 * `compartment-bpf observe`-generated profile must surface a
	 * loud stderr warning so an operator cannot promote a candidate
	 * draft to production enforcement silently. */
	int profile_is_candidate = 0;
	static const char candidate_marker[] =
		"#@compartment-bpf-profile-status:";
	for (;;) {
		// Pre-zero the buffer so we can detect an
		// embedded NUL that fgets() would have written into the
		// middle of the line (silent truncation at strlen()). The
		// caller would otherwise parse only line[0..strlen(line))
		// and miss the trailing bytes — including any further
		// directives a hostile profile crammed past a NUL.
		memset(line, 0, sizeof(line));
		if (!fgets(line, sizeof(line), f))
			break;
		char *p, *hash, *dir, *target, *flagspec;
		char *save = NULL;
		size_t len;
		__u32 flags;
		char actor_name[ACTOR_NAME_MAX];
		const struct actor_group *actor_ref = NULL;

		line_no++;
		len = strlen(line);
		// If the buffer holds non-zero bytes BEYOND the first
		// strlen-terminating NUL (i.e. the byte at index `len + 1`
		// or any byte after, up to where fgets stopped), the input
		// contained an embedded NUL. Reject hard with a clear
		// diagnostic; this is profile-author error.
		{
			int saw_after = 0;
			for (size_t i = len + 1; i < sizeof(line); i++) {
				if (line[i] != '\0') {
					saw_after = 1;
					break;
				}
			}
			if (saw_after) {
				fprintf(stderr,
					"%d: embedded NUL detected in line; "
					"refusing profile (F21 fail-closed)\n",
					line_no);
				errs++;
				continue;
			}
		}
		// An un-newline-terminated read from fgets()
		// means the input line is at least sizeof(line)-1 bytes
		// wide and was truncated. Refuse hard with an explicit
		// diagnostic naming the buffer size — auto-growing would
		// open a memory-budget attack surface; the security-
		// conservative answer is to make the line a profile-author
		// error. Fixture pair 20 (overlong) + 21 (at-bound) in
		// tests/parser-actor/run.sh prevent regression.
		if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
			fprintf(stderr,
				"%d: line too long (truncated at %zu bytes by fgets — "
				"the parser hard-rejects this rather than auto-grow the "
				"buffer; split the directive across multiple lines or "
				"shorten paths)\n",
				line_no, sizeof(line) - 1);
			errs++;
			// Also check ferror during the flush drain so an
			// I/O error mid-drain is reported with the correct
			// line_no instead of being silently absorbed.
			while (fgets(line, sizeof(line), f)) {
				if (strchr(line, '\n'))
					break;
			}
			if (ferror(f)) {
				fprintf(stderr,
					"%d: read error draining overlong line: %s\n",
					line_no, strerror(errno));
				errs++;
				break;
			}
			continue;
		}

		/* Scan for the candidate-profile marker before
		 * stripping `#`-comments. Tolerates leading whitespace
		 * and any whitespace between the colon and the value.
		 * Use isspace() in skip loops so the accepted set
		 * matches trim() (catches '\v'/'\f' too) — an attacker
		 * cannot smuggle the marker past detection by prefixing
		 * '\v'. Tail set stays narrow intentionally: it is not a
		 * security gate (the loader validates the full marker on
		 * --pin); it just prevents trivial text misattribution
		 * such as a "candidatestable" suffix being read as
		 * "candidate". */
		{
			const char *cm = line;
			while (isspace((unsigned char)*cm)) cm++;
			if (strncmp(cm, candidate_marker,
				    sizeof(candidate_marker) - 1) == 0) {
				const char *val = cm + sizeof(candidate_marker) - 1;
				while (isspace((unsigned char)*val)) val++;
				if (strncmp(val, "candidate", 9) == 0) {
					char tail = val[9];
					if (tail == '\0' || tail == '\n' ||
					    tail == '\r' || tail == ' ' ||
					    tail == '\t' || tail == '#')
						profile_is_candidate = 1;
				}
			}
		}

		hash = strchr(line, '#');
		if (hash)
			*hash = '\0';

		p = trim(line);
		if (*p == '\0')
			continue;

		dir = strtok_r(p, " \t\r\n", &save);
		if (!dir)
			continue;

		// actor NAME = PATH [PATH ...]
		if (strcmp(dir, "actor") == 0) {
			char *rest = save ? save : "";
			/* v0.4: any non-env top-level closes the open
			 * actor-strict context. */
			ps.strict_open = NULL;
			if (parse_actor_decl(rest, line_no, &ps) < 0) {
				errs++;
				continue;
			}
			// Resolve declared paths now, unless we're in
			// parse-only mode (parser-fixture tests).
			if (!parse_only) {
				struct actor_group *ag =
					ps.actors[ps.n_actors - 1];
				if (actor_resolve_paths(ag, held) < 0) {
					errs++;
					continue;
				}
				fprintf(stderr,
					"[actor] %s → %zu binar%s\n",
					ag->name, ag->n_paths,
					ag->n_paths == 1 ? "y" : "ies");
			}
			continue;
		}

		// v0.4: actor-strict NAME = TARGET launcher=PATH
		if (strcmp(dir, "actor-strict") == 0) {
			char *rest = save ? save : "";
			ps.strict_open = NULL; /* will be reopened by parse */
			if (parse_actor_strict_decl(rest, line_no, &ps) < 0) {
				errs++;
				continue;
			}
			if (!parse_only) {
				struct actor_group *ag =
					ps.actors[ps.n_actors - 1];
				if (actor_resolve_paths(ag, held) < 0) {
					errs++;
					/* keep strict_open so further env
					 * lines don't get re-flagged with a
					 * different message; just keep the
					 * error and move on. */
					continue;
				}
				fprintf(stderr,
					"[actor-strict] %s → target=%s launcher=%s slot=%u\n",
					ag->name, ag->paths[0],
					ag->launcher_path, ag->strict_slot);
			}
			continue;
		}

		// v0.4: env NAME=VALUE or env NAME=* (nested under actor-strict)
		if (strcmp(dir, "env") == 0) {
			char *rest = save ? save : "";
			if (parse_env_decl(rest, line_no, &ps) < 0) {
				errs++;
				continue;
			}
			continue;
		}

		target = strtok_r(NULL, " \t\r\n", &save);
		flagspec = save ? save : "";

		/* v0.4: any top-level non-env directive closes the
		 * actor-strict env-context. */
		ps.strict_open = NULL;

		if (strcmp(dir, "seal") != 0) {
			fprintf(stderr, "%d: unknown directive '%s'\n", line_no, dir);
			errs++;
			continue;
		}
		if (!target) {
			fprintf(stderr, "%d: missing seal target\n", line_no);
			errs++;
			continue;
		}
		if (parse_flagspec(flagspec, &flags, actor_name,
				   sizeof(actor_name), line_no) < 0) {
			errs++;
			continue;
		}
		if (actor_name[0] != '\0') {
			actor_ref = profile_find_actor(&ps, actor_name);
			if (!actor_ref) {
				// "Forward reference" and "unknown name" are
				// the same surface error at this point: we
				// scan top-to-bottom and the name is not in
				// the table yet. Surface "unknown actor" with
				// a hint about decl ordering.
				fprintf(stderr,
					"%d: unknown actor '%s' (forward references not allowed; declare the actor before the seal that uses it)\n",
					line_no, actor_name);
				errs++;
				continue;
			}
		}
		if (parse_only) {
			// Parser-only: validate the seal target is absolute
			// so 01-basic etc. fail at the same site they would
			// in a real run; skip the actual seal_path() syscall.
			if (target[0] != '/') {
				fprintf(stderr,
					"%d: seal target '%s' must be absolute\n",
					line_no, target);
				errs++;
				continue;
			}
			sealed++;
			continue;
		}
		if (seal_path(skel, target, flags, actor_ref, held, &ps) < 0) {
			errs++;
		} else {
			sealed++;
			// An actor binary that is also a seal
			// target in the same profile is the recommended
			// secure state (SPEC §4 E-6). The
			// informational-note TODO that previously stood here
			// is superseded by the
			// enforce_actor_binaries_sealed() pass, which makes
			// "actor binary not sealed" a hard load error rather
			// than something to log informationally. No follow-up
			// is required at this call site; strict-mode already
			// performs the correlation that the TODO described.
		}
	}

	if (ferror(f)) {
		fprintf(stderr, "read %s: %s\n", path, strerror(errno));
		errs++;
	}
	if (fclose(f) < 0) {
		fprintf(stderr, "close %s: %s\n", path, strerror(errno));
		errs++;
	}

	/* Candidate-profile warning. The observe(1) draft is
	 * not intended for direct production enforcement; surfacing this
	 * on stderr makes that explicit in dry-run, parse-only, and
	 * real-load paths alike. */
	if (profile_is_candidate) {
		fprintf(stderr,
			"WARNING: %s carries `#@compartment-bpf-profile-status: candidate`. "
			"This profile was generated by `compartment-bpf observe` as a "
			"draft and is not intended for direct production enforcement; "
			"review and edit before loading as policy.\n",
			path);
		/* Warn-only is trivially silenced by
		 * `2>/dev/null`. On the --pin enforcement-enabling path,
		 * fail closed unless the operator explicitly opted in with
		 * --allow-candidate. dry-run / parse-only remain warn-only:
		 * the gate fires only when this load would commit live
		 * enforcement state. */
		if (pin_enforce_path && !allow_candidate) {
			fprintf(stderr,
				"error: %s is a candidate profile; refusing to "
				"--pin without --allow-candidate. Either review "
				"the profile and remove the "
				"`#@compartment-bpf-profile-status: candidate` "
				"marker, or pass --allow-candidate to override.\n",
				path);
			errs++;
		}
	}

	// Report inode collisions informationally.
	if (!parse_only && errs == 0)
		actor_log_inode_collisions(&ps);

	// Strict-mode actor-binary-sealed enforcement. Runs only when
	// actors have been resolved (i.e. not parse-only).
	// Un-gated from `errs == 0` so the strict
	// check fires even when the parser has already accumulated some
	// errors. Otherwise a single parse error would silently skip the
	// strict-mode check; the operator saw 'load failed' but had no
	// way to know whether the strict check would have rejected the
	// actor binaries too. Strict check counts +=1 on its own
	// failures, so the existing `errs > 0 → return -1` exit path
	// captures both error sources uniformly.
	// The inner enforce_actor_binaries_sealed prints a
	// `[strict-mode] n_actors=N result=...` line so the failure /
	// success is grounded in the actual set size.
	if (!parse_only) {
		if (enforce_actor_binaries_sealed(&ps) < 0)
			errs++;
	}

	// v0.4: validate every actor-strict declaration's launcher binary
	// (static-link, sealed `full`, target sealed `full`). Skipped in
	// parse-only because launcher resolution requires FS access.
	if (!parse_only) {
		if (strict_validate_launchers(&ps, held) < 0)
			errs++;
	}

	// v0.4: populate the BPF maps that back strict-launch enforcement.
	// Skipped in dry-run and parse-only modes (both have skel == NULL).
	// Runs only when there were no parse errors so a partially-broken
	// profile doesn't ship strict-launch with stale state.
	if (skel != NULL && errs == 0) {
		if (strict_populate_maps(skel, &ps) < 0)
			errs++;
	}

	if (skel == NULL && !parse_only) {
		fprintf(stderr,
			"[dry-run] summary: %d seal%s resolved, %zu actor group%s, %d error%s\n",
			sealed, sealed == 1 ? "" : "s",
			ps.n_actors, ps.n_actors == 1 ? "" : "s",
			errs, errs == 1 ? "" : "s");
	}
	if (parse_only) {
		fprintf(stderr,
			"[parse-only] summary: %d seal%s, %zu actor group%s, %d error%s\n",
			sealed, sealed == 1 ? "" : "s",
			ps.n_actors, ps.n_actors == 1 ? "" : "s",
			errs, errs == 1 ? "" : "s");
	}

	profile_state_release(&ps);

	if (errs)
		return -1;

	// A profile that resolves zero seals is a fail-open
	// no-op load. Refuse unless the operator opted in via --allow-empty.
	if (sealed == 0 && !allow_empty) {
		fprintf(stderr,
			"%s: empty profile (no seal directives loaded). "
			"Pass --allow-empty for soak/no-op runs.\n",
			path);
		return -1;
	}
	return 0;
}

static int audit_handler(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct audit_event)) {
		fprintf(stderr, "warn: short audit event: %zu bytes\n", sz);
		return 0;
	}

	struct audit_event *e = data;
	// v0.3: the ABI version word at offset 0 lets the consumer
	// detect a producer/consumer mismatch instead of silently parsing a
	// foreign layout. Reject loud and skip the event. This is the
	// fail-closed path: if the kernel and userspace disagree on
	// audit_event shape we MUST NOT emit a parsed line whose field
	// values may be from the wrong offsets.
	if (e->version != COMPARTMENT_ABI_VERSION) {
		fprintf(stderr,
			"warn: audit event version mismatch (got 0x%04x, "
			"expected 0x%04x); skipping. Rebuild loader against "
			"the running BPF object.\n",
			(unsigned)e->version,
			(unsigned)COMPARTMENT_ABI_VERSION);
		return 0;
	}
	// %.16s caps comm width to its struct size in case a future ABI bump
	// reuses this consumer with a different producer layout.
	// comm is user-settable via prctl(PR_SET_NAME) so it could
	// contain ANSI-escape control bytes that would inject into operator
	// stderr. Sanitize to printable ASCII before logging.
	char safe_comm[sizeof(e->comm) + 1];
	for (size_t i = 0; i < sizeof(e->comm); i++) {
		unsigned char c = (unsigned char)e->comm[i];
		if (c == 0) {
			safe_comm[i] = 0;
			break;
		}
		safe_comm[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
	}
	safe_comm[sizeof(e->comm)] = 0;
	// v0.3: actor_name carries the actor-group name on the
	// actor-mismatch path; for every other event type the slot is
	// zeroed by the producer. Sanitize the same way as comm because
	// although the loader validates name bytes today, a future ABI
	// bump could relax that — the consumer should not trust producer-
	// supplied bytes. Empty when the producer set no name (legacy or
	// non-actor-mismatch event).
	char safe_actor[sizeof(e->actor_name) + 1];
	for (size_t i = 0; i < sizeof(e->actor_name); i++) {
		unsigned char c = (unsigned char)e->actor_name[i];
		if (c == 0) {
			safe_actor[i] = 0;
			break;
		}
		safe_actor[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
	}
	safe_actor[sizeof(e->actor_name)] = 0;
	// ABI v0.2: caller_dev / caller_ino populated only on the actor-
	// mismatch path; for all v0.1 events both are zero and we omit them
	// to keep legacy audit lines stable. v0.3 appends actor=NAME only
	// when the actor-group name slot is non-empty (i.e. an actor-
	// mismatch event with a resolved actor_name). Format is two
	// suffixes so downstream log parsers can opt in on the substring
	// without breaking on legacy events.
	if (e->caller_dev != 0 || e->caller_ino != 0) {
		if (safe_actor[0] != '\0') {
			fprintf(stderr,
				"[audit] %s ts=%llu pid=%u ppid=%u uid=%u comm=%s dev=%llu ino=%llu caller_dev=%llu caller_ino=%llu actor=%s\n",
				action_name(e->action),
				(unsigned long long)e->ts_ns,
				e->pid, e->ppid, e->uid, safe_comm,
				(unsigned long long)e->dev,
				(unsigned long long)e->ino,
				(unsigned long long)e->caller_dev,
				(unsigned long long)e->caller_ino,
				safe_actor);
		} else {
			fprintf(stderr,
				"[audit] %s ts=%llu pid=%u ppid=%u uid=%u comm=%s dev=%llu ino=%llu caller_dev=%llu caller_ino=%llu\n",
				action_name(e->action),
				(unsigned long long)e->ts_ns,
				e->pid, e->ppid, e->uid, safe_comm,
				(unsigned long long)e->dev,
				(unsigned long long)e->ino,
				(unsigned long long)e->caller_dev,
				(unsigned long long)e->caller_ino);
		}
	} else {
		fprintf(stderr,
			"[audit] %s ts=%llu pid=%u ppid=%u uid=%u comm=%s dev=%llu ino=%llu\n",
			action_name(e->action),
			(unsigned long long)e->ts_ns,
			e->pid, e->ppid, e->uid, safe_comm,
			(unsigned long long)e->dev,
			(unsigned long long)e->ino);
	}
	return 0;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"usage: %s [--pin] [--dry-run] [--parse-only] [--allow-empty] [--allow-candidate] <profile.conf>\n"
		"       %s --unpin [PATH]\n"
		"       %s --stats\n"
		"  --pin          pin BPF links to " PIN_ROOT "\n"
		"                 (policy survives loader exit); when used with a\n"
		"                 profile, deny/audit-drop counter maps are also\n"
		"                 pinned under " PIN_ROOT "/maps.\n"
		"  --dry-run      parse the profile, stat every path, print resolved\n"
		"                 (dev, ino) keys; do not load or attach. Safe for\n"
		"                 non-root, no kernel state touched.\n"
		"  --parse-only   grammar-check the profile only; no filesystem\n"
		"                 access, no kernel state. Faster than --dry-run,\n"
		"                 used by parser-fixture tests.\n"
		"  --allow-empty  permit a profile with zero seal directives to load\n"
		"                 (default: refuse -- empty policy is fail-open).\n"
		"                 Use only for soak runs.\n"
		"  --allow-candidate\n"
		"                 explicitly load a candidate-marked profile under\n"
		"                 --pin. Without this flag, --pin against a profile\n"
		"                 carrying `#@compartment-bpf-profile-status:\n"
		"                 candidate` (the marker `compartment-bpf observe`\n"
		"                 writes) exits non-zero. dry-run / parse-only ignore\n"
		"                 this flag.\n"
		"  --unpin        remove known compartment-bpf pins under " PIN_ROOT ".\n"
		"                 PATH (optional) restricts the operation to that\n"
		"                 file or subdirectory; it must canonicalise to a\n"
		"                 location inside " PIN_ROOT " or it is refused.\n"
		"                 Mutually exclusive with --pin/--dry-run and a\n"
		"                 profile argument. " PIN_ROOT " itself is preserved.\n"
		"  --stats        open the pinned per-CPU counter maps under " PIN_ROOT "/maps\n"
		"                 (all 12: deny_total, audit_drop_total, actor_mismatch_total,\n"
		"                 strict_launch_{missing,allowed}_total, marker_{set,clear_foreign_exec,\n"
		"                 copy_fork,stale_generation}_total, prctl_set_mm_exe_file_denied_total,\n"
		"                 ptrace_{access,traceme}_denied_total — see COUNTERS.md), sum\n"
		"                 per-CPU values, and print one '[stats] <name>=<N> ...' line. Exit 2 with\n"
		"                 '[stats] no pinned counters found' if no pin\n"
		"                 exists. Read-only.\n",
		p, p, p);
}

// Print kernel version + active LSM list, hard-fail if 'bpf' is not in
// the active LSM list, and emit a kernel-version hint about file_truncate
// (the youngest hook we use; needs >= 6.5).
//
// The previous per-hook BTF lookup was overbuilt: it duplicated knowledge
// that libbpf already maintains in the skeleton's program metadata,
// soft-failed exactly on the kernels where it would matter, and added
// NULL-deref / type-id boundary risks. Replaced by a uname hint here +
// the existing `compartment_bpf__attach()` failure path which gives a
// hook-specific error message anyway.
static int probe_lsm_environment(void)
{
	struct utsname uts;
	FILE *f;
	// 4 KiB tolerates pathological stacked-LSM configurations that
	// would have truncated the 512-byte buffer (and falsely reported
	// 'bpf' missing).
	char lsm[4096];
	char tmp[4096];
	char *save = NULL, *tok;
	size_t n;
	int has_bpf = 0;
	unsigned int kmaj = 0, kmin = 0;

	if (uname(&uts) == 0) {
		fprintf(stderr, "[probe] kernel %s %s\n", uts.release, uts.machine);
		// Best-effort major.minor parse. release is e.g. "7.0.0-15-generic".
		(void)sscanf(uts.release, "%u.%u", &kmaj, &kmin);
	} else {
		fprintf(stderr, "[probe] warn: uname: %s\n", strerror(errno));
	}

	f = fopen("/sys/kernel/security/lsm", "r");
	if (!f) {
		fprintf(stderr,
			"error: cannot read /sys/kernel/security/lsm: %s\n"
			"  BPF LSM cannot be probed; refusing to load blind.\n",
			strerror(errno));
		return -1;
	}
	n = fread(lsm, 1, sizeof(lsm) - 1, f);
	if (ferror(f)) {
		fprintf(stderr, "error: read /sys/kernel/security/lsm: %s\n",
			strerror(errno));
		fclose(f);
		return -1;
	}
	fclose(f);
	lsm[n] = '\0';

	fprintf(stderr, "[probe] active LSMs: %s",
		lsm[0] ? lsm : "(empty)\n");
	if (n == 0 || lsm[n - 1] != '\n')
		fputc('\n', stderr);

	// Token-exact check for "bpf" so e.g. "bpfcheck" cannot satisfy a
	// substring match. The list is comma-separated; tokens may carry
	// surrounding whitespace including \r on some kernels.
	memcpy(tmp, lsm, n);
	tmp[n] = '\0';
	for (tok = strtok_r(tmp, ", \t\r\n", &save); tok;
	     tok = strtok_r(NULL, ", \t\r\n", &save)) {
		if (!strcmp(tok, "bpf")) {
			has_bpf = 1;
			break;
		}
	}

	if (!has_bpf) {
		fprintf(stderr,
			"error: 'bpf' is not in the active LSM list.\n"
			"  Add lsm=...,bpf to GRUB_CMDLINE_LINUX_DEFAULT, "
			"update-grub, reboot.\n");
		return -1;
	}

	// file_truncate is the youngest LSM hook we attach (kernel 6.5+).
	// Older kernels will have it absent and `compartment_bpf__attach()`
	// will fail with an attach-specific error; surface the actionable
	// hint here.
	if (kmaj > 0 && (kmaj < 6 || (kmaj == 6 && kmin < 5))) {
		fprintf(stderr,
			"[probe] warn: kernel %u.%u < 6.5; the file_truncate "
			"LSM hook may be missing. Attach will fail; upgrade "
			"the kernel to enforce no-write seals.\n",
			kmaj, kmin);
	}

	return 0;
}

static int ensure_bpffs(const char *path)
{
	struct statfs sfs;

	if (statfs(path, &sfs) < 0) {
		fprintf(stderr, "statfs %s: %s\n", path, strerror(errno));
		return -1;
	}
	if ((unsigned long)sfs.f_type != (unsigned long)BPF_FS_MAGIC) {
		fprintf(stderr,
			"error: %s is not a bpffs mount (f_type=0x%lx, want 0x%lx).\n"
			"  mount -t bpf bpf %s\n",
			path, (unsigned long)sfs.f_type,
			(unsigned long)BPF_FS_MAGIC, path);
		return -1;
	}
	return 0;
}

static int ensure_dir(const char *path)
{
	struct stat st;

	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (stat(path, &st) < 0) {
		fprintf(stderr, "stat %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "%s exists but is not a directory\n", path);
		return -1;
	}
	return 0;
}

static int pin_one_link(struct bpf_link *link, const char *name,
			char pinned[][PATH_MAX], int *pinned_count)
{
	char path[PATH_MAX];
	int err;

	if (!link) {
		fprintf(stderr, "pin link %s: link is not attached\n", name);
		return -1;
	}

	if (snprintf(path, sizeof(path), PIN_ROOT "/links/%s", name) >=
	    (int)sizeof(path)) {
		fprintf(stderr, "pin link %s: path too long\n", name);
		return -1;
	}

	err = bpf_link__pin(link, path);
	if (err < 0) {
		err = -err;
		fprintf(stderr, "pin link %s: %s\n", path, strerror(err));
		return -1;
	}

	snprintf(pinned[*pinned_count], PATH_MAX, "%s", path);
	(*pinned_count)++;
	return 0;
}

static void unlink_pinned_links(char pinned[][PATH_MAX], int pinned_count)
{
	for (int i = 0; i < pinned_count; i++) {
		if (unlink(pinned[i]) < 0)
			fprintf(stderr, "warn: unlink %s: %s\n",
				pinned[i], strerror(errno));
	}
}

// --pin and --unpin must not race each other or two
// concurrent --pin invocations against the same PIN_ROOT. A naïve race
// can unlink-then-recreate, or split a half-pinned state across the two
// processes. Use a process-wide flock on a lockfile under /run; the
// kernel releases the lock automatically on process exit so a crashed
// loader does not strand the lock.
//
// Lockfile lives under /run/lock/ when available, fall back to /tmp/
// only if /run/lock/ is unwritable (chroot / non-systemd). LOCK_NB so
// the second concurrent invocation returns EBUSY-with-diagnostic
// rather than blocking — operators get a fast, deterministic failure
// surface.
#define PIN_LIFECYCLE_LOCK_DEFAULT "/run/lock/compartment-bpf-pin.lock"
#define PIN_LIFECYCLE_LOCK_FALLBACK "/tmp/.compartment-bpf-pin.lock"

static int pin_lifecycle_lock(const char *who)
{
	int fd = open(PIN_LIFECYCLE_LOCK_DEFAULT,
		      O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0 && errno != EACCES && errno != EROFS && errno != ENOENT) {
		fprintf(stderr,
			"%s: open lockfile %s: %s\n",
			who, PIN_LIFECYCLE_LOCK_DEFAULT, strerror(errno));
		return -1;
	}
	if (fd < 0) {
		// O_NOFOLLOW on the fallback path
		// /tmp/.compartment-bpf-pin.lock too. /tmp is world-writable;
		// an attacker can pre-create a symlink at that path pointing
		// at any file root can write to and trick us into opening it.
		// O_NOFOLLOW refuses to traverse the symlink and the open
		// fails with ELOOP — fail-closed deny.
		fd = open(PIN_LIFECYCLE_LOCK_FALLBACK,
			  O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (fd < 0) {
			fprintf(stderr,
				"%s: open fallback lockfile %s: %s\n",
				who, PIN_LIFECYCLE_LOCK_FALLBACK,
				strerror(errno));
			return -1;
		}
	}
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			fprintf(stderr,
				"%s: another compartment-bpf pin/unpin is in progress (EBUSY); refuse to race the pin lifecycle. Try again once it completes.\n",
				who);
		} else {
			fprintf(stderr,
				"%s: flock pin lifecycle lock: %s\n",
				who, strerror(errno));
		}
		close(fd);
		return -1;
	}
	return fd;
}

static void pin_lifecycle_unlock(int fd)
{
	if (fd >= 0) {
		/* flock is released on close; explicit LOCK_UN is redundant
		 * but documents intent. */
		(void)flock(fd, LOCK_UN);
		close(fd);
	}
}

static int pin_links(struct compartment_bpf *skel)
{
	// pin_one_link writes into pinned[*pinned_count] without an
	// explicit bound. We currently make 21 PIN_LINK invocations and have
	// 32 slots. The assert hard-codes the current count (21) because
	// KNOWN_LINK_NAMES is declared later in the file; if the PIN_LINK
	// invocation count below grows, bump the literal here in lockstep.
	char pinned[32][PATH_MAX];
	_Static_assert(sizeof(pinned) / PATH_MAX >= 21,
		       "pinned[] must hold all PIN_LINK invocations (currently 21: 16 v0.3 + 5 v0.4)");
	int pinned_count = 0;

	if (ensure_bpffs("/sys/fs/bpf") < 0 ||
	    ensure_dir(PIN_ROOT) < 0 ||
	    ensure_dir(PIN_ROOT "/links") < 0)
		return -1;

#define PIN_LINK(name) do { \
	if (pin_one_link(skel->links.name, #name, pinned, &pinned_count) < 0) \
		goto err; \
} while (0)

	PIN_LINK(comp_inode_unlink);
	PIN_LINK(comp_inode_rename);
	PIN_LINK(comp_inode_rmdir);
	PIN_LINK(comp_inode_create);
	PIN_LINK(comp_inode_mkdir);
	PIN_LINK(comp_inode_mknod);
	PIN_LINK(comp_inode_symlink);
	PIN_LINK(comp_inode_link);
	PIN_LINK(comp_file_open);
	PIN_LINK(comp_file_permission);
	PIN_LINK(comp_file_truncate);
	// inode_setattr ships two kernel-signature wrappers (modern/legacy);
	// exactly one is autoloaded+attached (select_inode_setattr_variant). Pin
	// whichever is live under the CANONICAL name so the bpffs pin path and the
	// KNOWN_LINK_NAMES unpin/drain sweep stay kernel-independent.
	if (pin_one_link(skel->links.comp_inode_setattr
	                 ? skel->links.comp_inode_setattr
	                 : skel->links.comp_inode_setattr_legacy,
	                 "comp_inode_setattr", pinned, &pinned_count) < 0)
		goto err;
	PIN_LINK(comp_mmap_file);
	PIN_LINK(comp_file_mprotect);
	PIN_LINK(comp_inode_setxattr);
	PIN_LINK(comp_inode_removexattr);
	/* v0.4 strict-launch-marker hooks */
	PIN_LINK(comp_bprm_check_security);
	PIN_LINK(comp_task_alloc);
	PIN_LINK(comp_task_prctl);
	PIN_LINK(comp_ptrace_access_check);
	PIN_LINK(comp_ptrace_traceme);

#undef PIN_LINK

	fprintf(stderr, "[pin] " PIN_ROOT "/links\n");
	return 0;

err:
	unlink_pinned_links(pinned, pinned_count);
	return -1;
}

// Known pin shapes for --unpin enumeration. Must stay in lockstep
// with pin_links() above. The unpin path is name-based so that an unknown
// filename under PIN_ROOT/links (e.g. a stray pin from a hand-edited
// experiment) is refused and left intact rather than blindly removed.
static const char *const KNOWN_LINK_NAMES[] = {
	"comp_inode_unlink",
	"comp_inode_rename",
	"comp_inode_rmdir",
	"comp_inode_create",
	"comp_inode_mkdir",
	"comp_inode_mknod",
	"comp_inode_symlink",
	"comp_inode_link",
	"comp_file_open",
	"comp_file_permission",
	"comp_file_truncate",
	"comp_inode_setattr",
	"comp_mmap_file",
	"comp_file_mprotect",
	"comp_inode_setxattr",
	"comp_inode_removexattr",
	/* v0.4: strict-launch-marker hooks */
	"comp_bprm_check_security",
	"comp_task_alloc",
	"comp_task_prctl",
	"comp_ptrace_access_check",
	"comp_ptrace_traceme",
};
static const size_t N_KNOWN_LINK_NAMES =
	sizeof(KNOWN_LINK_NAMES) / sizeof(KNOWN_LINK_NAMES[0]);

// Detect an already-pinned tree. Returns 1 if any known link pin exists
// under <PIN_ROOT>/links, 0 if none is present.
//
// This gates re-pinning over a live tree. Without it, a second --pin
// attaches a fresh skel, then writes (or, in the no-passphrase case,
// clobbers on rollback) the unpin-auth sentinel BEFORE pin_links() fails
// EEXIST against the still-present old pins — and the EEXIST rollback
// path calls ed11_unpin_sentinel_unlink(). Net effect: the live,
// previously-pinned tree is left with no sentinel, so the next --unpin
// takes the legacy (no-passphrase) path and tears down enforcement with
// no auth. Refusing up front, before any side effect, closes that
// downgrade and matches the documented "reject a new --pin if stale
// pins exist" contract.
//
// Fail-closed: a bpf_obj_get() error other than ENOENT means we cannot
// prove the pin is absent, so we report existence and let the caller
// refuse rather than risk clobbering a sentinel we could not inspect.
static int pin_tree_exists(void)
{
	for (size_t i = 0; i < N_KNOWN_LINK_NAMES; i++) {
		char path[PATH_MAX];
		if (snprintf(path, sizeof(path), PIN_ROOT "/links/%s",
			     KNOWN_LINK_NAMES[i]) >= (int)sizeof(path))
			continue;
		int fd = bpf_obj_get(path);
		if (fd >= 0) {
			close(fd);
			return 1;
		}
		if (errno != ENOENT)
			return 1;
	}
	return 0;
}

// PIN_ROOT/maps is populated for the two deny/audit-drop counter
// maps when --pin is set with a profile. The seal maps (sealed_inodes,
// sealed_dirs) and audit_rb are still NOT pinned in v0 but their names
// are listed for forward-compatibility with future map-pinning revisions;
// sweep_known() tolerates absent files, so listing them is harmless.
	static const char *const KNOWN_MAP_NAMES[] = {
	"sealed_inodes",
	"sealed_dirs",
	"audit_rb",
	"deny_total",
	"audit_drop_total",
	"actor_mismatch_total",
	/* v0.4: strict-launch-marker maps + counters */
	"launcher_to_actor",
	"actor_marker_map",
	"policy_state_map",
	"abi_version_map",
	"strict_launch_missing_total",
	"strict_launch_allowed_total",
	"marker_set_total",
	"marker_clear_foreign_exec_total",
	"marker_copy_fork_total",
	"marker_stale_generation_total",
	"prctl_set_mm_exe_file_denied_total",
	"ptrace_access_denied_total",
	"ptrace_traceme_denied_total",
};
static const size_t N_KNOWN_MAP_NAMES =
	sizeof(KNOWN_MAP_NAMES) / sizeof(KNOWN_MAP_NAMES[0]);

static int name_in(const char *name, const char *const *table, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (strcmp(name, table[i]) == 0)
			return 1;
	return 0;
}

// Unlink the known pin files in <dir>. Directories themselves are left
// in place: preserving PIN_ROOT and its substructure lets a subsequent
// --pin invocation reuse them with no mkdir gymnastics. Unknown filenames are
// reported as warnings and left intact -- the unpin path never deletes
// an unrecognised bpffs object.
// Walk the pin directory through an fd opened with
// O_DIRECTORY | O_NOFOLLOW, then unlinkat(dirfd, name, 0) for each
// match. This closes a TOCTOU window where the dir component could
// be swapped (symlink to /etc replaced the bpffs directory) between
// opendir() returning and a path-based unlink() firing — even though
// realpath() canonicalised the initial path, nothing else pinned the
// resolved inode for the duration of the walk. The fd-anchored
// pattern means every unlinkat operates relative to the same inode
// the walk started against.
//
// fdopendir() takes ownership of the fd on success (closedir frees
// it); on failure we close the fd ourselves.
static int sweep_known(const char *dir,
		       const char *const *table, size_t n_table,
		       int *removed, int *unknown)
{
	int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dfd < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf(stderr, "open dir %s: %s\n", dir, strerror(errno));
		return -1;
	}
	DIR *d = fdopendir(dfd);
	if (!d) {
		fprintf(stderr, "fdopendir %s: %s\n", dir, strerror(errno));
		close(dfd);
		return -1;
	}
	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.' &&
		    (de->d_name[1] == '\0' ||
		     (de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		if (!name_in(de->d_name, table, n_table)) {
			fprintf(stderr,
				"warn: %s/%s is not a known compartment-bpf pin; left intact.\n",
				dir, de->d_name);
			(*unknown)++;
			continue;
		}
		if (unlinkat(dirfd(d), de->d_name, 0) < 0) {
			fprintf(stderr, "unlinkat %s/%s: %s\n",
				dir, de->d_name, strerror(errno));
			closedir(d);
			return -1;
		}
		(*removed)++;
	}
	closedir(d);
	return 0;
}

// Path-prefix safety for --unpin. Canonicalise both sides with realpath(),
// then accept iff cand == root OR cand starts with root + "/". Raw
// strncmp(PIN_ROOT) would accept e.g. /sys/fs/bpf/compartment2 -- the
// boundary character check blocks that. realpath() also collapses any
// symlink components, so a /sys/fs/bpf/foo -> /sys/fs/bpf/compartment
// symlink escape resolves the candidate to the real /sys/fs/bpf/foo
// before comparison and is rejected.
//
// Returns:
//   1 -- candidate accepted; cand_out is the canonical form to operate on
//   0 -- refused gracefully (caller surfaces non-zero exit, leaves target intact)
//  -1 -- hard error (caller surfaces non-zero exit)
//
// When `requested` is NULL we resolve PIN_ROOT into both root_out and
// cand_out and report "nothing to do" if PIN_ROOT does not exist; that
// is the no-arg --unpin idiom.
static int unpin_resolve(const char *requested,
			 char *root_out, size_t root_sz,
			 char *cand_out, size_t cand_sz)
{
	if (!realpath(PIN_ROOT, root_out)) {
		if (errno == ENOENT) {
			fprintf(stderr,
				"[unpin] %s does not exist; nothing to do.\n",
				PIN_ROOT);
			return 0;
		}
		fprintf(stderr, "realpath %s: %s\n",
			PIN_ROOT, strerror(errno));
		return -1;
	}
	if (strlen(root_out) >= root_sz) {
		fprintf(stderr, "unpin: canonical root too long\n");
		return -1;
	}

	if (!requested) {
		if (strlen(root_out) >= cand_sz) {
			fprintf(stderr, "unpin: canonical path too long\n");
			return -1;
		}
		strcpy(cand_out, root_out);
		return 1;
	}

	if (requested[0] != '/') {
		fprintf(stderr,
			"unpin %s: refusing; path must be absolute.\n",
			requested);
		return 0;
	}

	if (!realpath(requested, cand_out)) {
		fprintf(stderr, "unpin %s: realpath: %s.\n",
			requested, strerror(errno));
		return 0;
	}
	if (strlen(cand_out) >= cand_sz) {
		fprintf(stderr, "unpin: canonical candidate too long\n");
		return -1;
	}

	size_t rlen = strlen(root_out);
	if (strcmp(cand_out, root_out) == 0)
		return 1;
	if (strncmp(cand_out, root_out, rlen) == 0 && cand_out[rlen] == '/')
		return 1;

	fprintf(stderr,
		"unpin %s: refusing; resolves to %s which is outside %s.\n",
		requested, cand_out, root_out);
	return 0;
}

// Collect the prog_ids referenced by the pinned link files under
// <links_dir>. Reads each KNOWN_LINK_NAMES entry via bpf_obj_get() +
// bpf_obj_get_info_by_fd(struct bpf_link_info) BEFORE the caller
// unlinks the pin files. ENOENT on individual files is treated as
// "already unpinned" and skipped. Any other I/O error is hard-fail.
//
// On success *nids holds the count of unique prog_ids written into
// ids[]; caller-supplied capacity is passed in via *nids. Used by
// --unpin to derive a precise drain post-condition: the drain only
// waits for THESE prog_ids to disappear, so a third party that has
// loaded a program named comp_inode_unlink in parallel (different
// prog_id) cannot wedge our drain wait.
//
// Returns 0 on success, -1 on hard error.
static int collect_link_prog_ids(const char *links_dir,
				  __u32 *ids, size_t *nids)
{
	size_t cap = *nids;
	size_t out = 0;
	for (size_t i = 0; i < N_KNOWN_LINK_NAMES; i++) {
		char path[PATH_MAX];
		if (snprintf(path, sizeof(path), "%s/%s", links_dir,
			     KNOWN_LINK_NAMES[i]) >= (int)sizeof(path)) {
			fprintf(stderr, "drain: path too long: %s/%s\n",
				links_dir, KNOWN_LINK_NAMES[i]);
			return -1;
		}
		int fd = bpf_obj_get(path);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			fprintf(stderr,
				"drain: bpf_obj_get %s: %s; cannot prove --unpin drain.\n",
				path, strerror(errno));
			return -1;
		}
		struct bpf_link_info info = {};
		__u32 info_len = sizeof(info);
		if (bpf_obj_get_info_by_fd(fd, &info, &info_len) < 0) {
			fprintf(stderr,
				"drain: bpf_obj_get_info_by_fd %s: %s; cannot prove --unpin drain.\n",
				path, strerror(errno));
			close(fd);
			return -1;
		}
		close(fd);
		if (info.prog_id == 0)
			continue;
		int seen = 0;
		for (size_t k = 0; k < out; k++) {
			if (ids[k] == info.prog_id) {
				seen = 1;
				break;
			}
		}
		if (seen)
			continue;
		if (out >= cap) {
			fprintf(stderr,
				"drain: link prog_id capacity (%zu) exceeded\n",
				cap);
			return -1;
		}
		ids[out++] = info.prog_id;
	}
	*nids = out;
	return 0;
}

// Block until the kernel has released the specific BPF programs
// whose prog_ids we collected from the pinned link files. Removing a
// bpffs pin only drops the kernel-side refcount; the actual link /
// program teardown runs on a workqueue with RCU grace periods. With the
// counter map pins added, teardown takes longer (more kobjs to
// free) and can exceed the 30s budget used by tests/pin-regression.sh's
// wait_for_kernel_drain. Making --unpin synchronous gives operators a
// strong post-condition: when this returns 0, no enforcement remains
// for any compartment-bpf program we pinned. Polled because the kernel
// has no waitable handle for this.
//
// Keying on the exact prog_ids (not on a program-name table) closes the
// last false-red surface in --unpin: a third party who loads a program
// with one of our section names — accidentally or maliciously — does
// not share our prog_id, so we never wait on theirs. nids==0 means we
// found no pinned link files to begin with (nothing to drain).
//
// Returns 0 on full drain, -1 on timeout or hard error. Caller may
// proceed regardless; the calls used here (bpf_prog_get_fd_by_id +
// bpf_obj_get_info_by_fd) require CAP_BPF / CAP_SYS_ADMIN, which the
// caller already had to pin.
static int wait_program_drain(const __u32 *ids, size_t nids, int timeout_ms)
{
	const int poll_ms = 100;
	int waited = 0;

	if (nids == 0)
		return 0;

	for (;;) {
		int alive = 0;
		__u32 alive_first = 0;
		for (size_t i = 0; i < nids; i++) {
			int fd = bpf_prog_get_fd_by_id(ids[i]);
			if (fd < 0) {
				// ENOENT: program already gone — that
				// individual id is drained.
				if (errno == ENOENT)
					continue;
				fprintf(stderr,
					"warn: bpf_prog_get_fd_by_id(%u): %s; cannot prove --unpin drain.\n",
					ids[i], strerror(errno));
				return -1;
			}
			close(fd);
			if (alive == 0)
				alive_first = ids[i];
			alive++;
		}
		if (alive == 0)
			return 0;
		if (waited >= timeout_ms) {
			fprintf(stderr,
				"warn: %d compartment-bpf prog(s) (first id=%u) still loaded after %dms drain wait; kernel deferred-free has not completed.\n",
				alive, alive_first, timeout_ms);
			return -1;
		}
		usleep((useconds_t)poll_ms * 1000);
		waited += poll_ms;
	}
}

// Pin the two deny-side counter maps under PIN_ROOT/maps. Called
// alongside pin_links() when --pin is set. The kernel keeps the maps
// alive while the pins exist, so userspace can sum them after the
// loader exits via `compartment-bpf --stats`. Failure rolls back the
// link pins via the caller; we unpin our own partial state here.
static int pin_counter_maps(struct compartment_bpf *skel)
{
	const struct {
		const char *name;
		struct bpf_map *map;
	} entries[] = {
		{ "deny_total",           skel->maps.deny_total },
		{ "audit_drop_total",     skel->maps.audit_drop_total },
		{ "actor_mismatch_total", skel->maps.actor_mismatch_total },
		/* v0.4 strict-launch-marker counters + state maps */
		{ "strict_launch_missing_total",      skel->maps.strict_launch_missing_total },
		{ "strict_launch_allowed_total",      skel->maps.strict_launch_allowed_total },
		{ "marker_set_total",                  skel->maps.marker_set_total },
		{ "marker_clear_foreign_exec_total",   skel->maps.marker_clear_foreign_exec_total },
		{ "marker_copy_fork_total",            skel->maps.marker_copy_fork_total },
		{ "marker_stale_generation_total",     skel->maps.marker_stale_generation_total },
		{ "prctl_set_mm_exe_file_denied_total", skel->maps.prctl_set_mm_exe_file_denied_total },
		{ "ptrace_access_denied_total",        skel->maps.ptrace_access_denied_total },
		{ "ptrace_traceme_denied_total",       skel->maps.ptrace_traceme_denied_total },
		{ "launcher_to_actor",                 skel->maps.launcher_to_actor },
		{ "policy_state_map",                  skel->maps.policy_state_map },
		{ "abi_version_map",                   skel->maps.abi_version_map },
	};
	const size_t n = sizeof(entries) / sizeof(entries[0]);
	char (*done)[PATH_MAX] = calloc(n, sizeof(*done));
	size_t done_n = 0;

	if (!done) {
		fprintf(stderr, "pin maps: calloc rollback list: %s\n",
			strerror(errno));
		return -1;
	}

	if (ensure_dir(PIN_ROOT "/maps") < 0)
		goto err;

	for (size_t i = 0; i < n; i++) {
		char path[PATH_MAX];
		if (snprintf(path, sizeof(path), PIN_ROOT "/maps/%s",
		             entries[i].name) >= (int)sizeof(path)) {
			fprintf(stderr, "pin map %s: path too long\n",
				entries[i].name);
			goto err;
		}
		int err = bpf_map__pin(entries[i].map, path);
		if (err < 0) {
			fprintf(stderr, "pin map %s: %s\n", path,
				strerror(-err));
			goto err;
		}
		snprintf(done[done_n], PATH_MAX, "%s", path);
		done_n++;
	}

	fprintf(stderr, "[pin] " PIN_ROOT "/maps (v0.3 counters + v0.4 strict-launch state + v0.6 ABI version)\n");
	free(done);
	return 0;

err:
	for (size_t i = 0; i < done_n; i++)
		if (unlink(done[i]) < 0)
			fprintf(stderr, "warn: unlink %s: %s\n",
				done[i], strerror(errno));
	free(done);
	return -1;
}

// A v0 leftover pin at PIN_ROOT/maps/{sealed_inodes,
// sealed_dirs} with the old __u32 value shape (rather than struct
// seal_value — 88 bytes through v0.3, 96 bytes since v0.4) shadows
// our PIN_ROOT layout and is an attack
// surface even though we do not adopt pinned seal maps today.
// Surface the mismatch fail-closed at startup. Read-only; skip on
// ENOENT; -1 on shape mismatch with an explicit diagnostic.
static int check_one_pinned_seal_shape(const char *path)
{
	int fd = bpf_obj_get(path);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf(stderr,
			"pin-shape: open %s: %s\n",
			path, strerror(errno));
		return -1;
	}
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	if (bpf_obj_get_info_by_fd(fd, &info, &info_len) < 0) {
		fprintf(stderr,
			"pin-shape: info %s: %s\n",
			path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	if (info.key_size != sizeof(struct inode_key) ||
	    info.value_size != sizeof(struct seal_value)) {
		fprintf(stderr,
			"pin-shape: refusing to start — pinned map %s has the "
			"wrong shape (key=%u value=%u; expected key=%zu "
			"value=%zu = sizeof(struct seal_value)). This usually "
			"means a v0 deployment left a pinned __u32-valued seal "
			"map under PIN_ROOT. Unpin it explicitly (compartment-"
			"bpf --unpin %s) and retry. Fail-closed.\n",
			path, info.key_size, info.value_size,
			sizeof(struct inode_key),
			sizeof(struct seal_value), path);
		return -1;
	}
	return 0;
}

static int check_pinned_seal_map_shapes(void)
{
	if (check_one_pinned_seal_shape(PIN_ROOT "/maps/sealed_inodes") < 0)
		return -1;
	if (check_one_pinned_seal_shape(PIN_ROOT "/maps/sealed_dirs") < 0)
		return -1;
	return 0;
}

// --stats entry point. Read-only: opens the pinned counter maps via
// bpf_obj_get(), reads each as BPF_MAP_TYPE_PERCPU_ARRAY[0], sums values
// across libbpf_num_possible_cpus(), and prints the result on stdout.
// Exit 0 on success. Exit 2 with a stderr line if neither pin exists.
// Exit 1 on real errors (open succeeded but read failed, etc.).
static int read_pinned_counter(const char *path, __u64 *out)
{
	int fd = bpf_obj_get(path);
	if (fd < 0) {
		if (errno == ENOENT)
			return -2;
		fprintf(stderr, "open pinned %s: %s\n", path, strerror(errno));
		return -1;
	}
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	if (bpf_obj_get_info_by_fd(fd, &info, &info_len) < 0) {
		fprintf(stderr, "info pinned %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	if (info.type != BPF_MAP_TYPE_PERCPU_ARRAY ||
	    info.key_size != sizeof(__u32) ||
	    info.value_size != sizeof(__u64) ||
	    info.max_entries != 1) {
		fprintf(stderr,
			"pinned %s: unexpected map schema type=%u key=%u value=%u entries=%u\n",
			path, info.type, info.key_size, info.value_size,
			info.max_entries);
		close(fd);
		return -1;
	}
	int ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0) {
		fprintf(stderr, "libbpf_num_possible_cpus: %d\n", ncpus);
		close(fd);
		return -1;
	}
	__u64 *vals = calloc((size_t)ncpus, sizeof(*vals));
	if (!vals) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	__u32 key = 0;
	int err = bpf_map_lookup_elem(fd, &key, vals);
	if (err < 0) {
		fprintf(stderr, "lookup %s: %s\n", path, strerror(errno));
		free(vals);
		close(fd);
		return -1;
	}
	__u64 sum = 0;
	for (int i = 0; i < ncpus; i++)
		sum += vals[i];
	*out = sum;
	free(vals);
	close(fd);
	return 0;
}

static int freeze_seal_maps(struct compartment_bpf *skel)
{
	// Extend the freeze list to the v0.4
	// strict-launch maps + counters. Pre-fix, `launcher_to_actor`,
	// `policy_state_map`, and the 9 v0.4 counters were writable from
	// userspace — a CAP_BPF attacker on the same host could forge
	// `launcher_to_actor` entries, flip `policy_state_map.strict_loaded`
	// to 0 to silently disarm the five new LSM hooks' early-out, or
	// zero counters between deny event and audit collection.
	// `actor_marker_map` is BPF_MAP_TYPE_TASK_STORAGE which the kernel
	// does not allow to be frozen (per-task allocation); the markers
	// live in task storage and inherit the task's lifetime, not the
	// map's. The TASK_STORAGE escape hatch is explicitly out-of-scope
	// for the freeze gate per the SPEC §6.1 / §6.4 design.
	//
	// Listed in a table-driven shape so the _Static_assert below counts
	// entries and a future map addition without a matching freeze entry
	// fails to compile (symmetric gate).
	struct freeze_entry {
		const char *name;
		struct bpf_map *map;
	};
	const struct freeze_entry entries[] = {
		/* v0 / v0.1 seal map shapes */
		{ "sealed_inodes",                    skel->maps.sealed_inodes },
		{ "sealed_dirs",                      skel->maps.sealed_dirs },
		/* v0 counters — userspace reads only via bpf_map_lookup_elem;
		 * freezing blocks userspace writes, BPF-side (*v)++ still works. */
		{ "deny_total",                       skel->maps.deny_total },
		{ "audit_drop_total",                 skel->maps.audit_drop_total },
		/* actor-mismatch counter (v0.3) */
		{ "actor_mismatch_total",             skel->maps.actor_mismatch_total },
		/* v0.4 strict-launch state maps */
		{ "launcher_to_actor",                skel->maps.launcher_to_actor },
		{ "policy_state_map",                 skel->maps.policy_state_map },
		{ "abi_version_map",                  skel->maps.abi_version_map },
		/* v0.4 strict-launch counters */
		{ "strict_launch_missing_total",      skel->maps.strict_launch_missing_total },
		{ "strict_launch_allowed_total",      skel->maps.strict_launch_allowed_total },
		{ "marker_set_total",                 skel->maps.marker_set_total },
		{ "marker_clear_foreign_exec_total",  skel->maps.marker_clear_foreign_exec_total },
		{ "marker_copy_fork_total",           skel->maps.marker_copy_fork_total },
		{ "marker_stale_generation_total",    skel->maps.marker_stale_generation_total },
		{ "prctl_set_mm_exe_file_denied_total", skel->maps.prctl_set_mm_exe_file_denied_total },
		{ "ptrace_access_denied_total",       skel->maps.ptrace_access_denied_total },
		{ "ptrace_traceme_denied_total",      skel->maps.ptrace_traceme_denied_total },
	};
	const size_t n = sizeof(entries) / sizeof(entries[0]);
	/* Symmetric-gate assert: 5 v0/v0.3 + 11 v0.4 + 1 v0.6 = 17.
	 * If you add a freezable map to compartment.bpf.c without extending
	 * this table, the assert below catches it at build time. */
	_Static_assert(sizeof(entries) / sizeof(entries[0]) == 17,
		"freeze_seal_maps entry count drift (expected: 5 v0/v0.3 + 11 v0.4 + 1 v0.6 = 17)");

	for (size_t i = 0; i < n; i++) {
		int fd = bpf_map__fd(entries[i].map);
		if (fd < 0) {
			fprintf(stderr, "freeze %s: map fd unavailable\n",
				entries[i].name);
			return -1;
		}
		if (bpf_map_freeze(fd) < 0) {
			fprintf(stderr, "freeze %s: %s\n",
				entries[i].name, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int stats_action(void)
{
	// Extend --stats to surface the
	// v0.4 strict-launch counters in addition to the v0.3 baseline.
	// Pre-fix, an operator hitting a strict-launch deny had no
	// aggregate counter visibility via the documented operator tool;
	// SIEM integrations that scrape `--stats` were blind to
	// strict-launch enforcement. Mirror the v0.3 '?' fallback doctrine
	// — counters absent from the pin set print '?' (mixed-vintage
	// deployments) rather than failing the whole call.
	struct stats_entry {
		const char *name;
		__u64 v;
		int rc;
	};
	struct stats_entry entries[] = {
		/* v0.3 baseline */
		{ "deny_total",                       0, 0 },
		{ "audit_drop_total",                 0, 0 },
		{ "actor_mismatch_total",             0, 0 },
		/* v0.4 strict-launch counters */
		{ "strict_launch_missing_total",      0, 0 },
		{ "strict_launch_allowed_total",      0, 0 },
		{ "marker_set_total",                 0, 0 },
		{ "marker_clear_foreign_exec_total",  0, 0 },
		{ "marker_copy_fork_total",           0, 0 },
		{ "marker_stale_generation_total",    0, 0 },
		{ "prctl_set_mm_exe_file_denied_total", 0, 0 },
		{ "ptrace_access_denied_total",       0, 0 },
		{ "ptrace_traceme_denied_total",      0, 0 },
	};
	const size_t n = sizeof(entries) / sizeof(entries[0]);
	int all_missing = 1;
	int any_io_err = 0;
	char path[PATH_MAX];

	for (size_t i = 0; i < n; i++) {
		if (snprintf(path, sizeof(path), "%s/maps/%s", PIN_ROOT,
			     entries[i].name) >= (int)sizeof(path)) {
			fprintf(stderr, "[stats] path too long: %s\n",
				entries[i].name);
			return 1;
		}
		entries[i].rc = read_pinned_counter(path, &entries[i].v);
		if (entries[i].rc != -2)
			all_missing = 0;
		if (entries[i].rc == -1)
			any_io_err = 1;
	}

	if (all_missing) {
		fprintf(stderr, "[stats] no pinned counters found\n");
		return 2;
	}
	if (any_io_err)
		return 1;

	printf("[stats]");
	for (size_t i = 0; i < n; i++) {
		if (entries[i].rc == 0)
			printf(" %s=%llu", entries[i].name,
				(unsigned long long)entries[i].v);
		else
			printf(" %s=?", entries[i].name);
	}
	printf("\n");
	return 0;
}

// --unpin entry point. `requested` is the operator-supplied path or
// NULL for "operate on PIN_ROOT". This function does no BPF load/attach;
// it only enumerates known pin files under PIN_ROOT and removes them. It
// is invoked from main() before any BPF setup and main() returns its
// exit code directly. Cross-process cleanup: the kernel keeps a pinned
// LSM link alive as long as the bpffs file exists, so unlink()ing the
// pin file decrements the kernel's reference and tears down enforcement
// once no other holder remains. The seal maps follow the same shape.
// Synchronous-drain wrapper used after root unpin and after scoped unpin
// operations that remove link pins. The root/link contract is that
// when `--unpin` returns 0 after link removal, no compartment-bpf
// enforcement remains; honouring that contract means propagating drain
// timeout to the exit code. ids[] / nids identify the specific
// prog_ids collected from the pin files BEFORE they were unlinked;
// see collect_link_prog_ids() for rationale. Returns 0 on full drain,
// 1 on timeout.
static int unpin_drain_or_warn(const __u32 *ids, size_t nids)
{
	if (wait_program_drain(ids, nids, 60000) < 0) {
		fprintf(stderr,
			"[unpin] kernel deferred-free did not complete within 60s; "
			"enforcement may persist briefly. Returning nonzero so "
			"this is not silently misread as a clean drain.\n");
		return 1;
	}
	return 0;
}

// Unpin passphrase (Argon2id sentinel, SPEC §7.2 Shape A).
//
// Optional operator-supplied passphrase gates --unpin. This is a
// **credential gate / accidental-unpin guard**, NOT a root-of-trust
// against unrestricted privileged root: an attacker with CAP_BPF /
// CAP_SYS_ADMIN on the box can remove the sentinel file (it lives on
// tmpfs at /run/compartment-bpf/unpin-sentinel) and tear pins down via
// `bpftool prog detach`. The honest threat model lives in HOWTO.md §3:
// the gate raises cost against a non-CAP_BPF-restricted
// root attacker (setuid binary, confined-container root, dropped-cap
// daemon) and provides offline-brute-force resistance via Argon2id work
// factor on a captured sentinel. The passphrase travels in via
// COMPARTMENT_BPF_PASSPHRASE env at --pin time and at --unpin time; if
// --unpin is run interactively the passphrase is prompted via getpass()
// (no terminal echo). If no passphrase was provided at pin time, no
// sentinel is written and --unpin runs as in v0.x (legacy path
// preserved; backward compatible).
//
// libsodium's crypto_pwhash_str is Argon2id by default
// (crypto_pwhash_ALG_DEFAULT) with crypto_pwhash_STRBYTES (=128) output.
// We use OPSLIMIT_INTERACTIVE / MEMLIMIT_INTERACTIVE — a one-time unpin
// gate is not bulk-pw-hashing, so the interactive params (~70ms +
// 64 MiB) are right-sized.
//
// Sentinel storage: PIN_ROOT lives on bpffs which
// rejects regular-file creation; the sentinel goes to /run/compartment-
// bpf/unpin-sentinel (tmpfs, same boot lifecycle as the pins).
//
// Audit emission on verify-fail: the kernel audit
// ringbuf is producer-side BPF-only — userspace cannot push into it via
// the standard libbpf API. We emit the same logical event via syslog
// (LOG_AUTHPRIV / LOG_WARNING) plus a structured stderr line, with the
// ACTION_DENY_UNPIN_AUTH_FAIL action code (=7) preserved so a downstream
// log aggregator can correlate against the kernel-side ACTION_DENY_*.

// Read passphrase from env or interactive prompt. Returns:
//   * malloc'd buffer on success; caller must sodium_munlock + free.
//   * NULL on no-passphrase-available (env unset + non-tty stdin).
// Errors (alloc fail, getpass fail) cause a stderr message + NULL.
// The buffer is locked with sodium_mlock to keep it out of swap.
static char *ed11_read_passphrase(const char *prompt)
{
	char *env = getenv("COMPARTMENT_BPF_PASSPHRASE");
	if (env && *env) {
		size_t n = strlen(env);
		if (n > 4096) {
			fprintf(stderr,
				"ed11: COMPARTMENT_BPF_PASSPHRASE too long (>4096 bytes)\n");
			// Scrub the env-var string even on the
			// too-long path before bailing.
			sodium_memzero(env, n);
			(void)unsetenv("COMPARTMENT_BPF_PASSPHRASE");
			return NULL;
		}
		char *buf = malloc(n + 1);
		if (!buf) {
			fprintf(stderr, "ed11: passphrase malloc: %s\n", strerror(errno));
			sodium_memzero(env, n);
			(void)unsetenv("COMPARTMENT_BPF_PASSPHRASE");
			return NULL;
		}
		if (sodium_mlock(buf, n + 1) < 0) {
			// mlock failure is operator-visible but non-fatal; the
			// passphrase still works, just not pin-locked in RAM.
			fprintf(stderr, "ed11: warn: sodium_mlock failed: %s\n",
				strerror(errno));
		}
		memcpy(buf, env, n);
		buf[n] = '\0';
		// The env-var string lives in the process's environ[] block (heap or
		// initial stack). /proc/self/environ, ptrace, and a core
		// dump all read it. sodium_mlock on the malloc'd copy is
		// theater if the original string remains addressable.
		// Zero it in place and unsetenv() to remove it from
		// getenv()'s table. The race window between fork+exec and
		// this scrub is documented in HOWTO §3.1 (use a passphrase
		// agent / runtime-injected file for shells that may be
		// inspected mid-startup).
		sodium_memzero(env, n);
		(void)unsetenv("COMPARTMENT_BPF_PASSPHRASE");
		return buf;
	}
	if (!isatty(STDIN_FILENO)) {
		// No env, no tty — caller path will treat this as "no
		// passphrase available" and act accordingly.
		return NULL;
	}
	// getpass(3) is deprecated but POSIX-defined; the alternative is a
	// termios echo-off dance. getpass returns a pointer into a static
	// buffer — copy out into mlock'd memory before we hand back.
	char *p = getpass(prompt);
	if (!p) {
		fprintf(stderr, "ed11: getpass failed: %s\n", strerror(errno));
		return NULL;
	}
	size_t n = strlen(p);
	char *buf = malloc(n + 1);
	if (!buf) {
		fprintf(stderr, "ed11: passphrase malloc: %s\n", strerror(errno));
		// Zero the getpass static buffer before returning.
		sodium_memzero(p, n);
		return NULL;
	}
	if (sodium_mlock(buf, n + 1) < 0) {
		fprintf(stderr, "ed11: warn: sodium_mlock failed: %s\n",
			strerror(errno));
	}
	memcpy(buf, p, n);
	buf[n] = '\0';
	// Zero the getpass static buffer; the user copy is in `buf` now.
	sodium_memzero(p, n);
	return buf;
}

static void ed11_wipe_passphrase(char *buf)
{
	if (!buf)
		return;
	size_t n = strlen(buf);
	// Zero n+1 so the trailing NUL slot is
	// also wiped — same width as the malloc + sodium_mlock + the
	// sodium_munlock below. Off-by-one let one byte of clear-text
	// linger across free(); the rounding is free.
	sodium_memzero(buf, n + 1);
	(void)sodium_munlock(buf, n + 1);
	free(buf);
}

// Write the Argon2id hash of `pass` to SENTINEL_PATH. Returns 0 on
// success, -1 on error. The file is created O_NOFOLLOW|O_CREAT|O_EXCL,
// mode 0600, root-owned (mode + uid verified post-write fail-closed).
// Caller must be euid 0; we don't bother checking — this is called from
// the --pin path which already requires root for BPF LSM load.
static int ed11_write_sentinel(const char *pass)
{
	if (sodium_init() < 0) {
		fprintf(stderr, "ed11: sodium_init failed\n");
		return -1;
	}
	// Idempotently ensure SENTINEL_DIR exists with mode 0700, root:root.
	struct stat dst;
	if (lstat(SENTINEL_DIR, &dst) < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "ed11: lstat %s: %s\n",
				SENTINEL_DIR, strerror(errno));
			return -1;
		}
		if (mkdir(SENTINEL_DIR, 0700) < 0 && errno != EEXIST) {
			fprintf(stderr, "ed11: mkdir %s: %s\n",
				SENTINEL_DIR, strerror(errno));
			return -1;
		}
		if (lstat(SENTINEL_DIR, &dst) < 0) {
			fprintf(stderr, "ed11: lstat after mkdir %s: %s\n",
				SENTINEL_DIR, strerror(errno));
			return -1;
		}
	}
	if (!S_ISDIR(dst.st_mode) || dst.st_uid != 0 ||
	    (dst.st_mode & 0777) != 0700) {
		fprintf(stderr,
			"ed11: %s has wrong type/owner/mode (uid=%u mode=0%o); refusing to write sentinel\n",
			SENTINEL_DIR, (unsigned)dst.st_uid,
			(unsigned)(dst.st_mode & 0777));
		return -1;
	}
	// Pre-unlink any stale sentinel so O_EXCL fires on a clean slate.
	// Stale sentinel from a crashed peer should not block a fresh pin;
	// the lock around --pin excludes concurrent --pin so we
	// own this filesystem state for the duration of the pin window.
	if (unlink(SENTINEL_PATH) < 0 && errno != ENOENT) {
		fprintf(stderr, "ed11: unlink stale sentinel %s: %s\n",
			SENTINEL_PATH, strerror(errno));
		return -1;
	}
	// Zero-init: if crypto_pwhash_str fails before writing the buffer
	// the early return below skips any read; the sodium_memzero in
	// later cleanup branches is best-effort. Reviewer DiD on top of
	// the existing return-without-read path.
	char hash[crypto_pwhash_STRBYTES] = {};
	if (crypto_pwhash_str(hash, pass, strlen(pass),
			      crypto_pwhash_OPSLIMIT_INTERACTIVE,
			      crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
		fprintf(stderr, "ed11: crypto_pwhash_str failed (out of memory?)\n");
		// Defense-in-depth zero on this
		// early-return path. crypto_pwhash_str may have partially
		// written before failing; symmetric with the explicit
		// sodium_memzero(hash) on every other return path.
		sodium_memzero(hash, sizeof(hash));
		return -1;
	}
	int fd = open(SENTINEL_PATH,
		      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		      0600);
	if (fd < 0) {
		fprintf(stderr, "ed11: open %s: %s\n",
			SENTINEL_PATH, strerror(errno));
		sodium_memzero(hash, sizeof(hash));
		return -1;
	}
	size_t off = 0;
	size_t len = strlen(hash);
	while (off < len) {
		ssize_t w = write(fd, hash + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "ed11: write %s: %s\n",
				SENTINEL_PATH, strerror(errno));
			close(fd);
			(void)unlink(SENTINEL_PATH);
			sodium_memzero(hash, sizeof(hash));
			return -1;
		}
		off += (size_t)w;
	}
	// Verify the persisted mode + owner before reporting success.
	// fstat (not lstat) so we see the file we just wrote, not any
	// symlink chicanery (O_NOFOLLOW already excluded that anyway).
	struct stat fst;
	if (fstat(fd, &fst) < 0) {
		fprintf(stderr, "ed11: fstat sentinel: %s\n", strerror(errno));
		close(fd);
		(void)unlink(SENTINEL_PATH);
		sodium_memzero(hash, sizeof(hash));
		return -1;
	}
	close(fd);
	sodium_memzero(hash, sizeof(hash));
	if (fst.st_uid != 0 || (fst.st_mode & 0777) != 0600 ||
	    !S_ISREG(fst.st_mode)) {
		fprintf(stderr,
			"ed11: sentinel post-write check failed (uid=%u mode=0%o type=0%o); unlinking\n",
			(unsigned)fst.st_uid,
			(unsigned)(fst.st_mode & 0777),
			(unsigned)(fst.st_mode & S_IFMT));
		(void)unlink(SENTINEL_PATH);
		return -1;
	}
	fprintf(stderr, "[pin] %s sentinel=yes (Argon2id; %zu bytes)\n",
		SENTINEL_PATH, len);
	return 0;
}

// Pin-time entry: if a passphrase is in env (or stdin is a tty), write
// the sentinel. No passphrase available → no sentinel, legacy behaviour
// preserved. Returns 0 on success (with or without sentinel), -1 if a
// sentinel was attempted and failed (caller should abort the pin).
static int ed11_pin_maybe_write_sentinel(void)
{
	char *pass = ed11_read_passphrase("compartment-bpf unpin passphrase (for --unpin gating; press enter to skip): ");
	if (!pass) {
		fprintf(stderr,
			"[pin] no unpin passphrase configured (legacy mode; --unpin will not require auth)\n");
		return 0;
	}
	if (strlen(pass) == 0) {
		// User just hit enter on the interactive prompt — treat
		// identically to "no passphrase" (legacy path).
		ed11_wipe_passphrase(pass);
		fprintf(stderr,
			"[pin] empty passphrase entered; treating as legacy mode (no sentinel)\n");
		return 0;
	}
	int rc = ed11_write_sentinel(pass);
	ed11_wipe_passphrase(pass);
	return rc;
}

// Emit a userspace-side audit event for ACTION_DENY_UNPIN_AUTH_FAIL.
// The kernel audit ringbuf cannot be produced into from
// userspace via the standard libbpf API. We log the structured fields
// (ts_ns, pid, uid, comm, action, dev, ino) via syslog
// (LOG_AUTHPRIV / LOG_WARNING) AND on stderr in a parseable format so a
// downstream log aggregator can correlate ACTION_DENY_UNPIN_AUTH_FAIL=7
// events alongside the kernel-side ACTION_DENY_* stream.
static void ed11_emit_unpin_auth_fail(__u64 dev, __u64 ino)
{
	struct timespec ts = {};
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	unsigned long long ts_ns = (unsigned long long)ts.tv_sec * 1000000000ULL
				 + (unsigned long long)ts.tv_nsec;
	unsigned pid = (unsigned)getpid();
	unsigned ppid = (unsigned)getppid();
	unsigned uid = (unsigned)getuid();
	char comm[16] = {};
	int cfd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
	if (cfd >= 0) {
		ssize_t r = read(cfd, comm, sizeof(comm) - 1);
		if (r > 0) {
			// strip trailing newline
			while (r > 0 && (comm[r-1] == '\n' || comm[r-1] == '\0'))
				comm[--r] = '\0';
		}
		close(cfd);
	}
	// Emit in the same `[audit] <ACTION> ts=… pid=…
	// ppid=… uid=… comm=… dev=… ino=…` format as the kernel-side
	// audit_handler legacy (no-caller) branch. action_name() now covers
	// case 7 so SIEM consumers see DENY_UNPIN_AUTH_FAIL by symbol.
	fprintf(stderr,
		"[audit] %s ts=%llu pid=%u ppid=%u uid=%u comm=%s dev=%llu ino=%llu\n",
		action_name(ACTION_DENY_UNPIN_AUTH_FAIL),
		ts_ns, pid, ppid, uid, comm,
		(unsigned long long)dev, (unsigned long long)ino);
	openlog("compartment-bpf", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
	syslog(LOG_WARNING,
	       "%s pid=%u ppid=%u uid=%u comm=%s dev=%llu ino=%llu",
	       action_name(ACTION_DENY_UNPIN_AUTH_FAIL),
	       pid, ppid, uid, comm,
	       (unsigned long long)dev, (unsigned long long)ino);
	closelog();
}

// Unpin-time gate. Returns:
//    0  → no sentinel, or sentinel present and passphrase verified → proceed
//    1  → sentinel exists, verify failed or no passphrase available → abort
static int ed11_unpin_authgate(void)
{
	// The previous structure was lstat(SENTINEL_PATH, &st) →
	// open(SENTINEL_PATH, O_NOFOLLOW) →
	// read(fd). Two separate path resolutions across a security
	// decision: a root attacker between the lstat() and the open()
	// could swap the file, so the audit dev/ino emitted from `st`
	// would identify a different inode than the one we actually read.
	// Asymmetric with the WRITE path (ed11_write_sentinel) which
	// correctly uses fstat-through-fd. Mirror the write-path
	// open-then-fstat discipline here: one path resolution, fstat()
	// against the fd, validate, read.
	int fd = open(SENTINEL_PATH, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;  // legacy pin (no passphrase configured)
		fprintf(stderr, "ed11: open sentinel %s: %s\n",
			SENTINEL_PATH, strerror(errno));
		return 1;
	}
	struct stat st;
	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "ed11: fstat sentinel: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & 0777) != 0600) {
		fprintf(stderr,
			"ed11: sentinel %s has wrong type/owner/mode (uid=%u mode=0%o type=0%o); refusing unpin fail-closed\n",
			SENTINEL_PATH, (unsigned)st.st_uid,
			(unsigned)(st.st_mode & 0777),
			(unsigned)(st.st_mode & S_IFMT));
		ed11_emit_unpin_auth_fail((__u64)st.st_dev, (__u64)st.st_ino);
		close(fd);
		return 1;
	}
	if (sodium_init() < 0) {
		fprintf(stderr, "ed11: sodium_init failed\n");
		close(fd);
		return 1;
	}
	char hash[crypto_pwhash_STRBYTES] = {};
	ssize_t r;
	do {
		r = read(fd, hash, sizeof(hash) - 1);
	} while (r < 0 && errno == EINTR);
	close(fd);
	if (r <= 0) {
		fprintf(stderr, "ed11: read sentinel: %s\n",
			r == 0 ? "empty" : strerror(errno));
		ed11_emit_unpin_auth_fail((__u64)st.st_dev, (__u64)st.st_ino);
		return 1;
	}
	hash[r] = '\0';
	char *pass = ed11_read_passphrase("compartment-bpf unpin passphrase: ");
	if (!pass) {
		fprintf(stderr,
			"ed11: --unpin requires COMPARTMENT_BPF_PASSPHRASE env or a tty stdin (sentinel present at %s)\n",
			SENTINEL_PATH);
		ed11_emit_unpin_auth_fail((__u64)st.st_dev, (__u64)st.st_ino);
		sodium_memzero(hash, sizeof(hash));
		return 1;
	}
	int verify = crypto_pwhash_str_verify(hash, pass, strlen(pass));
	ed11_wipe_passphrase(pass);
	sodium_memzero(hash, sizeof(hash));
	if (verify != 0) {
		ed11_emit_unpin_auth_fail((__u64)st.st_dev, (__u64)st.st_ino);
		fprintf(stderr,
			"ed11: --unpin: passphrase verify failed (ACTION_DENY_UNPIN_AUTH_FAIL); refusing.\n");
		return 1;
	}
	return 0;
}

// Post-unpin cleanup: best-effort remove the sentinel after a successful
// authgate + unpin pass. Sentinel lifecycle binds to pin lifecycle.
static void ed11_unpin_sentinel_unlink(void)
{
	if (unlink(SENTINEL_PATH) < 0 && errno != ENOENT) {
		fprintf(stderr,
			"ed11: warn: post-unpin sentinel cleanup %s: %s\n",
			SENTINEL_PATH, strerror(errno));
	}
}

static int unpin_action(const char *requested)
{
	if (ensure_bpffs("/sys/fs/bpf") < 0)
		return 1;

	// Refuse to race a concurrent --pin / --unpin against
	// the same PIN_ROOT. Lock held for the entire enumerate-and-unlink
	// window. The function has many early returns; rather than thread
	// pin_lifecycle_unlock() through each, we rely on OS process-exit
	// to release the fd (unpin_action is only ever called from main()
	// which returns the rc to the OS). The lock auto-releases on
	// process exit so a SIGKILL'd peer does not strand the lock.
	int lock_fd = pin_lifecycle_lock("--unpin");
	if (lock_fd < 0)
		return 1;
	(void)lock_fd;  /* held until process exits; release-on-close. */

	// The unpin authgate runs INSIDE the pin lifecycle lock to
	// close a TOCTOU window where operator A authgates against tree T1
	// then operator B replaces the tree (different passphrase) before
	// A's unpin runs. Running auth under the lock binds the verified
	// passphrase to the tree the unpin then enumerates. Cost: a peer
	// typing a wrong passphrase parks the lock for the prompt window;
	// acceptable for a fail-closed operator action. (Previous note: the
	// gate ran pre-lock to avoid lock-parking during passphrase entry;
	// correctness wins.)
	if (ed11_unpin_authgate() != 0)
		return 1;

	char root[PATH_MAX];
	char cand[PATH_MAX];
	int rc = unpin_resolve(requested, root, sizeof(root),
			       cand, sizeof(cand));
	if (rc < 0)
		return 1;
	if (rc == 0)
		return requested ? 1 : 0;

	int removed = 0;
	int unknown = 0;
	// Reserved capacity for collected prog_ids. N_KNOWN_LINK_NAMES is the
	// hard upper bound — one prog per link pin. Stack-sized array keeps
	// the drain path allocation-free.
	__u32 link_prog_ids[64];
	_Static_assert(sizeof(link_prog_ids)/sizeof(link_prog_ids[0]) >= 21,
		       "link_prog_ids[] must hold every KNOWN_LINK_NAMES prog_id (currently 21)");
	size_t n_link_prog_ids;

	if (strcmp(cand, root) == 0) {
		char p[PATH_MAX];
		if (snprintf(p, sizeof(p), "%s/links", root)
		    >= (int)sizeof(p)) {
			fprintf(stderr, "unpin: links path too long\n");
			return 1;
		}
		// Collect prog_ids BEFORE the unlink — once the pin is gone the
		// kernel may have started teardown, but bpf_prog_get_fd_by_id()
		// still sees the prog until the workqueue runs. Doing this in
		// the opposite order would race the kernel's deferred-free.
		n_link_prog_ids =
			sizeof(link_prog_ids) / sizeof(link_prog_ids[0]);
		if (collect_link_prog_ids(p, link_prog_ids,
					   &n_link_prog_ids) < 0)
			return 1;
		if (sweep_known(p, KNOWN_LINK_NAMES, N_KNOWN_LINK_NAMES,
				&removed, &unknown) < 0)
			return 1;
		if (snprintf(p, sizeof(p), "%s/maps", root)
		    >= (int)sizeof(p)) {
			fprintf(stderr, "unpin: maps path too long\n");
			return 1;
		}
		if (sweep_known(p, KNOWN_MAP_NAMES, N_KNOWN_MAP_NAMES,
				&removed, &unknown) < 0)
			return 1;

		fprintf(stderr,
			"[unpin] %s preserved; %d pin%s removed, %d unknown left intact.\n",
			root, removed, removed == 1 ? "" : "s", unknown);
		// Root unpin tore the whole pin tree down, so the
		// passphrase sentinel is no longer load-bearing. Subdir/leaf
		// unpins below don't reach this; they leave the sentinel in
		// place because some pins remain.
		ed11_unpin_sentinel_unlink();
		// Post-condition: when this returns 0, the specific compartment-bpf
		// prog_ids we collected from the pin files are all gone
		// Drain timeout propagates to a nonzero exit
		// if the drain times out.
		return unpin_drain_or_warn(link_prog_ids, n_link_prog_ids);
	}

	// Candidate is strictly inside root: subdir or leaf.
	char links_dir[PATH_MAX];
	char maps_dir[PATH_MAX];
	if (snprintf(links_dir, sizeof(links_dir), "%s/links", root)
	    >= (int)sizeof(links_dir) ||
	    snprintf(maps_dir, sizeof(maps_dir), "%s/maps", root)
	    >= (int)sizeof(maps_dir)) {
		fprintf(stderr, "unpin: subdir path too long\n");
		return 1;
	}

	struct stat st;
	if (lstat(cand, &st) < 0) {
		fprintf(stderr, "unpin %s: lstat: %s.\n",
			cand, strerror(errno));
		return 1;
	}

	if (S_ISDIR(st.st_mode)) {
		const char *const *table = NULL;
		size_t n = 0;
		int removed_links = 0;
		if (strcmp(cand, links_dir) == 0) {
			table = KNOWN_LINK_NAMES;
			n = N_KNOWN_LINK_NAMES;
			removed_links = 1;
		} else if (strcmp(cand, maps_dir) == 0) {
			table = KNOWN_MAP_NAMES;
			n = N_KNOWN_MAP_NAMES;
		} else {
			fprintf(stderr,
				"unpin %s: refusing; only %s and %s are known directories under %s.\n",
				cand, links_dir, maps_dir, root);
			return 1;
		}
		// Collect link prog_ids BEFORE sweep_known when this is the
		// links directory; map-dir unpin has nothing to drain.
		n_link_prog_ids =
			sizeof(link_prog_ids) / sizeof(link_prog_ids[0]);
		if (removed_links) {
			if (collect_link_prog_ids(cand, link_prog_ids,
						   &n_link_prog_ids) < 0)
				return 1;
		} else {
			n_link_prog_ids = 0;
		}
		if (sweep_known(cand, table, n, &removed, &unknown) < 0)
			return 1;
		fprintf(stderr,
			"[unpin] %s: %d pin%s removed, %d unknown left intact.\n",
			cand, removed, removed == 1 ? "" : "s", unknown);
		// Path-specific unpin must honour the same drain contract as
		// root unpin when link pins were removed. Map-only cleanup
		// does not detach enforcement, so requiring a global drain
		// there would make valid `--unpin .../maps` calls fail until
		// the still-pinned links are also removed.
		return removed_links
			? unpin_drain_or_warn(link_prog_ids, n_link_prog_ids)
			: 0;
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr,
			"unpin %s: refusing; not a regular pin file.\n", cand);
		return 1;
	}

	// Leaf file: validate parent is a known directory and name is known.
	char parent[PATH_MAX];
	if (snprintf(parent, sizeof(parent), "%s", cand) >= (int)sizeof(parent)) {
		fprintf(stderr, "unpin: parent path too long\n");
		return 1;
	}
	char *slash = strrchr(parent, '/');
	if (!slash || slash == parent) {
		fprintf(stderr, "unpin %s: cannot derive parent.\n", cand);
		return 1;
	}
	*slash = '\0';
	const char *leaf = slash + 1;

	const char *const *table = NULL;
	size_t n = 0;
	int removed_link = 0;
	if (strcmp(parent, links_dir) == 0) {
		table = KNOWN_LINK_NAMES;
		n = N_KNOWN_LINK_NAMES;
		removed_link = 1;
	} else if (strcmp(parent, maps_dir) == 0) {
		table = KNOWN_MAP_NAMES;
		n = N_KNOWN_MAP_NAMES;
	} else {
		fprintf(stderr,
			"unpin %s: refusing; %s is not a known pin directory.\n",
			cand, parent);
		return 1;
	}
	if (!name_in(leaf, table, n)) {
		fprintf(stderr,
			"warn: %s is not a known compartment-bpf pin; left intact.\n",
			cand);
		return 1;
	}
	// For a leaf link pin, look up its prog_id BEFORE unlinking. For a
	// leaf map pin, there is no enforcement-detach so no drain is owed.
	__u32 leaf_prog_id = 0;
	size_t n_leaf = 0;
	if (removed_link) {
		int fd = bpf_obj_get(cand);
		if (fd < 0) {
			fprintf(stderr,
				"drain: bpf_obj_get %s: %s; cannot prove --unpin drain.\n",
				cand, strerror(errno));
			return 1;
		}
		struct bpf_link_info linfo = {};
		__u32 linfo_len = sizeof(linfo);
		if (bpf_obj_get_info_by_fd(fd, &linfo, &linfo_len) < 0) {
			fprintf(stderr,
				"drain: bpf_obj_get_info_by_fd %s: %s; cannot prove --unpin drain.\n",
				cand, strerror(errno));
			close(fd);
			return 1;
		}
		close(fd);
		if (linfo.prog_id != 0) {
			leaf_prog_id = linfo.prog_id;
			n_leaf = 1;
		}
	}
	if (unlink(cand) < 0) {
		fprintf(stderr, "unlink %s: %s\n", cand, strerror(errno));
		return 1;
	}
	fprintf(stderr, "[unpin] %s removed.\n", cand);
	// Leaf link unpin detaches enforcement and must satisfy the drain
	// contract. Leaf map unpin is scoped counter/state cleanup and can
	// succeed while enforcement intentionally remains via link pins.
	return removed_link ? unpin_drain_or_warn(&leaf_prog_id, n_leaf) : 0;
}

/* Implemented in compartment-observe.c */
extern int observe_main(int argc, char **argv);

// The inode_setattr LSM hook gained a leading `struct mnt_idmap *idmap` after
// kernel 6.8 (BTF func-proto vlen 2 -> 3). compartment.bpf.c ships two
// SEC("lsm/inode_setattr") wrappers (modern 3-arg + legacy 2-arg) over one
// shared body; exactly one matches the running kernel. Probe vmlinux BTF for
// the hook's arg count and autoload ONLY the matching wrapper, so the verifier
// never sees the wrong-shaped wrapper (which would fail with "func
// 'bpf_lsm_inode_setattr' doesn't have N-th argument"). Must run after
// __open() and before __load(). If BTF can't be read we fall back to the
// kernel version (uname) rather than blind-defaulting to modern — blind-modern
// would self-DoS exactly on the legacy target (Noble 6.8) this code exists for.
static int select_inode_setattr_variant(struct compartment_bpf *skel)
{
	bool modern;
	int decided = 0;
	struct btf *btf = btf__load_vmlinux_btf();
	if (btf) {
		__s32 id = btf__find_by_name_kind(btf, "bpf_lsm_inode_setattr",
		                                  BTF_KIND_FUNC);
		if (id >= 0) {
			const struct btf_type *fn = btf__type_by_id(btf, id);
			const struct btf_type *proto =
				fn ? btf__type_by_id(btf, fn->type) : NULL;
			// Guard the kind: btf_vlen is only meaningful on a FUNC_PROTO.
			if (proto && btf_kind(proto) == BTF_KIND_FUNC_PROTO) {
				modern = (btf_vlen(proto) >= 3);
				decided = 1;
			}
		}
		btf__free(btf);
	}
	if (!decided) {
		// BTF absent/unexpected: discriminate by kernel version. The
		// mnt_idmap arg was added to inode_setattr AFTER 6.8, so treat
		// <= 6.8 as legacy (2-arg). This is a best-effort fallback for the
		// rare BTF-less host; on a wrong guess the load fails the verifier
		// (fail-closed, clear message), never a silent mis-attach.
		struct utsname u;
		unsigned kmaj = 0, kmin = 0;
		if (uname(&u) == 0)
			sscanf(u.release, "%u.%u", &kmaj, &kmin);
		modern = !(kmaj < 6 || (kmaj == 6 && kmin <= 8));
		fprintf(stderr,
			"[probe] warn: vmlinux BTF unavailable; picked inode_setattr "
			"variant from uname %u.%u (%s).\n",
			kmaj, kmin, modern ? "modern" : "legacy");
	}

	int r1 = bpf_program__set_autoload(skel->progs.comp_inode_setattr, modern);
	int r2 = bpf_program__set_autoload(skel->progs.comp_inode_setattr_legacy,
	                                   !modern);
	if (r1 || r2) {
		// Abort HERE with the precise cause rather than letting both wrappers
		// stay enabled and surface later as a cryptic verifier reject.
		fprintf(stderr,
			"[probe] error: set_autoload(inode_setattr) failed (%d/%d); "
			"refusing to load.\n", r1, r2);
		return -1;
	}
	fprintf(stderr, "[probe] inode_setattr hook: %s signature (%s wrapper).\n",
		modern ? "modern/idmap" : "legacy/no-idmap",
		modern ? "3-arg" : "2-arg");
	return 0;
}

int main(int argc, char **argv)
{
	/* Subcommand dispatch: `compartment-bpf observe [OPTIONS]` */
	if (argc >= 2 && strcmp(argv[1], "observe") == 0)
		return observe_main(argc, argv);

	int pin = 0;
	int dry_run = 0;
	int parse_only = 0;
	int allow_empty = 0;
	int allow_candidate = 0;  /* opt-in to load a candidate-marked profile under --pin */
	int unpin_mode = 0;
	int stats_mode = 0;
	const char *unpin_path = NULL;
	int exit_code = 0;
	const char *conf = NULL;

	int i = 1;
	while (i < argc) {
		if (!strcmp(argv[i], "--pin")) {
			pin = 1;
			i++;
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = 1;
			i++;
		} else if (!strcmp(argv[i], "--parse-only")) {
			parse_only = 1;
			i++;
		} else if (!strcmp(argv[i], "--allow-empty")) {
			allow_empty = 1;
			i++;
		} else if (!strcmp(argv[i], "--allow-candidate")) {
			/* Opt-in to load a candidate-marked
			 * profile under --pin. Without this flag, --pin against
			 * a profile carrying
			 * `#@compartment-bpf-profile-status: candidate` exits
			 * non-zero. dry-run / parse-only ignore this flag. */
			allow_candidate = 1;
			i++;
		} else if (!strcmp(argv[i], "--stats")) {
			stats_mode = 1;
			i++;
		} else if (!strcmp(argv[i], "--unpin")) {
			unpin_mode = 1;
			// --unpin takes an optional non-flag argument; if the
			// next token is a flag we treat it as no-arg unpin.
			if (i + 1 < argc && argv[i + 1][0] != '-' &&
			    argv[i + 1][0] != '\0') {
				unpin_path = argv[i + 1];
				i += 2;
			} else {
				i++;
			}
		} else if (argv[i][0] == '-') {
			usage(argv[0]);
			return 2;
		} else {
			if (argv[i][0] == '\0' || conf) {
				usage(argv[0]);
				return 2;
			}
			conf = argv[i];
			i++;
		}
	}

	// --unpin / --stats are the only actions that bypass the profile-
	// required path. They are mutually exclusive with --pin, --dry-run,
	// --allow-empty, and a profile argument; combining them is a usage
	// error so the operator catches a confused invocation at the door
	// rather than after partial side effects.
	if (unpin_mode) {
		if (pin || dry_run || parse_only || allow_empty || allow_candidate || conf || stats_mode) {
			fprintf(stderr,
				"--unpin is mutually exclusive with --pin, --dry-run, --parse-only, --allow-empty, --allow-candidate, --stats, and a profile argument.\n");
			usage(argv[0]);
			return 2;
		}
		return unpin_action(unpin_path);
	}
	if (stats_mode) {
		if (pin || dry_run || parse_only || allow_empty || allow_candidate || conf) {
			fprintf(stderr,
				"--stats is mutually exclusive with --pin, --dry-run, --parse-only, --allow-empty, --allow-candidate, and a profile argument.\n");
			usage(argv[0]);
			return 2;
		}
		return stats_action();
	}

	if (parse_only && dry_run) {
		fprintf(stderr,
			"--parse-only and --dry-run are mutually exclusive (parse-only is the stricter no-FS-touch mode).\n");
		usage(argv[0]);
		return 2;
	}
	if (parse_only && (pin || allow_empty)) {
		fprintf(stderr,
			"--parse-only is mutually exclusive with --pin and --allow-empty\n");
		usage(argv[0]);
		return 2;
	}

	if (!conf) { usage(argv[0]); return 2; }

	// Refuse to start if a pre-existing pinned seal map at
	// PIN_ROOT/maps/{sealed_inodes,sealed_dirs} has the wrong value
	// shape. v0 used __u32; v0.1+ uses struct seal_value (88 bytes
	// through v0.3; 96 bytes since v0.4 with strict-launch fields).
	// The check is read-only and skip-on-ENOENT, so we run it in
	// parse-only / dry-run / real-load — anywhere an operator might
	// validate a profile against a deployed pin tree. --unpin (above)
	// is the documented recovery path, so it stays exempt; --stats is
	// counter-map-only and never opens seal maps. Mirrors the
	// counter-map schema check in read_pinned_counter().
	if (check_pinned_seal_map_shapes() < 0)
		return 1;

	// Parse-only: grammar checks only. No FS access, no kernel state.
	// Used by tests/parser-actor/run.sh to drive parser fixtures
	// deterministically without depending on host paths.
	if (parse_only) {
		if (load_conf(NULL, conf, NULL, /*allow_empty*/0, /*parse_only*/1,
		              /*pin_enforce_path*/0, /*allow_candidate*/0) < 0)
			return 1;
		fprintf(stderr, "[parse-only] ok\n");
		return 0;
	}

	// Dry-run: parse the profile, resolve every path, print the (dev, ino)
	// keys that BPF would see. No kernel state touched, no root needed.
	// Useful for offline profile tooling and for any operator validating
	// a .conf before deploying it.
	if (dry_run) {
		if (pin)
			fprintf(stderr,
				"[dry-run] note: --pin would write to "
				PIN_ROOT "/links/ on a real run\n");
		if (load_conf(NULL, conf, NULL, allow_empty, /*parse_only*/0,
		              /*pin_enforce_path*/0, /*allow_candidate*/0) < 0)
			return 1;
		fprintf(stderr, "[dry-run] ok\n");
		return 0;
	}

	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &r) < 0)
		fprintf(stderr, "warn: setrlimit(RLIMIT_MEMLOCK): %s\n",
			strerror(errno));

	// We hold an O_PATH fd per sealed path across attach (see comment on
	// `struct held_fds`). On a large policy this can exceed the default
	// soft NOFILE limit; bump to the hard limit as a best effort.
	// Surface failure with the same warn pattern as RLIMIT_MEMLOCK
	// above — a silent failure manifests as a confusing "open: Too many
	// open files" downstream rather than naming the actual cause.
	struct rlimit rf;
	if (getrlimit(RLIMIT_NOFILE, &rf) == 0) {
		rf.rlim_cur = rf.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rf) < 0)
			fprintf(stderr, "warn: setrlimit(RLIMIT_NOFILE): %s\n",
				strerror(errno));
	} else {
		fprintf(stderr, "warn: getrlimit(RLIMIT_NOFILE): %s\n",
			strerror(errno));
	}

	struct sigaction sa = {};
	sa.sa_handler = on_sigint;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) < 0 ||
	    sigaction(SIGTERM, &sa, NULL) < 0) {
		fprintf(stderr, "sigaction: %s\n", strerror(errno));
		return 1;
	}

	if (probe_lsm_environment() < 0)
		return 1;

	// Warn on fs.protected_hardlinks=0. Without that sysctl, any
	// unprivileged user on the box can `link("/usr/sbin/aide",
	// "/tmp/myactor")` and `exec /tmp/myactor` to inherit actor
	// identity (the kernel resolves current->mm->exe_file to the
	// same (dev, ino) under either path). The kernel already closes
	// the surface at the LSM layer via comp_inode_link's source-
	// inode SEAL_NO_WRITE check; this is the defense-in-depth
	// callout that surfaces the sysctl gap to the operator before
	// they deploy.
	//
	// Failure to read /proc/sys/fs/protected_hardlinks is treated
	// as "unknown — warn"; container images / kernels without
	// procfs-side knobs still get a heads-up. v0 deliberately
	// chooses warn-only (not refuse-to-load) per the sidebar:
	// some legitimate container hosts ship with the sysctl at 0.
	{
		int pfd = open("/proc/sys/fs/protected_hardlinks",
			       O_RDONLY | O_CLOEXEC);
		if (pfd >= 0) {
			char b[16] = {};
			ssize_t r = read(pfd, b, sizeof(b) - 1);
			close(pfd);
			if (r > 0 && b[0] == '0') {
				fprintf(stderr,
					"[loader] WARNING: fs.protected_hardlinks=0; "
					"unprivileged hardlinks to actor binaries are "
					"the documented bypass class (LIMITATIONS.md). "
					"The comp_inode_link source-inode check is "
					"the LSM-layer defense; set "
					"fs.protected_hardlinks=1 for defense-in-depth.\n");
			}
		} else {
			fprintf(stderr,
				"[loader] warn: cannot read /proc/sys/fs/protected_hardlinks (%s); "
				"hardlink-to-actor sysctl state unknown — assume worst case and "
				"verify fs.protected_hardlinks=1 on production hosts.\n",
				strerror(errno));
		}
	}

	// The pinned-seal-map shape check already ran above (before parse-only /
	// dry-run early returns) so adversarial pinned maps are rejected
	// for every mode the operator could plausibly run against a hot
	// pin tree, not just real-load.

	struct compartment_bpf *skel = compartment_bpf__open();
	if (!skel) {
		fprintf(stderr, "open BPF: %s\n", strerror(errno));
		return 1;
	}

	// Pick the inode_setattr wrapper matching this kernel's hook signature
	// (6.8 has no mnt_idmap; 7.0+ does) before load, so the verifier only
	// sees the correctly-shaped program.
	if (select_inode_setattr_variant(skel) < 0) {
		compartment_bpf__destroy(skel);
		return 1;
	}

	// Optional test-only override for the audit ringbuf size,
	// so counter-smoke.sh can deterministically induce ringbuf drops with
	// a small burst of denies. Value is bytes; libbpf will reject anything
	// that is not a positive power-of-two multiple of the page size. No
	// public CLI flag -- this is an env knob for the smoke harness only.
	const char *rbsz = getenv("COMPARTMENT_BPF_AUDIT_RB_BYTES");
	if (rbsz && *rbsz) {
		char *end = NULL;
		unsigned long sz = strtoul(rbsz, &end, 0);
		if (!end || *end || sz == 0 || sz > (1UL << 30)) {
			fprintf(stderr,
				"COMPARTMENT_BPF_AUDIT_RB_BYTES: invalid value '%s'\n",
				rbsz);
			compartment_bpf__destroy(skel);
			return 1;
		}
		if (bpf_map__set_max_entries(skel->maps.audit_rb,
		                             (__u32)sz) < 0) {
			fprintf(stderr,
				"set audit_rb max_entries=%lu: %s\n",
				sz, strerror(errno));
			compartment_bpf__destroy(skel);
			return 1;
		}
		fprintf(stderr,
			"[test] audit_rb max_entries overridden to %lu bytes\n",
			sz);
	}

	// If --pin is requested and a tree is already pinned, refuse up
	// front — before load, attach, or any sentinel write — so we never
	// reach the EEXIST rollback that would clobber the existing tree's
	// unpin-auth sentinel (see pin_tree_exists()). Operator must --unpin
	// first. This early check is advisory (the pin lifecycle lock is not
	// held yet); the authoritative re-check runs under the lock below.
	if (pin && pin_tree_exists()) {
		fprintf(stderr,
			"--pin: a pinned tree already exists at " PIN_ROOT
			"/links; run --unpin first. Refusing to re-pin "
			"(fail-closed; preserves the existing unpin auth gate).\n");
		compartment_bpf__destroy(skel);
		return 1;
	}

	if (compartment_bpf__load(skel) < 0) {
		fprintf(stderr, "load BPF: %s\n", strerror(errno));
		compartment_bpf__destroy(skel);
		return 1;
	}

	// Populate seal maps BEFORE attach so policy is live the instant the
	// hooks become reachable. seal_path() fills `held` with one O_PATH fd per
	// sealed inode; these are held for the daemon's WHOLE LIFETIME (NOT just
	// the load window) to pin each inode against number reuse — see the
	// "KEEP the held O_PATH fds" note after attach. Cost: one fd per seal, so
	// the fd footprint is O(policy size) for the daemon's life (RLIMIT_NOFILE
	// was raised to the hard limit above).
	struct held_fds held = {0};
	if (load_conf(skel, conf, &held, allow_empty, /*parse_only*/0,
	              /*pin_enforce_path*/pin, allow_candidate) < 0) {
		held_fds_release(&held);
		compartment_bpf__destroy(skel);
		return 1;
	}
	fprintf(stderr,
		"[seal] holding %zu O_PATH fd(s) (sealed inodes + actor/launcher "
		"binaries) for the daemon lifetime to prevent inode-number reuse.\n",
		held.n);

	// Freeze seal maps before attach so once enforcement is live a task
	// with CAP_BPF cannot enumerate map IDs and weaken policy by
	// userspace map writes. Lookups from BPF are unaffected.
	//
	// v0 contract: this does NOT defend against an in-host CAP_BPF
	// attacker during the load window itself — between __load() and the
	// freeze below, a concurrent CAP_BPF process can find these maps by
	// name and mutate entries. v0 explicitly excludes in-host CAP_BPF
	// from its threat model; the v1 defense is SPEC §7 `bpf_gate` (armed-sentinel
	// pid-gate + restrict_filesystems boot config).
	if (freeze_seal_maps(skel) < 0) {
		held_fds_release(&held);
		compartment_bpf__destroy(skel);
		return 1;
	}

	if (compartment_bpf__attach(skel) < 0) {
		fprintf(stderr, "attach: %s\n", strerror(errno));
		held_fds_release(&held);
		compartment_bpf__destroy(skel);
		return 1;
	}

	// Enforcement is now live. KEEP the held O_PATH fds open for the
	// daemon's whole lifetime — do NOT release them here.
	//
	// Seals are keyed by (dev, ino). A `no-write` seal permits unlink
	// (no-write != no-unlink), so a sealed file can be removed, its inode
	// freed, and that inode number REUSED by an unrelated new file — which
	// then inherits the stale (dev, ino) seal and gets a spurious deny
	// (fail-closed, but a real correctness bug; reproduced on kernels whose
	// inode allocator recycles immediately, e.g. Noble 6.8). Holding an
	// O_PATH fd per sealed inode pins the inode struct so the kernel cannot
	// reuse its number while this daemon runs. RLIMIT_NOFILE was already
	// raised to the hard limit above to afford one fd per seal.
	//
	// Intended side-effect: an O_PATH fd on a sealed file pins its
	// filesystem, so a fs containing seals cannot be unmounted or
	// remounted-ro while this daemon runs (umount/mount -o remount return
	// EBUSY); --unpin first. This is security-positive — it blocks a
	// remount/umount-to-bypass vector — but operators relocating a sealed
	// fs must tear the daemon down first.
	//
	// LIMITATION (tracked follow-up): in --pin persistent mode the fds die
	// when this process exits while pinned enforcement lives on, so a
	// pinned-but-daemonless tree retains the reuse window. The complete fix
	// is nlink-aware seal eviction when the inode is actually freed (must be
	// nlink-aware: dropping a seal while a hardlink still exists would be
	// fail-OPEN). `held` is intentionally not freed; the OS reclaims it at
	// process exit.

	// Order matters: set up the audit ringbuf BEFORE
	// pinning links. If ring_buffer__new() fails after pin, the daemon
	// exits but the pinned program persists with no audit reader, leaving
	// enforcement live and silent. Ringbuf-first means a ringbuf failure
	// fails closed: we destroy the skel and exit clean, no orphan pins.
	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.audit_rb), audit_handler, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ringbuf: %s\n", strerror(errno));
		compartment_bpf__destroy(skel);
		return 1;
	}

	if (!pin) {
		// Without --pin, enforcement evaporates the
		// instant this process dies (kernel drops all link refs on
		// process exit). The default invocation is no-pin; operators
		// expecting enforcement to survive loader death must pass
		// --pin. Surface this so a SIGKILL of the loader does not
		// silently un-enforce.
		fprintf(stderr,
			"warn: running without --pin; enforcement ends when "
			"this process exits. Use --pin to make policy persist.\n");
	}

	if (pin) {
		// Refuse to race a concurrent --pin / --unpin
		// during the pin lifecycle. Held for the attach-to-pin
		// window only; released as soon as pin_counter_maps
		// completes so a subsequent --unpin against the same
		// PIN_ROOT (operator tearing the daemon down) is not
		// permanently blocked.
		int pin_lock_fd = pin_lifecycle_lock("--pin");
		if (pin_lock_fd < 0) {
			ring_buffer__free(rb);
			compartment_bpf__destroy(skel);
			return 1;
		}
		// SIGINT/SIGTERM may have already arrived
		// between attach() and here. Check before we begin
		// creating bpffs files so the rollback is trivial (no
		// pins to undo). compartment_bpf__destroy() drops the
		// link refs so enforcement evaporates the moment we exit.
		if (pin_window_aborted("--pin")) {
			pin_lifecycle_unlock(pin_lock_fd);
			ring_buffer__free(rb);
			compartment_bpf__destroy(skel);
			return 1;
		}
		// Authoritative stale-pin re-check, now that we hold the pin
		// lifecycle lock. The pre-load check above is advisory (lock
		// not yet held); a concurrent --pin could have created the
		// tree in the race window. Refuse here BEFORE the sentinel
		// write so we never reach the EEXIST rollback that unlinks the
		// sentinel and downgrades the existing tree's unpin auth.
		if (pin_tree_exists()) {
			fprintf(stderr,
				"--pin: a pinned tree appeared under " PIN_ROOT
				"/links while acquiring the pin lock; run "
				"--unpin first. Refusing fail-closed.\n");
			pin_lifecycle_unlock(pin_lock_fd);
			ring_buffer__free(rb);
			compartment_bpf__destroy(skel);
			return 1;
		}
		// Write the sentinel BEFORE the
		// pin tree. Pre-this, the order was attach → pin_links →
		// pin_counter_maps → ed11_pin_maybe_write_sentinel; a
		// SIGKILL between pin_counter_maps and the sentinel write
		// left pins live but no sentinel → next --unpin silently
		// took the legacy (no-passphrase) path: a downgrade. The
		// sentinel-first ordering closes that window. If
		// ed11_pin_maybe_write_sentinel fails up front, no pins
		// have been written yet — trivial rollback (none needed).
		// If pin_links / pin_counter_maps fail later, the sentinel
		// is removed alongside the link/map sweeps (each rollback
		// path below calls ed11_unpin_sentinel_unlink). A "sentinel
		// without pins" residual is harmless: the sentinel is
		// idempotently overwritten on the next --pin (existing
		// pre-unlink + O_EXCL discipline in ed11_write_sentinel).
		if (ed11_pin_maybe_write_sentinel() < 0) {
			fprintf(stderr,
				"[pin] sentinel write failed; refusing pin fail-closed (no pins created).\n");
			pin_lifecycle_unlock(pin_lock_fd);
			ring_buffer__free(rb);
			compartment_bpf__destroy(skel);
			return 1;
		}
		if (pin_links(skel) < 0) {
			ed11_unpin_sentinel_unlink();
			pin_lifecycle_unlock(pin_lock_fd);
			ring_buffer__free(rb);
			compartment_bpf__destroy(skel);
			return 1;
		}
		// SIGTERM between pin_links and
		// pin_counter_maps would leave a half-pinned state. Sweep
		// the link pins we just created before exiting; this
		// also removes the sentinel we wrote up front.
		if (pin_window_aborted("--pin")) {
			int removed = 0, unknown = 0;
			(void)sweep_known(PIN_ROOT "/links",
				KNOWN_LINK_NAMES, N_KNOWN_LINK_NAMES,
				&removed, &unknown);
			ed11_unpin_sentinel_unlink();
			pin_lifecycle_unlock(pin_lock_fd);
			ring_buffer__free(rb);
			compartment_bpf__destroy(skel);
			return 1;
		}
		if (pin_counter_maps(skel) < 0) {
			// pin_links() already succeeded -- roll it back so we
			// do not leave a half-pinned state on bpffs;
			// also remove the sentinel we wrote up front.
			int removed = 0, unknown = 0;
			(void)sweep_known(PIN_ROOT "/links",
				KNOWN_LINK_NAMES, N_KNOWN_LINK_NAMES,
				&removed, &unknown);
			ed11_unpin_sentinel_unlink();
			pin_lifecycle_unlock(pin_lock_fd);
			ring_buffer__free(rb);
			compartment_bpf__destroy(skel);
			return 1;
		}
		// ed11_pin_maybe_write_sentinel already ran before
		// pin_links above. The pin tree is now in place AND the
		// sentinel matches it. The pre-this-commit ordering wrote
		// the sentinel here AFTER the pins, so a SIGKILL between
		// pin_counter_maps and the sentinel write left pins live
		// but no sentinel — next --unpin silently took the legacy
		// (no-passphrase) path. Sentinel-first closes that window.
		pin_lifecycle_unlock(pin_lock_fd);
	}

	// Synthetic ringbuf-emit test. When the test env knob
	// is set, fabricate one audit_event with a deliberately mismatched
	// ABI version and run it through audit_handler. The handler hits
	// the version-mismatch branch and emits its `warn:` line to
	// stderr. This is a synthetic exercise of the version-skip branch
	// (not a real ringbuf injection — userspace cannot produce into
	// BPF_MAP_TYPE_RINGBUF; the unit test path is the only feasible
	// witness). Never set in production. Picked up by
	// tests/bypass/exec-domain/BX-9-version-mismatch.sh.
	if (getenv("COMPARTMENT_BPF_TEST_EMIT_BAD_VERSION")) {
		struct audit_event synth = {};
		synth.version = 0xFFFE;
		(void)audit_handler(NULL, &synth, sizeof(synth));
		fprintf(stderr, "[test] BX-9 synthetic bad-version event emitted\n");
	}

	fprintf(stderr, "[run] compartment-bpf live. ^C to exit.\n");
	while (running) {
		int n = ring_buffer__poll(rb, 1000);
		if (n == -EINTR)
			continue;
		if (n < 0) {
			int err = -n;
			fprintf(stderr, "ringbuf poll: %s\n", strerror(err));
			exit_code = 1;
			break;
		}
	}

	ring_buffer__free(rb);
	compartment_bpf__destroy(skel);
	return exit_code;
}
