/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 *
 * tools/compartment-dangerous-env.h — single source of truth for the
 * dangerous dynamic-loader / interpreter env name list shared between:
 *  - the compartment-bpf loader (parse-time validation of profiles;
 *    legacy v0.3 `env` directives were rejected against this list; in
 *    v0.4 the directive parser is removed but the list is retained as
 *    the wrapper-alignment invariant — both translation units must
 *    reference the same data so a future drift cannot land silently);
 *  - the static actor wrapper `tools/compartment-actor-wrapper.c`
 *    (runtime scrub at exec time after `clearenv()`-then-allowlist).
 *
 * This header centralizes the dangerous env list. Before the
 * extraction, the loader shipped a 16-name list while the wrapper
 * shipped ~60. The list below mirrors the wrapper's canonical list:
 *  - glibc `elf/unsecvars.h` dynamic-linker vectors,
 *  - shell-script attack vectors (BASH_FUNC_* matched by prefix in
 *    the helper below — the kernel's bash export name vector
 *    survives the shellshock `()` fix because the prefix landed),
 *  - NSS / resolver / OpenSSL / crypto config injection,
 *  - language interpreter library/option vectors.
 *
 * A future glibc / bash / openssl update that adds a new env vector
 * goes here; the wrapper's identity witness (`make check-actor-hook`)
 * asserts both translation units reference the same symbol.
 *
 * Authoritative list:
 * compartment-actor-wrapper.c + this shared header.
 */

#ifndef COMPARTMENT_DANGEROUS_ENV_H
#define COMPARTMENT_DANGEROUS_ENV_H

#include <string.h>

/* X-macro list. Add new names by extending this block; both
 * COMPARTMENT_DANGEROUS_ENV_NAMES (array) and any future enum/lookup
 * stay in sync automatically. */
#define COMPARTMENT_DANGEROUS_ENV_LIST(X)                                      \
	/* dynamic-linker / glibc unsecvars.h */                               \
	X("LD_PRELOAD") X("LD_AUDIT") X("LD_LIBRARY_PATH") X("LD_DEBUG")       \
	X("LD_DEBUG_OUTPUT") X("LD_PROFILE") X("LD_TRACE_LOADED_OBJECTS")      \
	X("LD_BIND_NOW") X("LD_BIND_NOT") X("LD_DYNAMIC_WEAK")                 \
	X("LD_HWCAP_MASK") X("LD_ORIGIN_PATH") X("LD_POINTER_GUARD")           \
	X("LD_PROFILE_OUTPUT") X("LD_SHOW_AUXV") X("LD_USE_LOAD_BIAS")         \
	X("GLIBC_TUNABLES") X("GCONV_PATH") X("GETCONF_DIR")                   \
	X("LOCPATH") X("LOCALDOMAIN") X("NLSPATH")                             \
	X("RES_OPTIONS") X("RESOLV_HOST_CONF") X("HOSTALIASES")                \
	X("NIS_PATH") X("IFS")                                                 \
	X("MALLOC_TRACE") X("MALLOC_CHECK_") X("MALLOC_TOP_PAD_")              \
	X("MALLOC_ARENA_TEST") X("MALLOC_ARENA_MAX") X("MALLOC_CONF")          \
	/* shell-script attack vectors */                                      \
	X("BASH_ENV") X("ENV") X("CDPATH") X("BASHOPTS") X("SHELLOPTS")        \
	/* NSS / resolver */                                                   \
	X("NSS_PATH") X("NSS_STRICT_NOLOGIN")                                  \
	/* OpenSSL / crypto / TLS */                                           \
	X("OPENSSL_CONF") X("OPENSSL_ENGINES") X("OPENSSL_MODULES")            \
	X("SSL_CERT_FILE") X("SSL_CERT_DIR")                                   \
	X("CURL_CA_BUNDLE") X("CURL_HOME")                                     \
	X("KRB5_CONFIG") X("KRB5CCNAME") X("SASL_PATH") X("SASL_CONF_PATH")    \
	/* language interpreters */                                            \
	X("PYTHONPATH") X("PYTHONSTARTUP") X("PYTHONHOME") X("PYTHONINSPECT")  \
	X("PERL5LIB") X("PERL5OPT") X("PERL5DB")                               \
	X("RUBYLIB") X("RUBYOPT")                                              \
	X("NODE_OPTIONS") X("NODE_PATH")                                       \
	X("JAVA_TOOL_OPTIONS") X("_JAVA_OPTIONS") X("JDK_JAVA_OPTIONS")        \
	X("GIT_EXEC_PATH") X("GIT_TRACE") X("GIT_TEMPLATE_DIR")

static const char *const COMPARTMENT_DANGEROUS_ENV_NAMES[] = {
#define COMP_DANG_X(s) s,
	COMPARTMENT_DANGEROUS_ENV_LIST(COMP_DANG_X)
#undef COMP_DANG_X
	NULL,
};

/* BASH_FUNC_* exported shell functions land in the environment as
 * `BASH_FUNC_<name>%%=...`. The prefix is the load-bearing match —
 * bash imports any export whose name starts with `BASH_FUNC_` even
 * after the shellshock parenthesis fix. */
static inline int compartment_env_name_is_dangerous(const char *name)
{
	if (!name)
		return 0;
	if (strncmp(name, "BASH_FUNC_", 10) == 0)
		return 1;
	for (int i = 0; COMPARTMENT_DANGEROUS_ENV_NAMES[i]; i++) {
		if (strcmp(name, COMPARTMENT_DANGEROUS_ENV_NAMES[i]) == 0)
			return 1;
	}
	return 0;
}

#endif /* COMPARTMENT_DANGEROUS_ENV_H */
