# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# sandbox-hard.sh — the sandbox.sh HARD-mode assertions, against a real
# user + mount + net namespace.
#
# Sourced, never executed (no shebang, mode 644).  The caller provides
# pass/fail/skip and a writable scratch directory; this file provides
# sandbox_hard_assertions, which contributes exactly
# ${SANDBOX_HARD_COUNT} assertions on every path.
#
# Why it is shared: run_sandbox_proxy_matrix.sh runs it whenever the host
# already allows an unprivileged user namespace, and
# root.d/sandbox-hard.sh runs it after temporarily clearing
# kernel.apparmor_restrict_unprivileged_userns.  Before this, README:265's
# claim — "loopback-only, no external interfaces, no routes" — had no
# witness anywhere: the proxy matrix reported pass=0 fail=0 skip=1 on the
# host and on both guests, and rootless.d/sandbox.sh drives stubbed
# unshare/ip/mount only.
#
# shellcheck shell=bash

# shellcheck disable=SC2034  # read by the suites that source this file
SANDBOX_HARD_COUNT=9

# sandbox_hard_assertions SANDBOX_PATH SCRATCH_DIR [RUN_AS_USER]
sandbox_hard_assertions() {
    local sandbox="$1" scratch="$2" as_user="${3:-}"
    local runner=()
    [ -n "${as_user}" ] && runner=(runuser -u "${as_user}" --)

    # sandbox.sh finds compartment-user next to itself and then bind-mounts
    # it over every shell.  Inside a --map-root-user namespace the stashed
    # real shells belong to an unmapped uid, so that path cannot complete;
    # it is witnessed on its own below.  To assert the *namespace*, run a
    # copy of the script from a directory with no compartment-user beside
    # it.  (COMPARTMENT_USER= does not do this: sandbox.sh never reads that
    # variable — it searches $SCRIPT_DIR and then $PATH.)
    local plain="${scratch}/plain"
    mkdir -p "${plain}"
    cp "${sandbox}" "${plain}/sandbox.sh"
    chmod 755 "${plain}/sandbox.sh"
    chmod 0777 "${scratch}" "${plain}" 2>/dev/null || true

    # sandbox.sh also falls back to $PATH, so build a PATH with no
    # compartment-user on it rather than assuming there is none.
    local sbpath="" d
    for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
        [ -d "${d}" ] || continue
        [ -x "${d}/compartment-user" ] && continue
        sbpath="${sbpath}${sbpath:+:}${d}"
    done

    # /sys/class/net is the wrong place to look: sysfs is netns-tagged at
    # mount time, and sandbox.sh unshares the mount namespace without
    # remounting /sys, so the host's interfaces stay visible there even
    # inside a fresh netns.  netlink (ip) and /proc/self/net answer for
    # the caller's current netns, which is the question being asked.
    local out
    out="$(env -u COMPARTMENT_USER UPSTREAM_PROXY="" PATH="${sbpath}" \
        "${runner[@]}" timeout 30 "${plain}/sandbox.sh" /bin/sh -c '
            echo INSIDE
            echo "NETIF=[$(ip -o link show 2>/dev/null | awk -F": " "{print \$2}" | sort | tr "\n" " ")]"
            echo "PROCNETIF=[$(awk -F: "NR>2 {gsub(/[ \t]/,\"\",\$1); print \$1}" /proc/net/dev | sort | tr "\n" " ")]"
            echo "LOUP=$(ip -o link show lo 2>/dev/null | grep -c ",UP")"
            echo "ROUTES=$(ip route show 2>/dev/null | wc -l)"
            (exec 3<>/dev/tcp/192.0.2.1/80) 2>/dev/null \
                && echo "OFFHOST=connected" || echo "OFFHOST=refused"
            echo "ID=uid=$(id -u) gid=$(id -g)"
            echo "PROCS=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
        ' 2>/dev/null)" || true

    if printf '%s\n' "${out}" | grep -q '^INSIDE$'; then
        pass "HARD: the sandbox launched into a real namespace"
    else
        fail "HARD: sandbox.sh did not launch although userns is available"
    fi

    if printf '%s\n' "${out}" | grep -q '^NETIF=\[lo \]$' &&
       printf '%s\n' "${out}" | grep -q '^PROCNETIF=\[lo \]$'; then
        pass "HARD: the namespace has exactly one interface, lo (netlink and /proc/net/dev agree)"
    else
        fail "HARD: interface list is not lo-only ($(printf '%s\n' "${out}" | grep '^NETIF=\|^PROCNETIF=' | tr '\n' ' ' || echo 'no NETIF line'))"
    fi

    if [ "$(printf '%s\n' "${out}" | sed -n 's/^LOUP=//p')" = "1" ]; then
        pass "HARD: loopback is up"
    else
        fail "HARD: loopback is not up"
    fi

    local routes
    routes="$(printf '%s\n' "${out}" | sed -n 's/^ROUTES=//p')"
    if [ "${routes:-x}" = "0" ]; then
        pass "HARD: the routing table is empty"
    else
        fail "HARD: ${routes:-no} route(s) in the namespace"
    fi

    if printf '%s\n' "${out}" | grep -q '^OFFHOST=refused$'; then
        pass "HARD: a connect to an off-host address is refused"
    else
        fail "HARD: an off-host connect was not refused ($(printf '%s\n' "${out}" | grep '^OFFHOST=' || echo 'no OFFHOST line'))"
    fi

    if printf '%s\n' "${out}" | grep -q '^ID=uid=0 gid=0$'; then
        pass "HARD: --map-root-user maps the caller to uid 0 in the namespace"
    else
        fail "HARD: no mapped-root identity inside the namespace ($(printf '%s\n' "${out}" | grep '^ID=' || echo 'no ID line'))"
    fi

    # An honest witness, not a claim: HARD mode unshares user, mount and
    # net but NOT pid (sandbox.sh's own unshare line), so host processes
    # stay visible.  The old test called pass() in both branches of this
    # comparison, so a gained or lost PID namespace read the same.
    local host_procs procs
    host_procs="$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
    procs="$(printf '%s\n' "${out}" | sed -n 's/^PROCS=//p')"
    if [ -z "${procs}" ]; then
        fail "HARD: could not count processes inside the namespace"
    elif [ "${procs}" -ge $(( host_procs / 2 )) ]; then
        pass "HARD: pid is deliberately not unshared — ${procs} of ~${host_procs} host processes stay visible"
    else
        fail "HARD: only ${procs} of ~${host_procs} processes visible — pid now looks unshared; update sandbox.sh's documented behaviour and this witness"
    fi

    # The shell intercept in a real mapped-root namespace.  The stash
    # entries are bind mounts of the host's shells, whose owner (host root)
    # is not mapped, so compartment-user refuses the stash and sandbox.sh
    # refuses to continue with a half-installed intercept.  That is
    # fail-closed and correct; it is also the reason HARD mode has to be
    # run with SANDBOX_NO_SHELL_INTERCEPT=1 today.  Recorded so a change in
    # either direction is visible.
    local iout irc=0
    iout="$(env UPSTREAM_PROXY="" "${runner[@]}" timeout 30 \
        "${sandbox}" /bin/sh -c 'echo INTERCEPT_INSIDE' 2>&1)" || irc=$?
    if [ "${irc}" -ne 0 ] &&
       printf '%s\n' "${iout}" | grep -q 'refusing to continue with a half-installed shell intercept'; then
        pass "HARD: the shell intercept fails closed under a mapped-root namespace (documented residual)"
    elif [ "${irc}" -eq 0 ] && printf '%s\n' "${iout}" | grep -q '^INTERCEPT_INSIDE$'; then
        fail "HARD: the shell intercept now works under a mapped-root namespace — update LIMITATIONS and this witness"
    else
        fail "HARD: the shell intercept failed for an unexpected reason (rc=${irc}): $(printf '%s' "${iout}" | tr '\n' '|' | cut -c1-200)"
    fi

    # The proxy bridge.  socat is the only extra dependency; without an
    # upstream proxy there is nothing to bridge to.
    if ! command -v socat >/dev/null 2>&1; then
        skip "HARD+proxy: socat is not installed"
    elif ! curl -s --proxy http://127.0.0.1:8080 --connect-timeout 2 \
              http://example.com >/dev/null 2>&1; then
        skip "HARD+proxy: no upstream proxy answering on 127.0.0.1:8080"
    else
        local pout
        pout="$(env -u COMPARTMENT_USER UPSTREAM_PROXY="http://127.0.0.1:8080" \
            PATH="${sbpath}" "${runner[@]}" timeout 40 "${plain}/sandbox.sh" /bin/sh -c \
            'curl -s --proxy "${http_proxy:-}" --connect-timeout 5 http://example.com 2>&1 | head -5' \
            2>/dev/null)" || true
        if printf '%s\n' "${pout}" | grep -qi 'example\|html\|doctype'; then
            pass "HARD+proxy: curl through the unix-socket proxy bridge works"
        else
            fail "HARD+proxy: the bridge is configured but returned nothing usable"
        fi
    fi
}
