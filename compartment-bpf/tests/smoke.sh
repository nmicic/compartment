#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
	echo "error: smoke test requires Linux" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "error: smoke test requires root for BPF LSM load" >&2
	exit 1
fi

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "error: BPF LSM is not enabled in /sys/kernel/security/lsm" >&2
	exit 1
fi

tmp=$(mktemp -d /tmp/compartment-bpf-smoke.XXXXXX)
pid=

cleanup()
{
	if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

expect_fail()
{
	if "$@" >/dev/null 2>&1; then
		echo "error: command unexpectedly succeeded: $*" >&2
		exit 1
	fi
}

mkdir "$tmp/sealed"
printf 'original\n' > "$tmp/sealed/data"
mkdir "$tmp/sealed/subdir"
printf 'preopen\n' > "$tmp/preopen"
exec 9>"$tmp/preopen"

cat > "$tmp/policy.conf" <<EOF
seal $tmp/sealed full
seal $tmp/sealed/data no-write,no-unlink,no-rename
seal $tmp/preopen no-write,no-unlink,no-rename
EOF

# Dry-run sanity: parse the profile and resolve (dev, ino) without
# touching the kernel. Verifies the parser + path resolution path that
# real attach also goes through, but is safe to run before the daemon
# starts.
./compartment-bpf --dry-run "$tmp/policy.conf" >"$tmp/dry.out" 2>&1
if ! grep -q '\[dry-run\] ok' "$tmp/dry.out"; then
	echo "error: --dry-run did not report ok" >&2
	cat "$tmp/dry.out" >&2
	exit 1
fi
if ! grep -q '\[dry-run\].*\[d\].*sealed ' "$tmp/dry.out"; then
	echo "error: --dry-run did not mark sealed dir as [d]" >&2
	cat "$tmp/dry.out" >&2
	exit 1
fi

# Symlink-leaf rejection: regression-gate finding G from the Phase 2
# multi-pass review. The two-phase loader must refuse a symlink at the
# leaf (post-fstat S_ISLNK check) regardless of whether the target
# exists. Both a valid-link and a broken-link case must exit non-zero
# with the canonical message.
ln -s "$tmp/sealed/data" "$tmp/symlink-valid"
ln -s "$tmp/no-such-target" "$tmp/symlink-broken"
for sl in "$tmp/symlink-valid" "$tmp/symlink-broken"; do
	echo "seal $sl full" > "$tmp/symlink.conf"
	if ./compartment-bpf --dry-run "$tmp/symlink.conf" \
			>"$tmp/sym.out" 2>&1; then
		echo "error: --dry-run accepted symlink leaf: $sl" >&2
		cat "$tmp/sym.out" >&2
		exit 1
	fi
	if ! grep -q 'refusing to seal a symlink leaf' "$tmp/sym.out"; then
		echo "error: --dry-run did not print expected symlink rejection for $sl" >&2
		cat "$tmp/sym.out" >&2
		exit 1
	fi
done

./compartment-bpf "$tmp/policy.conf" >"$tmp/daemon.out" 2>"$tmp/daemon.err" &
pid=$!

# Poll until the daemon prints [run] (BPF programs loaded + maps populated).
# Timeout after 15 s to catch genuine failures; each poll is 100 ms.
_i=0
while [ $_i -lt 150 ]; do
	if ! kill -0 "$pid" 2>/dev/null; then
		echo "error: daemon exited early" >&2
		cat "$tmp/daemon.err" >&2 || true
		exit 1
	fi
	grep -q '\[run\]' "$tmp/daemon.err" 2>/dev/null && break
	sleep 0.1
	_i=$((_i + 1))
done
if [ $_i -eq 150 ]; then
	echo "error: daemon did not become ready within 15s" >&2
	cat "$tmp/daemon.err" >&2 || true
	kill "$pid" 2>/dev/null || true
	exit 1
fi

expect_fail rm "$tmp/sealed/data"
expect_fail sh -c "printf overwrite > '$tmp/sealed/data'"
expect_fail touch "$tmp/sealed/new"

printf 'replacement\n' > "$tmp/replacement"
expect_fail mv "$tmp/replacement" "$tmp/sealed/data"

expect_fail rmdir "$tmp/sealed/subdir"

expect_fail sh -c "printf later >&9"

kill "$pid"
wait "$pid" 2>/dev/null || true
pid=

echo "smoke ok"
