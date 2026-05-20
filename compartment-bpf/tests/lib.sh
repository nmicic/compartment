# SPDX-License-Identifier: Apache-2.0
# tests/lib.sh — shared bash helpers for the compartment-bpf overnight test
# suites. Sourced by matrix.sh, bypass/*.sh, fuzz_oracle harnesses, and the
# stress/bench runners. Intentionally POSIX-ish; runs on host (for static
# checks) AND on the VM (for live tests).
#
# Conventions:
#   - VM_HOST defaults to 192.168.122.253 (the Resolute VM)
#   - VM_USER defaults to root (matrix tests need CAP_BPF / CAP_SYS_ADMIN)
#   - SSH_OPTS is mutable so callers can override (StrictHostKeyChecking, etc.)
#   - All helpers fail loud: any unexpected condition prints to stderr and
#     returns non-zero. Callers `set -eu` and let errors propagate.
#
# The functions are deliberately small. Glue them together in matrix.sh
# rather than burying the test logic here.

VM_HOST=${VM_HOST:-192.168.122.253}
VM_USER=${VM_USER:-root}
SSH_OPTS=${SSH_OPTS:-"-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10"}
VM_WORKDIR=${VM_WORKDIR:-/root/compartment_ebpf-tests}
SEALPROBE=${SEALPROBE:-./tests/sealprobe}

# Map sealprobe exit codes back to symbolic names so harness output is
# legible without consulting the C source.
sealprobe_rc_name()
{
	case "$1" in
	0) echo ALLOW ;;
	1) echo DENY ;;
	2) echo USAGE ;;
	3) echo UNEXPECTED_ERRNO ;;
	4) echo STAGE_ERROR ;;
	*) echo "RC$1" ;;
	esac
}

# ssh_root <command...>
#   Run a command on the VM as VM_USER. Stdin is connected so that
#   `echo data | ssh_root 'cat > file'` works.
ssh_root()
{
	# shellcheck disable=SC2029
	ssh $SSH_OPTS "${VM_USER}@${VM_HOST}" "$@"
}

# scp_to <local> <remote>
scp_to()
{
	scp $SSH_OPTS "$1" "${VM_USER}@${VM_HOST}:$2"
}

# scp_from <remote> <local>
scp_from()
{
	scp $SSH_OPTS "${VM_USER}@${VM_HOST}:$1" "$2"
}

# vm_run <command...>
#   Alias for ssh_root with logging. Use this for top-level test steps so
#   the transcript shows what was attempted.
vm_run()
{
	echo "[vm] $*" >&2
	ssh_root "$@"
}

# expect_blocked <expected-rc> <command...>
#   Run a sealprobe invocation and assert the exit code matches the
#   "DENY" case (RC_DENY=1). Prints PASS/FAIL with context.
expect_blocked()
{
	local label=$1; shift
	local rc
	"$@" >/dev/null 2>&1 && rc=0 || rc=$?
	if [ "$rc" -eq 1 ]; then
		echo "PASS  $label  (DENY)"
		return 0
	fi
	echo "FAIL  $label  expected DENY, got $(sealprobe_rc_name "$rc")" >&2
	return 1
}

# expect_allowed <label> <command...>
expect_allowed()
{
	local label=$1; shift
	local rc
	"$@" >/dev/null 2>&1 && rc=0 || rc=$?
	if [ "$rc" -eq 0 ]; then
		echo "PASS  $label  (ALLOW)"
		return 0
	fi
	echo "FAIL  $label  expected ALLOW, got $(sealprobe_rc_name "$rc")" >&2
	return 1
}

# capture_audit <pid-file> <out-file>
#   Tail the daemon's stderr for a fixed window and dump audit lines into
#   <out-file>. Designed to run alongside a test step and be diff'd against
#   expected counts.
capture_audit()
{
	local pid_file=$1
	local out_file=$2
	local seconds=${3:-3}

	if [ ! -r "$pid_file" ]; then
		echo "capture_audit: pid file $pid_file not readable" >&2
		return 1
	fi
	# /proc/<pid>/fd/2 is the daemon's stderr fd, but it's a tty/pipe.
	# In the matrix harness the daemon writes to a file we open ourselves;
	# the harness passes that file's path here instead. So this is just a
	# sleep + tail.
	sleep "$seconds"
	grep -F '[audit]' "$pid_file" > "$out_file" || true
}

# count_audit <file> <action>
#   Count audit lines matching ACTION (e.g. DENY_WRITE, DENY_UNLINK).
count_audit()
{
	grep -c "\[audit\] $2" "$1" 2>/dev/null || echo 0
}

# vm_sync_repo
#   rsync the repo to the VM workdir so we can build sealprobe + run the
#   suite there. Excludes build artifacts and operator-local scratch.
vm_sync_repo()
{
	echo "[vm] sync repo -> ${VM_USER}@${VM_HOST}:${VM_WORKDIR}" >&2
	ssh_root "mkdir -p ${VM_WORKDIR}"
	rsync -az --delete \
		-e "ssh ${SSH_OPTS}" \
		--exclude='.git' \
		--exclude='kvm' \
		--exclude='compartment-bpf' \
		--exclude='compartment.bpf.o' \
		--exclude='compartment.skel.h' \
		--exclude='vmlinux.h' \
		--exclude='tests/sealprobe' \
		./ "${VM_USER}@${VM_HOST}:${VM_WORKDIR}/"
}

# vm_build
#   Build compartment-bpf + sealprobe on the VM.
vm_build()
{
	vm_run "cd ${VM_WORKDIR} && make vmlinux.h >/dev/null && make >/dev/null && make test-tools >/dev/null"
}

# vm_have_lsm
#   Verify the VM has bpf in the active LSM list. Bail early if not.
vm_have_lsm()
{
	if ! vm_run 'grep -qw bpf /sys/kernel/security/lsm'; then
		echo "vm_have_lsm: bpf not in /sys/kernel/security/lsm on ${VM_HOST}" >&2
		return 1
	fi
}

# tmpdir_on_vm
#   Echo a path; harness uses it as a per-test scratch dir.
tmpdir_on_vm()
{
	vm_run "mktemp -d /tmp/compartment-test.XXXXXX"
}
