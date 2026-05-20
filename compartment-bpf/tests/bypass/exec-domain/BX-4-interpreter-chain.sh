#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-4-interpreter-chain.sh
# Correct-behavior witness (NOT a bypass): exec via an interpreter
# replaces the process image with the interpreter binary. mm->exe_file
# is then the interpreter's inode (e.g. /usr/bin/python3), NOT the
# actor's. Actor check must DENY when a non-actor interpreter attempts
# the seal-gated op — even if it was launched from the actor's shell or
# script.
# Suggestion ID: SPEC §8 BX-4
set -u
BYPASS_NAME="BX-4-interpreter-chain"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

command -v python3 >/dev/null 2>&1 || bypass_skip "python3 not present"

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)

ed_setup_actor_seal myactor "$ACTOR" "no-write"

# Try to open TARGET for write from python. The seal flags include
# no-write actor=myactor → the LSM hook on file_open(O_WRONLY) checks
# the caller's mm->exe_file (= python3's inode) against the actor group.
# Python is not the actor → expect EACCES → PermissionError → python
# exits non-zero. We rely on rc != 0 since python's exception traceback
# return code is interpreter-dependent.
python3 -c "
import sys
try:
    f = open(sys.argv[1], 'w')
    f.write('x')
    f.close()
    sys.exit(0)   # would mean the write was ALLOWED — bypass
except PermissionError:
    sys.exit(1)   # EACCES — actor check fired correctly
except OSError as e:
    sys.exit(3)
" "$TARGET" >/dev/null 2>&1; rc=$?

case $rc in
	1) bypass_pass "python interpreter exec-chain denied (exe_inode != actor inode)" ;;
	0) bypass_fail "BYPASS: write via python interpreter succeeded — actor check missed exec switch?" ;;
	*) bypass_fail "unexpected rc=$rc (expected 1=DENY/EACCES)" ;;
esac
