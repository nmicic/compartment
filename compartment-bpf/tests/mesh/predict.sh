# SPDX-License-Identifier: Apache-2.0
#
# tests/mesh/predict.sh — §2.2 4-quadrant expected-outcome table.
#
# This file IS the predict function. Sourced by tests/mesh/run-mesh.sh.
# Per EXEC-DOMAIN-MESH-DRAFT.md §2.2 (corrected v0.4 round-2):
#
#   | Caller in Set | Target file       | Caller in target's actor group? | Op flag set on seal? | Expected |
#   |---------------|-------------------|----------------------------------|----------------------|----------|
#   | A             | A_j sealed        | Yes (j == caller)                | Yes                  | ALLOW    |
#   | A             | A_j sealed        | No  (j != caller's domain)       | Yes                  | DENY     |
#   | A             | A_j sealed        | (any)                            | No                   | ALLOW    |
#   | A             | non-sealed        | n/a                              | n/a                  | ALLOW    |
#   | B             | A_j sealed        | No  (B not in actor list)        | Yes                  | DENY     |
#   | B             | A_j sealed        | n/a                              | No                   | ALLOW    |
#   | B             | non-sealed        | n/a                              | n/a                  | ALLOW    |
#
# usage: mesh_predict <target_class> <flag_blocks_op> <actor_match>
#   target_class:    sealed | baseline
#   flag_blocks_op:  yes | no
#   actor_match:     yes | no       (always 'no' when caller is in Set B
#                                    AND caller is not listed in this seal's
#                                    actor group; 'yes' when caller's stub
#                                    inode is in the seal's actor[] array)
# echoes: ALLOW | DENY
#
# Note: the four-quadrant table reduces to three rules. Anything outside
# them is a logic gap — fail closed.
mesh_predict() {
	local target=$1 blocks=$2 match=$3
	# Rule 1: non-sealed target → always ALLOW (no seal entry to consult).
	if [ "$target" = "baseline" ]; then echo ALLOW; return; fi
	# Rule 2: sealed but the op's flag is NOT set on this seal → ALLOW
	# (the seal has actor= but doesn't restrict this particular op).
	if [ "$blocks" = "no" ]; then echo ALLOW; return; fi
	# Rule 3: sealed AND flag-blocks → ALLOW iff caller in actor group.
	if [ "$match" = "yes" ]; then echo ALLOW; return; fi
	echo DENY
}
