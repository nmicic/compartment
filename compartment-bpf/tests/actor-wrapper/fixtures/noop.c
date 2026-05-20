/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * noop — minimal exit-0 binary, regular-file-on-all-distros target for
 * actor-wrapper tests (avoiding /usr/bin/true symlink on Ubuntu 26.04
 * with uutils-coreutils).
 */
int main(void) { return 0; }
