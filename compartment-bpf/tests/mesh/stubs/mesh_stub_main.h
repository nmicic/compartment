/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Nenad Mićić <nenad@micic.be> */
/*
 * mesh_stub_main — shared op dispatcher for the exec-domain mesh stubs.
 *
 * Per EXEC-DOMAIN-MESH-DRAFT.md §5.1: each of the 8 stub binaries
 * (4 actor + 4 outsider) is a thin wrapper around mesh_stub_main().
 * The wrapper compiles with -DSTUB_ID=<id>, which the wrapper embeds
 * in a per-binary string so two stubs never share .rodata content
 * (defense in depth against build-system inode dedup).
 */
#ifndef MESH_STUB_MAIN_H
#define MESH_STUB_MAIN_H

int mesh_stub_main(int argc, char **argv);

#endif /* MESH_STUB_MAIN_H */
