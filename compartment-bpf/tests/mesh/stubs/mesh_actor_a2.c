// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
// mesh_actor_a2 — Set A actor stub a2 in the exec-domain mesh.
//
// Compiled with -DSTUB_ID=a2; the per-binary stub_id_tag string ensures
// distinct .rodata content so two stubs cannot share an inode under
// content-addressed storage / build-system dedup.
#include "mesh_stub_main.h"

#define _STR(x) #x
#define _XSTR(x) _STR(x)
static volatile const char stub_id_tag[] = "MESH_STUB_ID=" _XSTR(STUB_ID);

int main(int argc, char **argv)
{
	(void)stub_id_tag;
	return mesh_stub_main(argc, argv);
}
