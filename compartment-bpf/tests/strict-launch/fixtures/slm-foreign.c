// SPDX-License-Identifier: GPL-2.0
// Foreign-exec helper for the foreign-exec chain-break test.
// Distinct inode from slm-launcher and slm-actor — exec into here from a
// marked task causes bprm step 3b foreign-exec, clearing the marker.
#include <stdio.h>
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("foreign\n");
    return 0;
}
