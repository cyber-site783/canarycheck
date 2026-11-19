/* test_program.c - small test program for CanaryCheck.
 *
 * It uses strcpy() and strcat() on fixed-size buffers, so with
 * -O2 -D_FORTIFY_SOURCE=2 the compiler replaces them with the
 * fortified __strcpy_chk / __strcat_chk versions, and with
 * -fstack-protector-all it adds the __stack_chk_fail canary check.
 * Compile it with different flags to get binaries with different
 * mitigations switched on and off (see README.md).
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char dest[128] = "Hello, ";
    char buffer[64];

    if (argc > 1) {
        strcpy(dest, argv[1]);   /* fortifiable: replaced by __strcpy_chk */
        strcat(dest, " suffix"); /* fortifiable: replaced by __strcat_chk */
    }
    strcpy(buffer, dest);        /* another fortifiable call */
    printf("%s\n", buffer);
    return 0;
}
