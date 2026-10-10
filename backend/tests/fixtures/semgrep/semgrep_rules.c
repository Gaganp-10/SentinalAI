#include <string.h>
#include <stdlib.h>

void test(char *src, char *cmd) {
    char dest[10];
    // ruleid: c-unsafe-strcpy
    strcpy(dest, src);

    // ruleid: c-system-call
    system(cmd);
}
