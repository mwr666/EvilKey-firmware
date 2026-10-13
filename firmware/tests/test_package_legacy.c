/* SPDX-License-Identifier: MIT */
/* Compile against the released parser, not the extension parser. */
#include <assert.h>
#include <stdio.h>
#include "ek_package.h"
int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb"); assert(f);
    unsigned char header[EK_PACKAGE_HEADER_SIZE];
    assert(fread(header, 1, sizeof header, f) == sizeof header);
    assert(fseek(f, 0, SEEK_END) == 0);
    long total = ftell(f); fclose(f); assert(total > 0);
    EkPackageInfo info;
    assert(header[14] == 1 && header[15] == 0);
    assert(ek_package_parse(header, sizeof header, (size_t)total, &info) == 0);
    header[14] = 0;
    assert(ek_package_parse(header, sizeof header, (size_t)total, &info) == 1);
    puts("LEGACY PACKAGE PASS released parser rejects sdmesh1 before VM; feature0 accepted");
    return 0;
}
