/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../EvilKeyV1/src/apps/ek_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f || fseek(f, 0, SEEK_END) != 0) return 1;
    long length = ftell(f);
    if (length < 0 || fseek(f, 0, SEEK_SET) != 0) return 1;
    unsigned char header[EK_PACKAGE_HEADER_SIZE];
    if (fread(header, 1, sizeof(header), f) != sizeof(header)) return 1;
    fclose(f);
    EkPackageInfo info;
    if (!ek_package_parse(header, sizeof(header), (size_t)length, &info) ||
        !info.id[0] || !info.owner[0] || !info.license[0] ||
        info.wasm_size != (size_t)length - EK_PACKAGE_HEADER_SIZE)
        return 1;
    unsigned char bad[EK_PACKAGE_HEADER_SIZE];
    memcpy(bad, header, sizeof(bad));
    memcpy(bad + 22, "../evil", 8);
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    if (ek_package_parse(header, sizeof(header), (size_t)length - 1, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[12] = 2; /* Old ABI packages are no longer supported. */
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[186] = 1;
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[90] = 0; /* Empty owner. */
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[154] = 0; /* Empty license. */
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[153] = 'x'; /* Nonzero bytes after the owner terminator. */
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[154] = '\n'; /* Control characters in metadata. */
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[154] = 0x80; /* License identifiers are ASCII. */
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    memcpy(bad, header, sizeof(bad));
    bad[10] = 1; /* Earlier package format. */
    if (ek_package_parse(bad, sizeof(bad), (size_t)length, &info)) return 1;
    printf("Package: header, id and exact length validated; traversal rejected\n");
    return 0;
}
