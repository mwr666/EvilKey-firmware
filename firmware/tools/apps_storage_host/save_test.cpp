/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Host test of the production microSD save code with an in-memory File mock.
 * Package hashing is not exercised by this test.
 */
#include "SD.h"
#include "../../EvilKeyV1/src/apps/ek_storage.h"
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr,"CHECK failed: %s at line %d\n",#condition,__LINE__); \
        return 1; \
    } \
} while (0)

SDClass SD;
static uint32_t fake_ms = 1000;
uint32_t millis(void) { return fake_ms; }
extern "C" bool pf_apps_storage_role_allowed(void) { return true; }

int main(void) {
    CHECK(ek_storage_begin());
    uint8_t first[4096], second[4096], output[4096];
    memset(first, 0x39, sizeof(first));
    memset(second, 0xa6, sizeof(second));
    size_t size = 77;
    CHECK(!ek_storage_save_load("example", output, sizeof(output), &size));
    CHECK(size == 0);
    CHECK(ek_storage_save_write("example", first, sizeof(first), nullptr, nullptr));
    CHECK(SD.save.size() == 9216); /* two nine-sector records */
    CHECK(ek_storage_save_load("example", output, sizeof(output), &size));
    CHECK(size == sizeof(first) && !memcmp(first, output, size));
    CHECK(!ek_storage_save_write("example", second, sizeof(second), nullptr, nullptr));
    fake_ms += 1000;
    CHECK(ek_storage_save_write("example", second, sizeof(second), nullptr, nullptr));
    CHECK(ek_storage_save_load("example", output, sizeof(output), &size));
    CHECK(size == sizeof(second) && !memcmp(second, output, size));

    /* Simulate a torn write to the sector at the start of newer slot 1.
     * Older slot 0 retains its full 4096-byte payload and must still load. */
    memset(SD.save.data() + 4608, 0xff, 512);
    CHECK(ek_storage_save_load("example", output, sizeof(output), &size));
    CHECK(size == sizeof(first) && !memcmp(first, output, size));

    fake_ms += 1000;
    CHECK(ek_storage_save_write("example", nullptr, 0, nullptr, nullptr));
    size = 77;
    CHECK(ek_storage_save_load("example", output, sizeof(output), &size));
    CHECK(size == 0); /* valid empty save is distinct from a missing file */
    ek_storage_end();
    puts("EvilKey save host checks: alignment, rollback, empty record and rate limit OK");
    return 0;
}
