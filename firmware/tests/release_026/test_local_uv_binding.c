#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct file_t {
    uint16_t fid;
    const uint8_t *data;
    uint32_t size;
} file_t;

#define EF_PIN 0x1080
#define EF_KEY_DEV 0xCC00
#define SPECIFY_EF 1

static uint8_t pin_bytes[35] = {8, 4, 1};
static uint8_t key_bytes[33] = {1};
static file_t pin_file = {EF_PIN, pin_bytes, sizeof(pin_bytes)};
static file_t key_file = {EF_KEY_DEV, key_bytes, sizeof(key_bytes)};
file_t *ef_pin = NULL;
file_t *ef_keydev = NULL;

static file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t sp) {
    (void)parent; (void)sp;
    if (fid == EF_PIN) return &pin_file;
    if (fid == EF_KEY_DEV) return &key_file;
    return NULL;
}
static bool file_has_data(const file_t *f) { return f && f->data && f->size; }
static const uint8_t *file_get_data(const file_t *f) { return f ? f->data : NULL; }

#include "../../templates/port/local_uv_binding.h"

int main(void) {
    /* Reproduce the real boot lifecycle: flash records exist, but init_fido()
     * has not populated its convenience globals yet. */
    assert(ef_pin == NULL && ef_keydev == NULL);
    assert(pf_local_uv_pin_file() == &pin_file);
    assert(ef_pin == &pin_file);
    assert(pf_local_uv_bind_keydev_file());
    assert(ef_keydev == &key_file);

    pin_file.data = NULL;
    ef_pin = NULL;
    assert(pf_local_uv_pin_file() == &pin_file);
    assert(ef_pin == &pin_file); /* record exists; readiness checks data separately */

    key_file.data = NULL;
    ef_keydev = NULL;
    assert(!pf_local_uv_bind_keydev_file());
    assert(ef_keydev == NULL);
    puts("PASS R16: local Settings PIN resolves EF_PIN/EF_KEY_DEV before CTAPHID_INIT");
    return 0;
}
