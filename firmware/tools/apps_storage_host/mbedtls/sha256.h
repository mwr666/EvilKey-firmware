#pragma once
#include <stddef.h>
#include <stdint.h>
typedef struct { int unused; } mbedtls_sha256_context;
static inline void mbedtls_sha256_init(mbedtls_sha256_context *) {}
static inline int mbedtls_sha256_starts(mbedtls_sha256_context *, int) { return 0; }
static inline int mbedtls_sha256_update(mbedtls_sha256_context *, const uint8_t *, size_t) { return 0; }
static inline int mbedtls_sha256_finish(mbedtls_sha256_context *, uint8_t *out) {
    for (unsigned i = 0; i < 32; ++i) out[i] = 0;
    return 0;
}
static inline void mbedtls_sha256_free(mbedtls_sha256_context *) {}
/* Deliberately not cryptographic: exercise the caller's icon mismatch branch.
 * Real SHA-256 is checked by package tools and the ESP32 mbedTLS build. */
static inline int mbedtls_sha256(const uint8_t *data,size_t size,uint8_t *out,int) {
    for(unsigned i=0;i<32;++i) out[i]=0;
    for(size_t i=0;i<size;++i)out[i%32]^=data[i];
    return 0;
}
