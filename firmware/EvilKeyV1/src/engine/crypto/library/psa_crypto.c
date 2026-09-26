#include "../../../pf_build_config.h"
/*
 *  PSA crypto layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"
#include "psa_crypto_core_common.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_C)

#if defined(PF_MBEDTLS_PSA_CRYPTO_CONFIG)
#include "check_crypto_config.h"
#endif

#include "../include/psa/crypto.h"
#include "../include/psa/crypto_values.h"

#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "psa_crypto_invasive.h"
#include "psa_crypto_driver_wrappers.h"
#include "psa_crypto_driver_wrappers_no_static.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_ffdh.h"
#include "psa_crypto_hash.h"
#include "psa_crypto_mac.h"
#include "psa_crypto_rsa.h"
#include "psa_crypto_ecp.h"
#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
#include "psa_crypto_se.h"
#endif
#include "psa_crypto_slot_management.h"
/* Include internal declarations that are useful for implementing persistently
 * stored keys. */
#include "psa_crypto_storage.h"

#include "psa_crypto_random.h"
#include "psa_crypto_random_impl.h"

#include <stdlib.h>
#include <string.h>
#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/aes.h"
#include "../include/mbedtls/asn1.h"
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/bignum.h"
#include "../include/mbedtls/camellia.h"
#include "../include/mbedtls/chacha20.h"
#include "../include/mbedtls/chachapoly.h"
#include "../include/mbedtls/cipher.h"
#include "../include/mbedtls/ccm.h"
#include "../include/mbedtls/cmac.h"
#include "../include/mbedtls/constant_time.h"
#include "../include/mbedtls/des.h"
#include "../include/mbedtls/ecdh.h"
#include "../include/mbedtls/ecp.h"
#include "../include/mbedtls/entropy.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/gcm.h"
#include "../include/mbedtls/md5.h"
#include "../include/mbedtls/pk.h"
#include "pk_wrap.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/ripemd160.h"
#include "../include/mbedtls/rsa.h"
#include "../include/mbedtls/sha1.h"
#include "../include/mbedtls/sha256.h"
#include "../include/mbedtls/sha512.h"
#include "../include/mbedtls/psa_util.h"
#include "../include/mbedtls/threading.h"

#include "constant_time_internal.h"

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF) ||          \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT) ||  \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
#define BUILTIN_ALG_ANY_HKDF 1
#endif

/****************************************************************/
/* Global data, support functions and library management */
/****************************************************************/

static int key_type_is_raw_bytes(pf_psa_key_type_t type)
{
    return PF_PSA_KEY_TYPE_IS_UNSTRUCTURED(type);
}

/* Values for psa_global_data_t::rng_state */
#define RNG_NOT_INITIALIZED 0
#define RNG_INITIALIZED 1
#define RNG_SEEDED 2

/* IDs for PSA crypto subsystems. Starts at 1 to catch potential uninitialized
 * variables as arguments. */
typedef enum {
    PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS = 1,
    PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS,
    PF_PSA_CRYPTO_SUBSYSTEM_RNG,
    PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION,
} pf_mbedtls_psa_crypto_subsystem;

/* Initialization flags for global_data::initialized */
#define PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED    0x01
#define PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED          0x02
#define PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED        0x04

#define PF_PSA_CRYPTO_SUBSYSTEM_ALL_INITIALISED                ( \
        PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED | \
        PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED | \
        PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED)

typedef struct {
    uint8_t initialized;
    uint8_t rng_state;
    pf_mbedtls_psa_random_context_t rng;
} pf_psa_global_data_t;

static pf_psa_global_data_t global_data;

static uint8_t pf_psa_get_initialized(void)
{
    uint8_t initialized;

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    initialized = global_data.rng_state == RNG_SEEDED;

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    initialized =
        (initialized && (global_data.initialized == PF_PSA_CRYPTO_SUBSYSTEM_ALL_INITIALISED));

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    return initialized;
}

static uint8_t pf_psa_get_drivers_initialized(void)
{
    uint8_t initialized;

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    initialized = (global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED) != 0;

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    return initialized;
}

#define GUARD_MODULE_INITIALIZED        \
    if (pf_psa_get_initialized() == 0)     \
    return PF_PSA_ERROR_BAD_STATE;

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)

/* Declare a local copy of an input buffer and a variable that will be used
 * to store a pointer to the start of the buffer.
 *
 * Note: This macro must be called before any operations which may jump to
 * the exit label, so that the local input copy object is safe to be freed.
 *
 * Assumptions:
 * - input is the name of a pointer to the buffer to be copied
 * - The name LOCAL_INPUT_COPY_OF_input is unused in the current scope
 * - input_copy_name is a name that is unused in the current scope
 */
#define LOCAL_INPUT_DECLARE(input, input_copy_name) \
    pf_psa_crypto_local_input_t LOCAL_INPUT_COPY_OF_##input = PF_PSA_CRYPTO_LOCAL_INPUT_INIT; \
    const uint8_t *input_copy_name = NULL;

/* Allocate a copy of the buffer input and set the pointer input_copy to
 * point to the start of the copy.
 *
 * Assumptions:
 * - psa_status_t status exists
 * - An exit label is declared
 * - input is the name of a pointer to the buffer to be copied
 * - LOCAL_INPUT_DECLARE(input, input_copy) has previously been called
 */
#define LOCAL_INPUT_ALLOC(input, length, input_copy) \
    status = pf_psa_crypto_local_input_alloc(input, length, \
                                          &LOCAL_INPUT_COPY_OF_##input); \
    if (status != PF_PSA_SUCCESS) { \
        goto exit; \
    } \
    input_copy = LOCAL_INPUT_COPY_OF_##input.buffer;

/* Free the local input copy allocated previously by LOCAL_INPUT_ALLOC()
 *
 * Assumptions:
 * - input_copy is the name of the input copy pointer set by LOCAL_INPUT_ALLOC()
 * - input is the name of the original buffer that was copied
 */
#define LOCAL_INPUT_FREE(input, input_copy) \
    input_copy = NULL; \
    pf_psa_crypto_local_input_free(&LOCAL_INPUT_COPY_OF_##input);

/* Declare a local copy of an output buffer and a variable that will be used
 * to store a pointer to the start of the buffer.
 *
 * Note: This macro must be called before any operations which may jump to
 * the exit label, so that the local output copy object is safe to be freed.
 *
 * Assumptions:
 * - output is the name of a pointer to the buffer to be copied
 * - The name LOCAL_OUTPUT_COPY_OF_output is unused in the current scope
 * - output_copy_name is a name that is unused in the current scope
 */
#define LOCAL_OUTPUT_DECLARE(output, output_copy_name) \
    pf_psa_crypto_local_output_t LOCAL_OUTPUT_COPY_OF_##output = PF_PSA_CRYPTO_LOCAL_OUTPUT_INIT; \
    uint8_t *output_copy_name = NULL;

/* Allocate a copy of the buffer output and set the pointer output_copy to
 * point to the start of the copy.
 *
 * Assumptions:
 * - psa_status_t status exists
 * - An exit label is declared
 * - output is the name of a pointer to the buffer to be copied
 * - LOCAL_OUTPUT_DECLARE(output, output_copy) has previously been called
 */
#define LOCAL_OUTPUT_ALLOC(output, length, output_copy) \
    status = pf_psa_crypto_local_output_alloc(output, length, \
                                           &LOCAL_OUTPUT_COPY_OF_##output); \
    if (status != PF_PSA_SUCCESS) { \
        goto exit; \
    } \
    output_copy = LOCAL_OUTPUT_COPY_OF_##output.buffer;

/* Free the local output copy allocated previously by LOCAL_OUTPUT_ALLOC()
 * after first copying back its contents to the original buffer.
 *
 * Assumptions:
 * - psa_status_t status exists
 * - output_copy is the name of the output copy pointer set by LOCAL_OUTPUT_ALLOC()
 * - output is the name of the original buffer that was copied
 */
#define LOCAL_OUTPUT_FREE(output, output_copy) \
    output_copy = NULL; \
    do { \
        pf_psa_status_t local_output_status; \
        local_output_status = pf_psa_crypto_local_output_free(&LOCAL_OUTPUT_COPY_OF_##output); \
        if (local_output_status != PF_PSA_SUCCESS) { \
            /* Since this error case is an internal error, it's more serious than \
             * any existing error code and so it's fine to overwrite the existing \
             * status. */ \
            status = local_output_status; \
        } \
    } while (0)
#else /* !MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS */
#define LOCAL_INPUT_DECLARE(input, input_copy_name) \
    const uint8_t *input_copy_name = NULL;
#define LOCAL_INPUT_ALLOC(input, length, input_copy) \
    input_copy = input;
#define LOCAL_INPUT_FREE(input, input_copy) \
    input_copy = NULL;
#define LOCAL_OUTPUT_DECLARE(output, output_copy_name) \
    uint8_t *output_copy_name = NULL;
#define LOCAL_OUTPUT_ALLOC(output, length, output_copy) \
    output_copy = output;
#define LOCAL_OUTPUT_FREE(output, output_copy) \
    output_copy = NULL;
#endif /* !MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS */


int pf_psa_can_do_hash(pf_psa_algorithm_t hash_alg)
{
    (void) hash_alg;
    return pf_psa_get_drivers_initialized();
}

int pf_psa_can_do_cipher(pf_psa_key_type_t key_type, pf_psa_algorithm_t cipher_alg)
{
    (void) key_type;
    (void) cipher_alg;
    return pf_psa_get_drivers_initialized();
}


#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT) ||       \
    defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY) ||     \
    defined(PF_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE)
static int pf_psa_is_dh_key_size_valid(size_t bits)
{
    switch (bits) {
#if defined(PF_PSA_WANT_DH_RFC7919_2048)
        case 2048:
            return 1;
#endif /* PSA_WANT_DH_RFC7919_2048 */
#if defined(PF_PSA_WANT_DH_RFC7919_3072)
        case 3072:
            return 1;
#endif /* PSA_WANT_DH_RFC7919_3072 */
#if defined(PF_PSA_WANT_DH_RFC7919_4096)
        case 4096:
            return 1;
#endif /* PSA_WANT_DH_RFC7919_4096 */
#if defined(PF_PSA_WANT_DH_RFC7919_6144)
        case 6144:
            return 1;
#endif /* PSA_WANT_DH_RFC7919_6144 */
#if defined(PF_PSA_WANT_DH_RFC7919_8192)
        case 8192:
            return 1;
#endif /* PSA_WANT_DH_RFC7919_8192 */
        default:
            return 0;
    }
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT ||
          MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY ||
          PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE */

pf_psa_status_t pf_mbedtls_to_psa_error(int ret)
{
    /* Mbed TLS error codes can combine a high-level error code and a
     * low-level error code. The low-level error usually reflects the
     * root cause better, so dispatch on that preferably. */
    int low_level_ret = -(-ret & 0x007f);
    switch (low_level_ret != 0 ? low_level_ret : ret) {
        case 0:
            return PF_PSA_SUCCESS;

#if defined(PF_MBEDTLS_AES_C)
        case PF_MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
        case PF_MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_AES_BAD_INPUT_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
#endif

#if defined(PF_MBEDTLS_ASN1_PARSE_C) || defined(PF_MBEDTLS_ASN1_WRITE_C)
        case PF_MBEDTLS_ERR_ASN1_OUT_OF_DATA:
        case PF_MBEDTLS_ERR_ASN1_UNEXPECTED_TAG:
        case PF_MBEDTLS_ERR_ASN1_INVALID_LENGTH:
        case PF_MBEDTLS_ERR_ASN1_LENGTH_MISMATCH:
        case PF_MBEDTLS_ERR_ASN1_INVALID_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_ASN1_ALLOC_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        case PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
            return PF_PSA_ERROR_BUFFER_TOO_SMALL;
#endif

#if defined(PF_MBEDTLS_CAMELLIA_C)
        case PF_MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA:
        case PF_MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH:
            return PF_PSA_ERROR_NOT_SUPPORTED;
#endif

#if defined(PF_MBEDTLS_CCM_C)
        case PF_MBEDTLS_ERR_CCM_BAD_INPUT:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_CCM_AUTH_FAILED:
            return PF_PSA_ERROR_INVALID_SIGNATURE;
#endif

#if defined(PF_MBEDTLS_CHACHA20_C)
        case PF_MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
#endif

#if defined(PF_MBEDTLS_CHACHAPOLY_C)
        case PF_MBEDTLS_ERR_CHACHAPOLY_BAD_STATE:
            return PF_PSA_ERROR_BAD_STATE;
        case PF_MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED:
            return PF_PSA_ERROR_INVALID_SIGNATURE;
#endif

#if defined(PF_MBEDTLS_CIPHER_C)
        case PF_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        case PF_MBEDTLS_ERR_CIPHER_INVALID_PADDING:
            return PF_PSA_ERROR_INVALID_PADDING;
        case PF_MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_CIPHER_AUTH_FAILED:
            return PF_PSA_ERROR_INVALID_SIGNATURE;
        case PF_MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
            return PF_PSA_ERROR_CORRUPTION_DETECTED;
#endif

#if !(defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) ||      \
            defined(PF_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE))
        /* Only check CTR_DRBG error codes if underlying mbedtls_xxx
         * functions are passed a CTR_DRBG instance. */
        case PF_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;
        case PF_MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
        case PF_MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:
            return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;
#endif

#if defined(PF_MBEDTLS_DES_C)
        case PF_MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH:
            return PF_PSA_ERROR_NOT_SUPPORTED;
#endif

        case PF_MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED:
        case PF_MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE:
        case PF_MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;

#if defined(PF_MBEDTLS_GCM_C)
        case PF_MBEDTLS_ERR_GCM_AUTH_FAILED:
            return PF_PSA_ERROR_INVALID_SIGNATURE;
        case PF_MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL:
            return PF_PSA_ERROR_BUFFER_TOO_SMALL;
        case PF_MBEDTLS_ERR_GCM_BAD_INPUT:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
#endif

#if !defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) &&        \
            defined(PF_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE)
        /* Only check HMAC_DRBG error codes if underlying mbedtls_xxx
         * functions are passed a HMAC_DRBG instance. */
        case PF_MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;
        case PF_MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG:
        case PF_MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR:
            return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;
#endif

#if defined(PF_MBEDTLS_MD_LIGHT)
        case PF_MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_MD_ALLOC_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
#if defined(PF_MBEDTLS_FS_IO)
        case PF_MBEDTLS_ERR_MD_FILE_IO_ERROR:
            return PF_PSA_ERROR_STORAGE_FAILURE;
#endif
#endif

#if defined(PF_MBEDTLS_BIGNUM_C)
#if defined(PF_MBEDTLS_FS_IO)
        case PF_MBEDTLS_ERR_MPI_FILE_IO_ERROR:
            return PF_PSA_ERROR_STORAGE_FAILURE;
#endif
        case PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_MPI_INVALID_CHARACTER:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
            return PF_PSA_ERROR_BUFFER_TOO_SMALL;
        case PF_MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_MPI_ALLOC_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
#endif

#if defined(PF_MBEDTLS_PK_C)
        case PF_MBEDTLS_ERR_PK_ALLOC_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        case PF_MBEDTLS_ERR_PK_TYPE_MISMATCH:
        case PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
#if defined(PF_MBEDTLS_PSA_CRYPTO_STORAGE_C) || defined(PF_MBEDTLS_FS_IO) || \
            defined(PF_MBEDTLS_PSA_ITS_FILE_C)
        case PF_MBEDTLS_ERR_PK_FILE_IO_ERROR:
            return PF_PSA_ERROR_STORAGE_FAILURE;
#endif
        case PF_MBEDTLS_ERR_PK_KEY_INVALID_VERSION:
        case PF_MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
        case PF_MBEDTLS_ERR_PK_PASSWORD_MISMATCH:
            return PF_PSA_ERROR_NOT_PERMITTED;
        case PF_MBEDTLS_ERR_PK_INVALID_PUBKEY:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_PK_INVALID_ALG:
        case PF_MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE:
        case PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH:
            return PF_PSA_ERROR_INVALID_SIGNATURE;
        case PF_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL:
            return PF_PSA_ERROR_BUFFER_TOO_SMALL;
#endif

        case PF_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED:
            return PF_PSA_ERROR_HARDWARE_FAILURE;
        case PF_MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED:
            return PF_PSA_ERROR_NOT_SUPPORTED;

#if defined(PF_MBEDTLS_RSA_C)
        case PF_MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_RSA_INVALID_PADDING:
            return PF_PSA_ERROR_INVALID_PADDING;
        case PF_MBEDTLS_ERR_RSA_KEY_GEN_FAILED:
            return PF_PSA_ERROR_HARDWARE_FAILURE;
        case PF_MBEDTLS_ERR_RSA_KEY_CHECK_FAILED:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_RSA_PUBLIC_FAILED:
        case PF_MBEDTLS_ERR_RSA_PRIVATE_FAILED:
            return PF_PSA_ERROR_CORRUPTION_DETECTED;
        case PF_MBEDTLS_ERR_RSA_VERIFY_FAILED:
            return PF_PSA_ERROR_INVALID_SIGNATURE;
        case PF_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
            return PF_PSA_ERROR_BUFFER_TOO_SMALL;
        case PF_MBEDTLS_ERR_RSA_RNG_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;
#endif

#if defined(PF_MBEDTLS_ECP_LIGHT)
        case PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
        case PF_MBEDTLS_ERR_ECP_INVALID_KEY:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        case PF_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
            return PF_PSA_ERROR_BUFFER_TOO_SMALL;
        case PF_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE:
            return PF_PSA_ERROR_NOT_SUPPORTED;
        case PF_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:
        case PF_MBEDTLS_ERR_ECP_VERIFY_FAILED:
            return PF_PSA_ERROR_INVALID_SIGNATURE;
        case PF_MBEDTLS_ERR_ECP_ALLOC_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        case PF_MBEDTLS_ERR_ECP_RANDOM_FAILED:
            return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
        case PF_MBEDTLS_ERR_ECP_IN_PROGRESS:
            return PF_PSA_OPERATION_INCOMPLETE;
#endif
#endif

        case PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:
            return PF_PSA_ERROR_CORRUPTION_DETECTED;

        default:
            return PF_PSA_ERROR_GENERIC_ERROR;
    }
}

/**
 * \brief                       For output buffers which contain "tags"
 *                              (outputs that may be checked for validity like
 *                              hashes, MACs and signatures), fill the unused
 *                              part of the output buffer (the whole buffer on
 *                              error, the trailing part on success) with
 *                              something that isn't a valid tag (barring an
 *                              attack on the tag and deliberately-crafted
 *                              input), in case the caller doesn't check the
 *                              return status properly.
 *
 * \param output_buffer         Pointer to buffer to wipe. May not be NULL
 *                              unless \p output_buffer_size is zero.
 * \param status                Status of function called to generate
 *                              output_buffer originally
 * \param output_buffer_size    Size of output buffer. If zero, \p output_buffer
 *                              could be NULL.
 * \param output_buffer_length  Length of data written to output_buffer, must be
 *                              less than \p output_buffer_size
 */
static void pf_psa_wipe_tag_output_buffer(uint8_t *output_buffer, pf_psa_status_t status,
                                       size_t output_buffer_size, size_t output_buffer_length)
{
    size_t offset = 0;

    if (output_buffer_size == 0) {
        /* If output_buffer_size is 0 then we have nothing to do. We must not
           call memset because output_buffer may be NULL in this case */
        return;
    }

    if (status == PF_PSA_SUCCESS) {
        offset = output_buffer_length;
    }

    memset(output_buffer + offset, '!', output_buffer_size - offset);
}


pf_psa_status_t pf_psa_validate_unstructured_key_bit_size(pf_psa_key_type_t type,
                                                    size_t bits)
{
    /* Check that the bit size is acceptable for the key type */
    switch (type) {
        case PF_PSA_KEY_TYPE_RAW_DATA:
        case PF_PSA_KEY_TYPE_HMAC:
        case PF_PSA_KEY_TYPE_DERIVE:
        case PF_PSA_KEY_TYPE_PASSWORD:
        case PF_PSA_KEY_TYPE_PASSWORD_HASH:
            break;
#if defined(PF_PSA_WANT_KEY_TYPE_AES)
        case PF_PSA_KEY_TYPE_AES:
            if (bits != 128 && bits != 192 && bits != 256) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PF_PSA_WANT_KEY_TYPE_ARIA)
        case PF_PSA_KEY_TYPE_ARIA:
            if (bits != 128 && bits != 192 && bits != 256) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PF_PSA_WANT_KEY_TYPE_CAMELLIA)
        case PF_PSA_KEY_TYPE_CAMELLIA:
            if (bits != 128 && bits != 192 && bits != 256) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PF_PSA_WANT_KEY_TYPE_DES)
        case PF_PSA_KEY_TYPE_DES:
            if (bits != 64 && bits != 128 && bits != 192) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PF_PSA_WANT_KEY_TYPE_CHACHA20)
        case PF_PSA_KEY_TYPE_CHACHA20:
            if (bits != 256) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
        default:
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }
    if (bits % 8 != 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    return PF_PSA_SUCCESS;
}

/** Check whether a given key type is valid for use with a given MAC algorithm
 *
 * Upon successful return of this function, the behavior of #PSA_MAC_LENGTH
 * when called with the validated \p algorithm and \p key_type is well-defined.
 *
 * \param[in] algorithm     The specific MAC algorithm (can be wildcard).
 * \param[in] key_type      The key type of the key to be used with the
 *                          \p algorithm.
 *
 * \retval #PSA_SUCCESS
 *         The \p key_type is valid for use with the \p algorithm
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p key_type is not valid for use with the \p algorithm
 */
PF_MBEDTLS_STATIC_TESTABLE pf_psa_status_t pf_psa_mac_key_can_do(
    pf_psa_algorithm_t algorithm,
    pf_psa_key_type_t key_type)
{
    if (PF_PSA_ALG_IS_HMAC(algorithm)) {
        if (key_type == PF_PSA_KEY_TYPE_HMAC) {
            return PF_PSA_SUCCESS;
        }
    }

    if (PF_PSA_ALG_IS_BLOCK_CIPHER_MAC(algorithm)) {
        /* Check that we're calling PSA_BLOCK_CIPHER_BLOCK_LENGTH with a cipher
         * key. */
        if ((key_type & PF_PSA_KEY_TYPE_CATEGORY_MASK) ==
            PF_PSA_KEY_TYPE_CATEGORY_SYMMETRIC) {
            /* PSA_BLOCK_CIPHER_BLOCK_LENGTH returns 1 for stream ciphers and
             * the block length (larger than 1) for block ciphers. */
            if (PF_PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) > 1) {
                return PF_PSA_SUCCESS;
            }
        }
    }

    return PF_PSA_ERROR_INVALID_ARGUMENT;
}

pf_psa_status_t pf_psa_allocate_buffer_to_slot(pf_psa_key_slot_t *slot,
                                         size_t buffer_length)
{
#if defined(PF_MBEDTLS_PSA_STATIC_KEY_SLOTS)
    if (buffer_length > ((size_t) PF_MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }
#else
    if (slot->key.data != NULL) {
        return PF_PSA_ERROR_ALREADY_EXISTS;
    }

    slot->key.data = pf_mbedtls_calloc(1, buffer_length);
    if (slot->key.data == NULL) {
        return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#endif

    slot->key.bytes = buffer_length;
    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_copy_key_material_into_slot(pf_psa_key_slot_t *slot,
                                             const uint8_t *data,
                                             size_t data_length)
{
    pf_psa_status_t status = pf_psa_allocate_buffer_to_slot(slot,
                                                      data_length);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    memcpy(slot->key.data, data, data_length);
    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_import_key_into_slot(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_type_t type = attributes->type;

    /* zero-length keys are never supported. */
    if (data_length == 0) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_type_is_raw_bytes(type)) {
        *bits = PF_PSA_BYTES_TO_BITS(data_length);

        status = pf_psa_validate_unstructured_key_bit_size(attributes->type,
                                                        *bits);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }

        /* Copy the key material. */
        memcpy(key_buffer, data, data_length);
        *key_buffer_length = data_length;
        (void) key_buffer_size;

        return PF_PSA_SUCCESS;
    } else if (PF_PSA_KEY_TYPE_IS_ASYMMETRIC(type)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT) || \
        defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY)
        if (PF_PSA_KEY_TYPE_IS_DH(type)) {
            if (pf_psa_is_dh_key_size_valid(PF_PSA_BYTES_TO_BITS(data_length)) == 0) {
                return PF_PSA_ERROR_NOT_SUPPORTED;
            }
            return pf_mbedtls_psa_ffdh_import_key(attributes,
                                               data, data_length,
                                               key_buffer, key_buffer_size,
                                               key_buffer_length,
                                               bits);
        }
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY) */
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
        defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)
        if (PF_PSA_KEY_TYPE_IS_ECC(type)) {
            return pf_mbedtls_psa_ecp_import_key(attributes,
                                              data, data_length,
                                              key_buffer, key_buffer_size,
                                              key_buffer_length,
                                              bits);
        }
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) */
#if (defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT) && \
        defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT)) || \
        defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
        if (PF_PSA_KEY_TYPE_IS_RSA(type)) {
            return pf_mbedtls_psa_rsa_import_key(attributes,
                                              data, data_length,
                                              key_buffer, key_buffer_size,
                                              key_buffer_length,
                                              bits);
        }
#endif /* (defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT) &&
           defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT)) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */
    }

    return PF_PSA_ERROR_NOT_SUPPORTED;
}

/** Calculate the intersection of two algorithm usage policies.
 *
 * Return 0 (which allows no operation) on incompatibility.
 */
static pf_psa_algorithm_t pf_psa_key_policy_algorithm_intersection(
    pf_psa_key_type_t key_type,
    pf_psa_algorithm_t alg1,
    pf_psa_algorithm_t alg2)
{
    /* Common case: both sides actually specify the same policy. */
    if (alg1 == alg2) {
        return alg1;
    }
    /* If the policies are from the same hash-and-sign family, check
     * if one is a wildcard. If so the other has the specific algorithm. */
    if (PF_PSA_ALG_IS_SIGN_HASH(alg1) &&
        PF_PSA_ALG_IS_SIGN_HASH(alg2) &&
        (alg1 & ~PF_PSA_ALG_HASH_MASK) == (alg2 & ~PF_PSA_ALG_HASH_MASK)) {
        if (PF_PSA_ALG_SIGN_GET_HASH(alg1) == PF_PSA_ALG_ANY_HASH) {
            return alg2;
        }
        if (PF_PSA_ALG_SIGN_GET_HASH(alg2) == PF_PSA_ALG_ANY_HASH) {
            return alg1;
        }
    }
    /* If the policies are from the same AEAD family, check whether
     * one of them is a minimum-tag-length wildcard. Calculate the most
     * restrictive tag length. */
    if (PF_PSA_ALG_IS_AEAD(alg1) && PF_PSA_ALG_IS_AEAD(alg2) &&
        (PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg1, 0) ==
         PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg2, 0))) {
        size_t alg1_len = PF_PSA_ALG_AEAD_GET_TAG_LENGTH(alg1);
        size_t alg2_len = PF_PSA_ALG_AEAD_GET_TAG_LENGTH(alg2);
        size_t restricted_len = alg1_len > alg2_len ? alg1_len : alg2_len;

        /* If both are wildcards, return most restrictive wildcard */
        if (((alg1 & PF_PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            ((alg2 & PF_PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0)) {
            return PF_PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                alg1, restricted_len);
        }
        /* If only one is a wildcard, return specific algorithm if compatible. */
        if (((alg1 & PF_PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            (alg1_len <= alg2_len)) {
            return alg2;
        }
        if (((alg2 & PF_PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            (alg2_len <= alg1_len)) {
            return alg1;
        }
    }
    /* If the policies are from the same MAC family, check whether one
     * of them is a minimum-MAC-length policy. Calculate the most
     * restrictive tag length. */
    if (PF_PSA_ALG_IS_MAC(alg1) && PF_PSA_ALG_IS_MAC(alg2) &&
        (PF_PSA_ALG_FULL_LENGTH_MAC(alg1) ==
         PF_PSA_ALG_FULL_LENGTH_MAC(alg2))) {
        /* Validate the combination of key type and algorithm. Since the base
         * algorithm of alg1 and alg2 are the same, we only need this once. */
        if (PF_PSA_SUCCESS != pf_psa_mac_key_can_do(alg1, key_type)) {
            return 0;
        }

        /* Get the (exact or at-least) output lengths for both sides of the
         * requested intersection. None of the currently supported algorithms
         * have an output length dependent on the actual key size, so setting it
         * to a bogus value of 0 is currently OK.
         *
         * Note that for at-least-this-length wildcard algorithms, the output
         * length is set to the shortest allowed length, which allows us to
         * calculate the most restrictive tag length for the intersection. */
        size_t alg1_len = PF_PSA_MAC_LENGTH(key_type, 0, alg1);
        size_t alg2_len = PF_PSA_MAC_LENGTH(key_type, 0, alg2);
        size_t restricted_len = alg1_len > alg2_len ? alg1_len : alg2_len;

        /* If both are wildcards, return most restrictive wildcard */
        if (((alg1 & PF_PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            ((alg2 & PF_PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0)) {
            return PF_PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(alg1, restricted_len);
        }

        /* If only one is an at-least-this-length policy, the intersection would
         * be the other (fixed-length) policy as long as said fixed length is
         * equal to or larger than the shortest allowed length. */
        if ((alg1 & PF_PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
            return (alg1_len <= alg2_len) ? alg2 : 0;
        }
        if ((alg2 & PF_PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
            return (alg2_len <= alg1_len) ? alg1 : 0;
        }

        /* If none of them are wildcards, check whether they define the same tag
         * length. This is still possible here when one is default-length and
         * the other specific-length. Ensure to always return the
         * specific-length version for the intersection. */
        if (alg1_len == alg2_len) {
            return PF_PSA_ALG_TRUNCATED_MAC(alg1, alg1_len);
        }
    }
    /* If the policies are incompatible, allow nothing. */
    return 0;
}

static int pf_psa_key_algorithm_permits(pf_psa_key_type_t key_type,
                                     pf_psa_algorithm_t policy_alg,
                                     pf_psa_algorithm_t requested_alg)
{
    /* Common case: the policy only allows requested_alg. */
    if (requested_alg == policy_alg) {
        return 1;
    }
    /* If policy_alg is a hash-and-sign with a wildcard for the hash,
     * and requested_alg is the same hash-and-sign family with any hash,
     * then requested_alg is compliant with policy_alg. */
    if (PF_PSA_ALG_IS_SIGN_HASH(requested_alg) &&
        PF_PSA_ALG_SIGN_GET_HASH(policy_alg) == PF_PSA_ALG_ANY_HASH) {
        return (policy_alg & ~PF_PSA_ALG_HASH_MASK) ==
               (requested_alg & ~PF_PSA_ALG_HASH_MASK);
    }
    /* If policy_alg is a wildcard AEAD algorithm of the same base as
     * the requested algorithm, check the requested tag length to be
     * equal-length or longer than the wildcard-specified length. */
    if (PF_PSA_ALG_IS_AEAD(policy_alg) &&
        PF_PSA_ALG_IS_AEAD(requested_alg) &&
        (PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(policy_alg, 0) ==
         PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(requested_alg, 0)) &&
        ((policy_alg & PF_PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0)) {
        return PF_PSA_ALG_AEAD_GET_TAG_LENGTH(policy_alg) <=
               PF_PSA_ALG_AEAD_GET_TAG_LENGTH(requested_alg);
    }
    /* If policy_alg is a MAC algorithm of the same base as the requested
     * algorithm, check whether their MAC lengths are compatible. */
    if (PF_PSA_ALG_IS_MAC(policy_alg) &&
        PF_PSA_ALG_IS_MAC(requested_alg) &&
        (PF_PSA_ALG_FULL_LENGTH_MAC(policy_alg) ==
         PF_PSA_ALG_FULL_LENGTH_MAC(requested_alg))) {
        /* Validate the combination of key type and algorithm. Since the policy
         * and requested algorithms are the same, we only need this once. */
        if (PF_PSA_SUCCESS != pf_psa_mac_key_can_do(policy_alg, key_type)) {
            return 0;
        }

        /* Get both the requested output length for the algorithm which is to be
         * verified, and the default output length for the base algorithm.
         * Note that none of the currently supported algorithms have an output
         * length dependent on actual key size, so setting it to a bogus value
         * of 0 is currently OK. */
        size_t requested_output_length = PF_PSA_MAC_LENGTH(
            key_type, 0, requested_alg);
        size_t default_output_length = PF_PSA_MAC_LENGTH(
            key_type, 0,
            PF_PSA_ALG_FULL_LENGTH_MAC(requested_alg));

        /* If the policy is default-length, only allow an algorithm with
         * a declared exact-length matching the default. */
        if (PF_PSA_MAC_TRUNCATED_LENGTH(policy_alg) == 0) {
            return requested_output_length == default_output_length;
        }

        /* If the requested algorithm is default-length, allow it if the policy
         * length exactly matches the default length. */
        if (PF_PSA_MAC_TRUNCATED_LENGTH(requested_alg) == 0 &&
            PF_PSA_MAC_TRUNCATED_LENGTH(policy_alg) == default_output_length) {
            return 1;
        }

        /* If policy_alg is an at-least-this-length wildcard MAC algorithm,
         * check for the requested MAC length to be equal to or longer than the
         * minimum allowed length. */
        if ((policy_alg & PF_PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
            return PF_PSA_MAC_TRUNCATED_LENGTH(policy_alg) <=
                   requested_output_length;
        }
    }
    /* If policy_alg is a generic key agreement operation, then using it for
     * a key derivation with that key agreement should also be allowed. This
     * behaviour is expected to be defined in a future specification version. */
    if (PF_PSA_ALG_IS_RAW_KEY_AGREEMENT(policy_alg) &&
        PF_PSA_ALG_IS_KEY_AGREEMENT(requested_alg)) {
        return PF_PSA_ALG_KEY_AGREEMENT_GET_BASE(requested_alg) ==
               policy_alg;
    }
    /* If it isn't explicitly permitted, it's forbidden. */
    return 0;
}

/** Test whether a policy permits an algorithm.
 *
 * The caller must test usage flags separately.
 *
 * \note This function requires providing the key type for which the policy is
 *       being validated, since some algorithm policy definitions (e.g. MAC)
 *       have different properties depending on what kind of cipher it is
 *       combined with.
 *
 * \retval PSA_SUCCESS                  When \p alg is a specific algorithm
 *                                      allowed by the \p policy.
 * \retval PSA_ERROR_INVALID_ARGUMENT   When \p alg is not a specific algorithm
 * \retval PSA_ERROR_NOT_PERMITTED      When \p alg is a specific algorithm, but
 *                                      the \p policy does not allow it.
 */
static pf_psa_status_t pf_psa_key_policy_permits(const pf_psa_key_policy_t *policy,
                                           pf_psa_key_type_t key_type,
                                           pf_psa_algorithm_t alg)
{
    /* '0' is not a valid algorithm */
    if (alg == 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    /* A requested algorithm cannot be a wildcard. */
    if (PF_PSA_ALG_IS_WILDCARD(alg)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (pf_psa_key_algorithm_permits(key_type, policy->alg, alg) ||
        pf_psa_key_algorithm_permits(key_type, policy->alg2, alg)) {
        return PF_PSA_SUCCESS;
    } else {
        return PF_PSA_ERROR_NOT_PERMITTED;
    }
}

/** Restrict a key policy based on a constraint.
 *
 * \note This function requires providing the key type for which the policy is
 *       being restricted, since some algorithm policy definitions (e.g. MAC)
 *       have different properties depending on what kind of cipher it is
 *       combined with.
 *
 * \param[in] key_type      The key type for which to restrict the policy
 * \param[in,out] policy    The policy to restrict.
 * \param[in] constraint    The policy constraint to apply.
 *
 * \retval #PSA_SUCCESS
 *         \c *policy contains the intersection of the original value of
 *         \c *policy and \c *constraint.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \c key_type, \c *policy and \c *constraint are incompatible.
 *         \c *policy is unchanged.
 */
static pf_psa_status_t pf_psa_restrict_key_policy(
    pf_psa_key_type_t key_type,
    pf_psa_key_policy_t *policy,
    const pf_psa_key_policy_t *constraint)
{
    pf_psa_algorithm_t intersection_alg =
        pf_psa_key_policy_algorithm_intersection(key_type, policy->alg,
                                              constraint->alg);
    pf_psa_algorithm_t intersection_alg2 =
        pf_psa_key_policy_algorithm_intersection(key_type, policy->alg2,
                                              constraint->alg2);
    if (intersection_alg == 0 && policy->alg != 0 && constraint->alg != 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
    if (intersection_alg2 == 0 && policy->alg2 != 0 && constraint->alg2 != 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
    policy->usage &= constraint->usage;
    policy->alg = intersection_alg;
    policy->alg2 = intersection_alg2;
    return PF_PSA_SUCCESS;
}

/** Get the description of a key given its identifier and policy constraints
 *  and lock it.
 *
 * The key must have allow all the usage flags set in \p usage. If \p alg is
 * nonzero, the key must allow operations with this algorithm. If \p alg is
 * zero, the algorithm is not checked.
 *
 * In case of a persistent key, the function loads the description of the key
 * into a key slot if not already done.
 *
 * On success, the returned key slot has been registered for reading.
 * It is the responsibility of the caller to then unregister
 * once they have finished reading the contents of the slot.
 * The caller unregisters by calling psa_unregister_read() or
 * psa_unregister_read_under_mutex(). psa_unregister_read() must be called
 * if and only if the caller already holds the global key slot mutex
 * (when mutexes are enabled). psa_unregister_read_under_mutex() encapsulates
 * the unregister with mutex lock and unlock operations.
 */
static pf_psa_status_t pf_psa_get_and_lock_key_slot_with_policy(
    pf_mbedtls_svc_key_id_t key,
    pf_psa_key_slot_t **p_slot,
    pf_psa_key_usage_t usage,
    pf_psa_algorithm_t alg)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;

    status = pf_psa_get_and_lock_key_slot(key, p_slot);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }
    slot = *p_slot;

    /* Enforce that usage policy for the key slot contains all the flags
     * required by the usage parameter. There is one exception: public
     * keys can always be exported, so we treat public key objects as
     * if they had the export flag. */
    if (PF_PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attr.type)) {
        usage &= ~PF_PSA_KEY_USAGE_EXPORT;
    }

    if ((slot->attr.policy.usage & usage) != usage) {
        status = PF_PSA_ERROR_NOT_PERMITTED;
        goto error;
    }

    /* Enforce that the usage policy permits the requested algorithm. */
    if (alg != 0) {
        status = pf_psa_key_policy_permits(&slot->attr.policy,
                                        slot->attr.type,
                                        alg);
        if (status != PF_PSA_SUCCESS) {
            goto error;
        }
    }

    return PF_PSA_SUCCESS;

error:
    *p_slot = NULL;
    pf_psa_unregister_read_under_mutex(slot);

    return status;
}

/** Get a key slot containing a transparent key and lock it.
 *
 * A transparent key is a key for which the key material is directly
 * available, as opposed to a key in a secure element and/or to be used
 * by a secure element.
 *
 * This is a temporary function that may be used instead of
 * psa_get_and_lock_key_slot_with_policy() when there is no opaque key support
 * for a cryptographic operation.
 *
 * On success, the returned key slot has been registered for reading.
 * It is the responsibility of the caller to then unregister
 * once they have finished reading the contents of the slot.
 * The caller unregisters by calling psa_unregister_read() or
 * psa_unregister_read_under_mutex(). psa_unregister_read() must be called
 * if and only if the caller already holds the global key slot mutex
 * (when mutexes are enabled). psa_unregister_read_under_mutex() encapsulates
 * psa_unregister_read() with mutex lock and unlock operations.
 */
static pf_psa_status_t pf_psa_get_and_lock_transparent_key_slot_with_policy(
    pf_mbedtls_svc_key_id_t key,
    pf_psa_key_slot_t **p_slot,
    pf_psa_key_usage_t usage,
    pf_psa_algorithm_t alg)
{
    pf_psa_status_t status = pf_psa_get_and_lock_key_slot_with_policy(key, p_slot,
                                                                usage, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    if (pf_psa_key_lifetime_is_external((*p_slot)->attr.lifetime)) {
        pf_psa_unregister_read_under_mutex(*p_slot);
        *p_slot = NULL;
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_remove_key_data_from_memory(pf_psa_key_slot_t *slot)
{
#if defined(PF_MBEDTLS_PSA_STATIC_KEY_SLOTS)
    if (slot->key.bytes > 0) {
        pf_mbedtls_platform_zeroize(slot->key.data, PF_MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE);
    }
#else
    if (slot->key.data != NULL) {
        pf_mbedtls_zeroize_and_free(slot->key.data, slot->key.bytes);
    }

    slot->key.data = NULL;
#endif /* MBEDTLS_PSA_STATIC_KEY_SLOTS */

    slot->key.bytes = 0;

    return PF_PSA_SUCCESS;
}

/** Completely wipe a slot in memory, including its policy.
 * Persistent storage is not affected. */
pf_psa_status_t pf_psa_wipe_key_slot(pf_psa_key_slot_t *slot)
{
    pf_psa_status_t status = pf_psa_remove_key_data_from_memory(slot);

    /*
     * As the return error code may not be handled in case of multiple errors,
     * do our best to report an unexpected amount of registered readers or
     * an unexpected state.
     * Assert with MBEDTLS_TEST_HOOK_TEST_ASSERT that the slot is valid for
     * wiping.
     * if the MBEDTLS_TEST_HOOKS configuration option is enabled and the
     * function is called as part of the execution of a test suite, the
     * execution of the test suite is stopped in error if the assertion fails.
     */
    switch (slot->state) {
        case PF_PSA_SLOT_FULL:
        /* In this state psa_wipe_key_slot() must only be called if the
         * caller is the last reader. */
        case PF_PSA_SLOT_PENDING_DELETION:
            /* In this state psa_wipe_key_slot() must only be called if the
             * caller is the last reader. */
            if (slot->var.occupied.registered_readers != 1) {
                PF_MBEDTLS_TEST_HOOK_TEST_ASSERT(slot->var.occupied.registered_readers == 1);
                status = PF_PSA_ERROR_CORRUPTION_DETECTED;
            }
            break;
        case PF_PSA_SLOT_FILLING:
            /* In this state registered_readers must be 0. */
            if (slot->var.occupied.registered_readers != 0) {
                PF_MBEDTLS_TEST_HOOK_TEST_ASSERT(slot->var.occupied.registered_readers == 0);
                status = PF_PSA_ERROR_CORRUPTION_DETECTED;
            }
            break;
        case PF_PSA_SLOT_EMPTY:
            /* The slot is already empty, it cannot be wiped. */
            PF_MBEDTLS_TEST_HOOK_TEST_ASSERT(slot->state != PF_PSA_SLOT_EMPTY);
            status = PF_PSA_ERROR_CORRUPTION_DETECTED;
            break;
        default:
            /* The slot's state is invalid. */
            status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    }

#if defined(PF_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    size_t slice_index = slot->slice_index;
#endif /* MBEDTLS_PSA_KEY_STORE_DYNAMIC */


    /* Multipart operations may still be using the key. This is safe
     * because all multipart operation objects are independent from
     * the key slot: if they need to access the key after the setup
     * phase, they have a copy of the key. Note that this means that
     * key material can linger until all operations are completed. */
    /* At this point, key material and other type-specific content has
     * been wiped. Clear remaining metadata. We can call memset and not
     * zeroize because the metadata is not particularly sensitive.
     * This memset also sets the slot's state to PSA_SLOT_EMPTY. */
    memset(slot, 0, sizeof(*slot));

#if defined(PF_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    /* If the slot is already corrupted, something went deeply wrong,
     * like a thread still using the slot or a stray pointer leading
     * to the slot's memory being used for another object. Let the slot
     * leak rather than make the corruption worse. */
    if (status == PF_PSA_SUCCESS) {
        status = pf_psa_free_key_slot(slice_index, slot);
    }
#endif /* MBEDTLS_PSA_KEY_STORE_DYNAMIC */

    return status;
}

pf_psa_status_t pf_psa_destroy_key(pf_mbedtls_svc_key_id_t key)
{
    pf_psa_key_slot_t *slot;
    pf_psa_status_t status; /* status of the last operation */
    pf_psa_status_t overall_status = PF_PSA_SUCCESS;
#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    pf_psa_se_drv_table_entry_t *driver;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    if (pf_mbedtls_svc_key_id_is_null(key)) {
        return PF_PSA_SUCCESS;
    }

    /*
     * Get the description of the key in a key slot, and register to read it.
     * In the case of a persistent key, this will load the key description
     * from persistent memory if not done yet.
     * We cannot avoid this loading as without it we don't know if
     * the key is operated by an SE or not and this information is needed by
     * the current implementation. */
    status = pf_psa_get_and_lock_key_slot(key, &slot);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    /* We cannot unlock between setting the state to PENDING_DELETION
     * and destroying the key in storage, as otherwise another thread
     * could load the key into a new slot and the key will not be
     * fully destroyed. */
    PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_lock(
                                    &pf_mbedtls_threading_key_slot_mutex));

    if (slot->state == PF_PSA_SLOT_PENDING_DELETION) {
        /* Another thread has destroyed the key between us locking the slot
         * and us gaining the mutex. Unregister from the slot,
         * and report that the key does not exist. */
        status = pf_psa_unregister_read(slot);

        PF_PSA_THREADING_CHK_RET(pf_mbedtls_mutex_unlock(
                                  &pf_mbedtls_threading_key_slot_mutex));
        return (status == PF_PSA_SUCCESS) ? PF_PSA_ERROR_INVALID_HANDLE : status;
    }
#endif
    /* Set the key slot containing the key description's state to
     * PENDING_DELETION. This stops new operations from registering
     * to read the slot. Current readers can safely continue to access
     * the key within the slot; the last registered reader will
     * automatically wipe the slot when they call psa_unregister_read().
     * If the key is persistent, we can now delete the copy of the key
     * from memory. If the key is opaque, we require the driver to
     * deal with the deletion. */
    overall_status = pf_psa_key_slot_state_transition(slot, PF_PSA_SLOT_FULL,
                                                   PF_PSA_SLOT_PENDING_DELETION);

    if (overall_status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (PF_PSA_KEY_LIFETIME_IS_READ_ONLY(slot->attr.lifetime)) {
        /* Refuse the destruction of a read-only key (which may or may not work
         * if we attempt it, depending on whether the key is merely read-only
         * by policy or actually physically read-only).
         * Just do the best we can, which is to wipe the copy in memory
         * (done in this function's cleanup code). */
        overall_status = PF_PSA_ERROR_NOT_PERMITTED;
        goto exit;
    }

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    driver = pf_psa_get_se_driver_entry(slot->attr.lifetime);
    if (driver != NULL) {
        /* For a key in a secure element, we need to do three things:
         * remove the key file in internal storage, destroy the
         * key inside the secure element, and update the driver's
         * persistent data. Start a transaction that will encompass these
         * three actions. */
        pf_psa_crypto_prepare_transaction(PF_PSA_CRYPTO_TRANSACTION_DESTROY_KEY);
        pf_psa_crypto_transaction.key.lifetime = slot->attr.lifetime;
        pf_psa_crypto_transaction.key.slot = pf_psa_key_slot_get_slot_number(slot);
        pf_psa_crypto_transaction.key.id = slot->attr.id;
        status = pf_psa_crypto_save_transaction();
        if (status != PF_PSA_SUCCESS) {
            (void) pf_psa_crypto_stop_transaction();
            /* We should still try to destroy the key in the secure
             * element and the key metadata in storage. This is especially
             * important if the error is that the storage is full.
             * But how to do it exactly without risking an inconsistent
             * state after a reset?
             * https://github.com/ARMmbed/mbed-crypto/issues/215
             */
            overall_status = status;
            goto exit;
        }

        status = pf_psa_destroy_se_key(driver,
                                    pf_psa_key_slot_get_slot_number(slot));
        if (overall_status == PF_PSA_SUCCESS) {
            overall_status = status;
        }
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

#if defined(PF_MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if (!PF_PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime)) {
        /* Destroy the copy of the persistent key from storage.
         * The slot will still hold a copy of the key until the last reader
         * unregisters. */
        status = pf_psa_destroy_persistent_key(slot->attr.id);
        if (overall_status == PF_PSA_SUCCESS) {
            overall_status = status;
        }
    }
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    if (driver != NULL) {
        status = pf_psa_save_se_persistent_data(driver);
        if (overall_status == PF_PSA_SUCCESS) {
            overall_status = status;
        }
        status = pf_psa_crypto_stop_transaction();
        if (overall_status == PF_PSA_SUCCESS) {
            overall_status = status;
        }
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

exit:
    /* Unregister from reading the slot. If we are the last active reader
     * then this will wipe the slot. */
    status = pf_psa_unregister_read(slot);
    /* Prioritize CORRUPTION_DETECTED from unregistering over
     * a storage error. */
    if (status != PF_PSA_SUCCESS) {
        overall_status = status;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    /* Don't overwrite existing errors if the unlock fails. */
    status = overall_status;
    PF_PSA_THREADING_CHK_RET(pf_mbedtls_mutex_unlock(
                              &pf_mbedtls_threading_key_slot_mutex));
#endif

    return overall_status;
}

/** Retrieve all the publicly-accessible attributes of a key.
 */
pf_psa_status_t pf_psa_get_key_attributes(pf_mbedtls_svc_key_id_t key,
                                    pf_psa_key_attributes_t *attributes)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    pf_psa_reset_key_attributes(attributes);

    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot, 0, 0);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    *attributes = slot->attr;

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    if (pf_psa_get_se_driver_entry(slot->attr.lifetime) != NULL) {
        pf_psa_set_key_slot_number(attributes,
                                pf_psa_key_slot_get_slot_number(slot));
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    return pf_psa_unregister_read_under_mutex(slot);
}

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
pf_psa_status_t pf_psa_get_key_slot_number(
    const pf_psa_key_attributes_t *attributes,
    pf_psa_key_slot_number_t *slot_number)
{
    if (attributes->has_slot_number) {
        *slot_number = attributes->slot_number;
        return PF_PSA_SUCCESS;
    } else {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
}
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

static pf_psa_status_t pf_psa_export_key_buffer_internal(const uint8_t *key_buffer,
                                                   size_t key_buffer_size,
                                                   uint8_t *data,
                                                   size_t data_size,
                                                   size_t *data_length)
{
    if (key_buffer_size > data_size) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(data, key_buffer, key_buffer_size);
    memset(data + key_buffer_size, 0,
           data_size - key_buffer_size);
    *data_length = key_buffer_size;
    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_export_key_internal(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    pf_psa_key_type_t type = attributes->type;

    if (key_type_is_raw_bytes(type) ||
        PF_PSA_KEY_TYPE_IS_RSA(type)   ||
        PF_PSA_KEY_TYPE_IS_ECC(type)   ||
        PF_PSA_KEY_TYPE_IS_DH(type)) {
        return pf_psa_export_key_buffer_internal(
            key_buffer, key_buffer_size,
            data, data_size, data_length);
    } else {
        /* This shouldn't happen in the built-in implementation, but
           it is valid for a special-purpose drivers to omit
           support for exporting certain key types. */
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }
}

pf_psa_status_t pf_psa_export_key(pf_mbedtls_svc_key_id_t key,
                            uint8_t *data_external,
                            size_t data_size,
                            size_t *data_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;
    LOCAL_OUTPUT_DECLARE(data_external, data);

    /* Reject a zero-length output buffer now, since this can never be a
     * valid key representation. This way we know that data must be a valid
     * pointer and we can do things like memset(data, ..., data_size). */
    if (data_size == 0) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    /* Export requires the EXPORT flag. There is an exception for public keys,
     * which don't require any flag, but
     * psa_get_and_lock_key_slot_with_policy() takes care of this.
     */
    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PF_PSA_KEY_USAGE_EXPORT, 0);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    LOCAL_OUTPUT_ALLOC(data_external, data_size, data);

    status = pf_psa_driver_wrapper_export_key(&slot->attr,
                                           slot->key.data, slot->key.bytes,
                                           data, data_size, data_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    LOCAL_OUTPUT_FREE(data_external, data);
    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_export_public_key_internal(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    pf_psa_key_type_t type = attributes->type;

    if (PF_PSA_KEY_TYPE_IS_PUBLIC_KEY(type) &&
        (PF_PSA_KEY_TYPE_IS_RSA(type) || PF_PSA_KEY_TYPE_IS_ECC(type) ||
         PF_PSA_KEY_TYPE_IS_DH(type))) {
        /* Exporting public -> public */
        return pf_psa_export_key_buffer_internal(
            key_buffer, key_buffer_size,
            data, data_size, data_length);
    } else if (PF_PSA_KEY_TYPE_IS_RSA(type)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT) || \
        defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
        return pf_mbedtls_psa_rsa_export_public_key(attributes,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 data,
                                                 data_size,
                                                 data_length);
#else
        /* We don't know how to convert a private RSA key to public. */
        return PF_PSA_ERROR_NOT_SUPPORTED;
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */
    } else if (PF_PSA_KEY_TYPE_IS_ECC(type)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT) || \
        defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)
        return pf_mbedtls_psa_ecp_export_public_key(attributes,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 data,
                                                 data_size,
                                                 data_length);
#else
        /* We don't know how to convert a private ECC key to public */
        return PF_PSA_ERROR_NOT_SUPPORTED;
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) */
    } else if (PF_PSA_KEY_TYPE_IS_DH(type)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT) || \
        defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY)
        return pf_mbedtls_psa_ffdh_export_public_key(attributes,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  data, data_size,
                                                  data_length);
#else
        return PF_PSA_ERROR_NOT_SUPPORTED;
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY) */
    } else {
        (void) key_buffer;
        (void) key_buffer_size;
        (void) data;
        (void) data_size;
        (void) data_length;
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }
}

pf_psa_status_t pf_psa_export_public_key(pf_mbedtls_svc_key_id_t key,
                                   uint8_t *data_external,
                                   size_t data_size,
                                   size_t *data_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    LOCAL_OUTPUT_DECLARE(data_external, data);

    /* Reject a zero-length output buffer now, since this can never be a
     * valid key representation. This way we know that data must be a valid
     * pointer and we can do things like memset(data, ..., data_size). */
    if (data_size == 0) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    /* Exporting a public key doesn't require a usage flag. */
    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot, 0, 0);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    LOCAL_OUTPUT_ALLOC(data_external, data_size, data);

    if (!PF_PSA_KEY_TYPE_IS_ASYMMETRIC(slot->attr.type)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = pf_psa_driver_wrapper_export_public_key(
        &slot->attr, slot->key.data, slot->key.bytes,
        data, data_size, data_length);

exit:
    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    LOCAL_OUTPUT_FREE(data_external, data);
    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

/** Validate that a key policy is internally well-formed.
 *
 * This function only rejects invalid policies. It does not validate the
 * consistency of the policy with respect to other attributes of the key
 * such as the key type.
 */
static pf_psa_status_t pf_psa_validate_key_policy(const pf_psa_key_policy_t *policy)
{
    if ((policy->usage & ~(PF_PSA_KEY_USAGE_EXPORT |
                           PF_PSA_KEY_USAGE_COPY |
                           PF_PSA_KEY_USAGE_ENCRYPT |
                           PF_PSA_KEY_USAGE_DECRYPT |
                           PF_PSA_KEY_USAGE_SIGN_MESSAGE |
                           PF_PSA_KEY_USAGE_VERIFY_MESSAGE |
                           PF_PSA_KEY_USAGE_SIGN_HASH |
                           PF_PSA_KEY_USAGE_VERIFY_HASH |
                           PF_PSA_KEY_USAGE_VERIFY_DERIVATION |
                           PF_PSA_KEY_USAGE_DERIVE)) != 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    return PF_PSA_SUCCESS;
}

/** Validate the internal consistency of key attributes.
 *
 * This function only rejects invalid attribute values. If does not
 * validate the consistency of the attributes with any key data that may
 * be involved in the creation of the key.
 *
 * Call this function early in the key creation process.
 *
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 */
static pf_psa_status_t pf_psa_validate_key_attributes(
    const pf_psa_key_attributes_t *attributes,
    pf_psa_se_drv_table_entry_t **p_drv)
{
    pf_psa_status_t status = PF_PSA_ERROR_INVALID_ARGUMENT;
    pf_psa_key_lifetime_t lifetime = pf_psa_get_key_lifetime(attributes);
    pf_mbedtls_svc_key_id_t key = pf_psa_get_key_id(attributes);

    status = pf_psa_validate_key_location(lifetime, p_drv);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_psa_validate_key_persistence(lifetime);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    if (PF_PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        if (PF_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key) != 0) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    } else {
        if (!pf_psa_is_valid_key_id(pf_psa_get_key_id(attributes), 0)) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    status = pf_psa_validate_key_policy(&attributes->policy);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    /* Refuse to create overly large keys.
     * Note that this doesn't trigger on import if the attributes don't
     * explicitly specify a size (so psa_get_key_bits returns 0), so
     * psa_import_key() needs its own checks. */
    if (pf_psa_get_key_bits(attributes) > PF_PSA_MAX_KEY_BITS) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_SUCCESS;
}

/** Prepare a key slot to receive key material.
 *
 * This function allocates a key slot and sets its metadata.
 *
 * If this function fails, call psa_fail_key_creation().
 *
 * This function is intended to be used as follows:
 * -# Call psa_start_key_creation() to allocate a key slot, prepare
 *    it with the specified attributes, and in case of a volatile key assign it
 *    a volatile key identifier.
 * -# Populate the slot with the key material.
 * -# Call psa_finish_key_creation() to finalize the creation of the slot.
 * In case of failure at any step, stop the sequence and call
 * psa_fail_key_creation().
 *
 * On success, the key slot's state is PSA_SLOT_FILLING.
 * It is the responsibility of the caller to change the slot's state to
 * PSA_SLOT_EMPTY/FULL once key creation has finished.
 *
 * \param method            An identification of the calling function.
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] p_slot       On success, a pointer to the prepared slot.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 * \retval #PSA_SUCCESS
 *         The key slot is ready to receive key material.
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static pf_psa_status_t pf_psa_start_key_creation(
    pf_psa_key_creation_method_t method,
    const pf_psa_key_attributes_t *attributes,
    pf_psa_key_slot_t **p_slot,
    pf_psa_se_drv_table_entry_t **p_drv)
{
    pf_psa_status_t status;

    (void) method;
    *p_drv = NULL;

    status = pf_psa_validate_key_attributes(attributes, p_drv);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    int key_is_volatile = PF_PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime);
    pf_psa_key_id_t volatile_key_id;

#if defined(PF_MBEDTLS_THREADING_C)
    PF_PSA_THREADING_CHK_RET(pf_mbedtls_mutex_lock(
                              &pf_mbedtls_threading_key_slot_mutex));
#endif
    status = pf_psa_reserve_free_key_slot(
        key_is_volatile ? &volatile_key_id : NULL,
        p_slot);
#if defined(PF_MBEDTLS_THREADING_C)
    PF_PSA_THREADING_CHK_RET(pf_mbedtls_mutex_unlock(
                              &pf_mbedtls_threading_key_slot_mutex));
#endif
    if (status != PF_PSA_SUCCESS) {
        return status;
    }
    pf_psa_key_slot_t *slot = *p_slot;

    /* We're storing the declared bit-size of the key. It's up to each
     * creation mechanism to verify that this information is correct.
     * It's automatically correct for mechanisms that use the bit-size as
     * an input (generate, device) but not for those where the bit-size
     * is optional (import, copy). In case of a volatile key, assign it the
     * volatile key identifier associated to the slot returned to contain its
     * definition. */

    slot->attr = *attributes;
    if (key_is_volatile) {
#if !defined(PF_MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
        slot->attr.id = volatile_key_id;
#else
        slot->attr.id.key_id = volatile_key_id;
#endif
    }

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    /* For a key in a secure element, we need to do three things
     * when creating or registering a persistent key:
     * create the key file in internal storage, create the
     * key inside the secure element, and update the driver's
     * persistent data. This is done by starting a transaction that will
     * encompass these three actions.
     * For registering a volatile key, we just need to find an appropriate
     * slot number inside the SE. Since the key is designated volatile, creating
     * a transaction is not required. */
    /* The first thing to do is to find a slot number for the new key.
     * We save the slot number in persistent storage as part of the
     * transaction data. It will be needed to recover if the power
     * fails during the key creation process, to clean up on the secure
     * element side after restarting. Obtaining a slot number from the
     * secure element driver updates its persistent state, but we do not yet
     * save the driver's persistent state, so that if the power fails,
     * we can roll back to a state where the key doesn't exist. */
    if (*p_drv != NULL) {
        pf_psa_key_slot_number_t slot_number;
        status = pf_psa_find_se_slot_for_key(attributes, method, *p_drv,
                                          &slot_number);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }

        if (!PF_PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime)) {
            pf_psa_crypto_prepare_transaction(PF_PSA_CRYPTO_TRANSACTION_CREATE_KEY);
            pf_psa_crypto_transaction.key.lifetime = slot->attr.lifetime;
            pf_psa_crypto_transaction.key.slot = slot_number;
            pf_psa_crypto_transaction.key.id = slot->attr.id;
            status = pf_psa_crypto_save_transaction();
            if (status != PF_PSA_SUCCESS) {
                (void) pf_psa_crypto_stop_transaction();
                return status;
            }
        }

        status = pf_psa_copy_key_material_into_slot(
            slot, (uint8_t *) (&slot_number), sizeof(slot_number));
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
    }

    if (*p_drv == NULL && method == PF_PSA_KEY_CREATION_REGISTER) {
        /* Key registration only makes sense with a secure element. */
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    return PF_PSA_SUCCESS;
}

/** Finalize the creation of a key once its key material has been set.
 *
 * This entails writing the key to persistent storage.
 *
 * If this function fails, call psa_fail_key_creation().
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function.
 *
 * If the finalization succeeds, the function sets the key slot's state to
 * PSA_SLOT_FULL, and the key slot can no longer be accessed as part of the
 * key creation process.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 * \param[out] key      On success, identifier of the key. Note that the
 *                      key identifier is also stored in the key slot.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully created.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_INSUFFICIENT_STORAGE \emptydescription
 * \retval #PSA_ERROR_ALREADY_EXISTS \emptydescription
 * \retval #PSA_ERROR_DATA_INVALID \emptydescription
 * \retval #PSA_ERROR_DATA_CORRUPT \emptydescription
 * \retval #PSA_ERROR_STORAGE_FAILURE \emptydescription
 *
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static pf_psa_status_t pf_psa_finish_key_creation(
    pf_psa_key_slot_t *slot,
    pf_psa_se_drv_table_entry_t *driver,
    pf_mbedtls_svc_key_id_t *key)
{
    pf_psa_status_t status = PF_PSA_SUCCESS;
    (void) slot;
    (void) driver;

#if defined(PF_MBEDTLS_THREADING_C)
    PF_PSA_THREADING_CHK_RET(pf_mbedtls_mutex_lock(
                              &pf_mbedtls_threading_key_slot_mutex));
#endif

#if defined(PF_MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if (!PF_PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime)) {
#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
        if (driver != NULL) {
            pf_psa_se_key_data_storage_t data;
            pf_psa_key_slot_number_t slot_number =
                pf_psa_key_slot_get_slot_number(slot);

            PF_MBEDTLS_STATIC_ASSERT(sizeof(slot_number) ==
                                  sizeof(data.slot_number),
                                  "Slot number size does not match psa_se_key_data_storage_t");

            memcpy(&data.slot_number, &slot_number, sizeof(slot_number));
            status = pf_psa_save_persistent_key(&slot->attr,
                                             (uint8_t *) &data,
                                             sizeof(data));
        } else
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
        {
            /* Key material is saved in export representation in the slot, so
             * just pass the slot buffer for storage. */
            status = pf_psa_save_persistent_key(&slot->attr,
                                             slot->key.data,
                                             slot->key.bytes);
        }
    }
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    /* Finish the transaction for a key creation. This does not
     * happen when registering an existing key. Detect this case
     * by checking whether a transaction is in progress (actual
     * creation of a persistent key in a secure element requires a transaction,
     * but registration or volatile key creation doesn't use one). */
    if (driver != NULL &&
        pf_psa_crypto_transaction.unknown.type == PF_PSA_CRYPTO_TRANSACTION_CREATE_KEY) {
        status = pf_psa_save_se_persistent_data(driver);
        if (status != PF_PSA_SUCCESS) {
            pf_psa_destroy_persistent_key(slot->attr.id);

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_RET(pf_mbedtls_mutex_unlock(
                                      &pf_mbedtls_threading_key_slot_mutex));
#endif
            return status;
        }
        status = pf_psa_crypto_stop_transaction();
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    if (status == PF_PSA_SUCCESS) {
        *key = slot->attr.id;
        status = pf_psa_key_slot_state_transition(slot, PF_PSA_SLOT_FILLING,
                                               PF_PSA_SLOT_FULL);
        if (status != PF_PSA_SUCCESS) {
            *key = PF_MBEDTLS_SVC_KEY_ID_INIT;
        }
    }

#if defined(PF_MBEDTLS_THREADING_C)
    PF_PSA_THREADING_CHK_RET(pf_mbedtls_mutex_unlock(
                              &pf_mbedtls_threading_key_slot_mutex));
#endif
    return status;
}

/** Abort the creation of a key.
 *
 * You may call this function after calling psa_start_key_creation(),
 * or after psa_finish_key_creation() fails. In other circumstances, this
 * function may not clean up persistent storage.
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function. Sets the slot's state to PSA_SLOT_EMPTY.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 */
static void pf_psa_fail_key_creation(pf_psa_key_slot_t *slot,
                                  pf_psa_se_drv_table_entry_t *driver)
{
    (void) driver;

    if (slot == NULL) {
        return;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    /* If the lock operation fails we still wipe the slot.
     * Operations will no longer work after a failed lock,
     * but we still need to wipe the slot of confidential data. */
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_key_slot_mutex);
#endif

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    /* TODO: If the key has already been created in the secure
     * element, and the failure happened later (when saving metadata
     * to internal storage), we need to destroy the key in the secure
     * element.
     * https://github.com/ARMmbed/mbed-crypto/issues/217
     */

    /* Abort the ongoing transaction if any (there may not be one if
     * the creation process failed before starting one, or if the
     * key creation is a registration of a key in a secure element).
     * Earlier functions must already have done what it takes to undo any
     * partial creation. All that's left is to update the transaction data
     * itself. */
    (void) pf_psa_crypto_stop_transaction();
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    pf_psa_wipe_key_slot(slot);

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_key_slot_mutex);
#endif
}

/** Validate optional attributes during key creation.
 *
 * Some key attributes are optional during key creation. If they are
 * specified in the attributes structure, check that they are consistent
 * with the data in the slot.
 *
 * This function should be called near the end of key creation, after
 * the slot in memory is fully populated but before saving persistent data.
 */
static pf_psa_status_t pf_psa_validate_optional_attributes(
    const pf_psa_key_slot_t *slot,
    const pf_psa_key_attributes_t *attributes)
{
    if (attributes->type != 0) {
        if (attributes->type != slot->attr.type) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    if (attributes->bits != 0) {
        if (attributes->bits != slot->attr.bits) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_import_key(const pf_psa_key_attributes_t *attributes,
                            const uint8_t *data_external,
                            size_t data_length,
                            pf_mbedtls_svc_key_id_t *key)
{
    pf_psa_status_t status;
    LOCAL_INPUT_DECLARE(data_external, data);
    pf_psa_key_slot_t *slot = NULL;
    pf_psa_se_drv_table_entry_t *driver = NULL;
    size_t bits;
    size_t storage_size = data_length;

    *key = PF_MBEDTLS_SVC_KEY_ID_INIT;

    /* Reject zero-length symmetric keys (including raw data key objects).
     * This also rejects any key which might be encoded as an empty string,
     * which is never valid. */
    if (data_length == 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Ensure that the bytes-to-bits conversion cannot overflow. */
    if (data_length > SIZE_MAX / 8) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    LOCAL_INPUT_ALLOC(data_external, data_length, data);

    status = pf_psa_start_key_creation(PF_PSA_KEY_CREATION_IMPORT, attributes,
                                    &slot, &driver);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    /* In the case of a transparent key or an opaque key stored in local
     * storage ( thus not in the case of importing a key in a secure element
     * with storage ( MBEDTLS_PSA_CRYPTO_SE_C ) ),we have to allocate a
     * buffer to hold the imported key material. */
    if (slot->key.bytes == 0) {
        if (pf_psa_key_lifetime_is_external(attributes->lifetime)) {
            status = pf_psa_driver_wrapper_get_key_buffer_size_from_key_data(
                attributes, data, data_length, &storage_size);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
        }
        status = pf_psa_allocate_buffer_to_slot(slot, storage_size);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }

    bits = slot->attr.bits;
    status = pf_psa_driver_wrapper_import_key(attributes,
                                           data, data_length,
                                           slot->key.data,
                                           slot->key.bytes,
                                           &slot->key.bytes, &bits);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (slot->attr.bits == 0) {
        slot->attr.bits = (pf_psa_key_bits_t) bits;
    } else if (bits != slot->attr.bits) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Enforce a size limit, and in particular ensure that the bit
     * size fits in its representation type.*/
    if (bits > PF_PSA_MAX_KEY_BITS) {
        status = PF_PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = pf_psa_validate_optional_attributes(slot, attributes);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_finish_key_creation(slot, driver, key);
exit:
    LOCAL_INPUT_FREE(data_external, data);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_fail_key_creation(slot, driver);
    }

    return status;
}

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
pf_psa_status_t pf_mbedtls_psa_register_se_key(
    const pf_psa_key_attributes_t *attributes)
{
    pf_psa_status_t status;
    pf_psa_key_slot_t *slot = NULL;
    pf_psa_se_drv_table_entry_t *driver = NULL;
    pf_mbedtls_svc_key_id_t key = PF_MBEDTLS_SVC_KEY_ID_INIT;

    /* Leaving attributes unspecified is not currently supported.
     * It could make sense to query the key type and size from the
     * secure element, but not all secure elements support this
     * and the driver HAL doesn't currently support it. */
    if (pf_psa_get_key_type(attributes) == PF_PSA_KEY_TYPE_NONE) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }
    if (pf_psa_get_key_bits(attributes) == 0) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    /* Not usable with volatile keys, even with an appropriate location,
     * due to the API design.
     * https://github.com/Mbed-TLS/mbedtls/issues/9253
     */
    if (PF_PSA_KEY_LIFETIME_IS_VOLATILE(pf_psa_get_key_lifetime(attributes))) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    status = pf_psa_start_key_creation(PF_PSA_KEY_CREATION_REGISTER, attributes,
                                    &slot, &driver);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_finish_key_creation(slot, driver, &key);

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_fail_key_creation(slot, driver);
    }

    /* Registration doesn't keep the key in RAM. */
    pf_psa_close_key(key);
    return status;
}
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

pf_psa_status_t pf_psa_copy_key(pf_mbedtls_svc_key_id_t source_key,
                          const pf_psa_key_attributes_t *specified_attributes,
                          pf_mbedtls_svc_key_id_t *target_key)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *source_slot = NULL;
    pf_psa_key_slot_t *target_slot = NULL;
    pf_psa_key_attributes_t actual_attributes = *specified_attributes;
    pf_psa_se_drv_table_entry_t *driver = NULL;
    size_t storage_size = 0;

    *target_key = PF_MBEDTLS_SVC_KEY_ID_INIT;

    status = pf_psa_get_and_lock_key_slot_with_policy(
        source_key, &source_slot, PF_PSA_KEY_USAGE_COPY, 0);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_validate_optional_attributes(source_slot,
                                              specified_attributes);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    /* The target key type and number of bits have been validated by
     * psa_validate_optional_attributes() to be either equal to zero or
     * equal to the ones of the source key. So it is safe to inherit
     * them from the source key now."
     * */
    actual_attributes.bits = source_slot->attr.bits;
    actual_attributes.type = source_slot->attr.type;


    status = pf_psa_restrict_key_policy(source_slot->attr.type,
                                     &actual_attributes.policy,
                                     &source_slot->attr.policy);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_start_key_creation(PF_PSA_KEY_CREATION_COPY, &actual_attributes,
                                    &target_slot, &driver);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }
    if (PF_PSA_KEY_LIFETIME_GET_LOCATION(target_slot->attr.lifetime) !=
        PF_PSA_KEY_LIFETIME_GET_LOCATION(source_slot->attr.lifetime)) {
        /*
         * If the source and target keys are stored in different locations,
         * the source key would need to be exported as plaintext and re-imported
         * in the other location. This has security implications which have not
         * been fully mapped. For now, this can be achieved through
         * appropriate API invocations from the application, if needed.
         * */
        status = PF_PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    /*
     * When the source and target keys are within the same location,
     * - For transparent keys it is a blind copy without any driver invocation,
     * - For opaque keys this translates to an invocation of the drivers'
     *   copy_key entry point through the dispatch layer.
     * */
    if (pf_psa_key_lifetime_is_external(actual_attributes.lifetime)) {
        status = pf_psa_driver_wrapper_get_key_buffer_size(&actual_attributes,
                                                        &storage_size);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }

        status = pf_psa_allocate_buffer_to_slot(target_slot, storage_size);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }

        status = pf_psa_driver_wrapper_copy_key(&actual_attributes,
                                             source_slot->key.data,
                                             source_slot->key.bytes,
                                             target_slot->key.data,
                                             target_slot->key.bytes,
                                             &target_slot->key.bytes);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    } else {
        status = pf_psa_copy_key_material_into_slot(target_slot,
                                                 source_slot->key.data,
                                                 source_slot->key.bytes);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }
    status = pf_psa_finish_key_creation(target_slot, driver, target_key);
exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_fail_key_creation(target_slot, driver);
    }

    unlock_status = pf_psa_unregister_read_under_mutex(source_slot);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}



/****************************************************************/
/* Message digests */
/****************************************************************/

static int is_hash_supported(pf_psa_algorithm_t alg)
{
    switch (alg) {
#if defined(PF_PSA_WANT_ALG_MD5)
        case PF_PSA_ALG_MD5:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_RIPEMD160)
        case PF_PSA_ALG_RIPEMD160:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA_1)
        case PF_PSA_ALG_SHA_1:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA_224)
        case PF_PSA_ALG_SHA_224:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA_256)
        case PF_PSA_ALG_SHA_256:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA_384)
        case PF_PSA_ALG_SHA_384:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA_512)
        case PF_PSA_ALG_SHA_512:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA3_224)
        case PF_PSA_ALG_SHA3_224:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA3_256)
        case PF_PSA_ALG_SHA3_256:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA3_384)
        case PF_PSA_ALG_SHA3_384:
            return 1;
#endif
#if defined(PF_PSA_WANT_ALG_SHA3_512)
        case PF_PSA_ALG_SHA3_512:
            return 1;
#endif
        default:
            return 0;
    }
}

pf_psa_status_t pf_psa_hash_abort(pf_psa_hash_operation_t *operation)
{
    /* Aborting a non-active operation is allowed */
    if (operation->id == 0) {
        return PF_PSA_SUCCESS;
    }

    pf_psa_status_t status = pf_psa_driver_wrapper_hash_abort(operation);
    operation->id = 0;

    return status;
}

pf_psa_status_t pf_psa_hash_setup(pf_psa_hash_operation_t *operation,
                            pf_psa_algorithm_t alg)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if (operation->id != 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!PF_PSA_ALG_IS_HASH(alg)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    status = pf_psa_driver_wrapper_hash_setup(operation, alg);

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_hash_abort(operation);
    }

    return status;
}

pf_psa_status_t pf_psa_hash_update(pf_psa_hash_operation_t *operation,
                             const uint8_t *input_external,
                             size_t input_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(input_external, input);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if (input_length == 0) {
        return PF_PSA_SUCCESS;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    status = pf_psa_driver_wrapper_hash_update(operation, input, input_length);

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_hash_abort(operation);
    }

    LOCAL_INPUT_FREE(input_external, input);
    return status;
}

static pf_psa_status_t pf_psa_hash_finish_internal(pf_psa_hash_operation_t *operation,
                                             uint8_t *hash,
                                             size_t hash_size,
                                             size_t *hash_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    *hash_length = 0;
    if (operation->id == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    status = pf_psa_driver_wrapper_hash_finish(
        operation, hash, hash_size, hash_length);
    pf_psa_hash_abort(operation);

    return status;
}

pf_psa_status_t pf_psa_hash_finish(pf_psa_hash_operation_t *operation,
                             uint8_t *hash_external,
                             size_t hash_size,
                             size_t *hash_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_OUTPUT_DECLARE(hash_external, hash);

    LOCAL_OUTPUT_ALLOC(hash_external, hash_size, hash);
    status = pf_psa_hash_finish_internal(operation, hash, hash_size, hash_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_OUTPUT_FREE(hash_external, hash);
    return status;
}

pf_psa_status_t pf_psa_hash_verify(pf_psa_hash_operation_t *operation,
                             const uint8_t *hash_external,
                             size_t hash_length)
{
    uint8_t actual_hash[PF_PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(hash_external, hash);

    status = pf_psa_hash_finish_internal(
        operation,
        actual_hash, sizeof(actual_hash),
        &actual_hash_length);

    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (actual_hash_length != hash_length) {
        status = PF_PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(hash_external, hash_length, hash);
    if (pf_mbedtls_ct_memcmp(hash, actual_hash, actual_hash_length) != 0) {
        status = PF_PSA_ERROR_INVALID_SIGNATURE;
    }

exit:
    pf_mbedtls_platform_zeroize(actual_hash, sizeof(actual_hash));
    if (status != PF_PSA_SUCCESS) {
        pf_psa_hash_abort(operation);
    }
    LOCAL_INPUT_FREE(hash_external, hash);
    return status;
}

pf_psa_status_t pf_psa_hash_compute(pf_psa_algorithm_t alg,
                              const uint8_t *input_external, size_t input_length,
                              uint8_t *hash_external, size_t hash_size,
                              size_t *hash_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_OUTPUT_DECLARE(hash_external, hash);

    *hash_length = 0;
    if (!PF_PSA_ALG_IS_HASH(alg)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_OUTPUT_ALLOC(hash_external, hash_size, hash);
    status = pf_psa_driver_wrapper_hash_compute(alg, input, input_length,
                                             hash, hash_size, hash_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_OUTPUT_FREE(hash_external, hash);
    return status;
}

pf_psa_status_t pf_psa_hash_compare(pf_psa_algorithm_t alg,
                              const uint8_t *input_external, size_t input_length,
                              const uint8_t *hash_external, size_t hash_length)
{
    uint8_t actual_hash[PF_PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_INPUT_DECLARE(hash_external, hash);

    if (!PF_PSA_ALG_IS_HASH(alg)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        return status;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    status = pf_psa_driver_wrapper_hash_compute(
        alg, input, input_length,
        actual_hash, sizeof(actual_hash),
        &actual_hash_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }
    if (actual_hash_length != hash_length) {
        status = PF_PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(hash_external, hash_length, hash);
    if (pf_mbedtls_ct_memcmp(hash, actual_hash, actual_hash_length) != 0) {
        status = PF_PSA_ERROR_INVALID_SIGNATURE;
    }

exit:
    pf_mbedtls_platform_zeroize(actual_hash, sizeof(actual_hash));

    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_INPUT_FREE(hash_external, hash);

    return status;
}

pf_psa_status_t pf_psa_hash_clone(const pf_psa_hash_operation_t *source_operation,
                            pf_psa_hash_operation_t *target_operation)
{
    if (source_operation->id == 0 ||
        target_operation->id != 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&target_operation->ctx, 0, sizeof(target_operation->ctx));

    pf_psa_status_t status = pf_psa_driver_wrapper_hash_clone(source_operation,
                                                        target_operation);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_hash_abort(target_operation);
    }

    return status;
}


/****************************************************************/
/* MAC */
/****************************************************************/

pf_psa_status_t pf_psa_mac_abort(pf_psa_mac_operation_t *operation)
{
    /* Aborting a non-active operation is allowed */
    if (operation->id == 0) {
        return PF_PSA_SUCCESS;
    }

    pf_psa_status_t status = pf_psa_driver_wrapper_mac_abort(operation);
    operation->mac_size = 0;
    operation->is_sign = 0;
    operation->id = 0;

    return status;
}

static pf_psa_status_t pf_psa_mac_finalize_alg_and_key_validation(
    pf_psa_algorithm_t alg,
    const pf_psa_key_attributes_t *attributes,
    uint8_t *mac_size)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_type_t key_type = pf_psa_get_key_type(attributes);
    size_t key_bits = pf_psa_get_key_bits(attributes);

    if (!PF_PSA_ALG_IS_MAC(alg)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Validate the combination of key type and algorithm */
    status = pf_psa_mac_key_can_do(alg, key_type);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    /* Get the output length for the algorithm and key combination */
    *mac_size = PF_PSA_MAC_LENGTH(key_type, key_bits, alg);

    if (*mac_size < 4) {
        /* A very short MAC is too short for security since it can be
         * brute-forced. Ancient protocols with 32-bit MACs do exist,
         * so we make this our minimum, even though 32 bits is still
         * too small for security. */
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    if (*mac_size > PF_PSA_MAC_LENGTH(key_type, key_bits,
                                   PF_PSA_ALG_FULL_LENGTH_MAC(alg))) {
        /* It's impossible to "truncate" to a larger length than the full length
         * of the algorithm. */
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (*mac_size > PF_PSA_MAC_MAX_SIZE) {
        /* PSA_MAC_LENGTH returns the correct length even for a MAC algorithm
         * that is disabled in the compile-time configuration. The result can
         * therefore be larger than PSA_MAC_MAX_SIZE, which does take the
         * configuration into account. In this case, force a return of
         * PSA_ERROR_NOT_SUPPORTED here. Otherwise psa_mac_verify(), or
         * psa_mac_compute(mac_size=PSA_MAC_MAX_SIZE), would return
         * PSA_ERROR_BUFFER_TOO_SMALL for an unsupported algorithm whose MAC size
         * is larger than PSA_MAC_MAX_SIZE, which is misleading and which breaks
         * systematically generated tests. */
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_mac_setup(pf_psa_mac_operation_t *operation,
                                  pf_mbedtls_svc_key_id_t key,
                                  pf_psa_algorithm_t alg,
                                  int is_sign)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;

    /* A context must be freshly initialized before it can be set up. */
    if (operation->id != 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key,
        &slot,
        is_sign ? PF_PSA_KEY_USAGE_SIGN_MESSAGE : PF_PSA_KEY_USAGE_VERIFY_MESSAGE,
        alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_mac_finalize_alg_and_key_validation(alg, &slot->attr,
                                                     &operation->mac_size);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    operation->is_sign = is_sign;
    /* Dispatch the MAC setup call with validated input */
    if (is_sign) {
        status = pf_psa_driver_wrapper_mac_sign_setup(operation,
                                                   &slot->attr,
                                                   slot->key.data,
                                                   slot->key.bytes,
                                                   alg);
    } else {
        status = pf_psa_driver_wrapper_mac_verify_setup(operation,
                                                     &slot->attr,
                                                     slot->key.data,
                                                     slot->key.bytes,
                                                     alg);
    }

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_mac_abort(operation);
    }

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_mac_sign_setup(pf_psa_mac_operation_t *operation,
                                pf_mbedtls_svc_key_id_t key,
                                pf_psa_algorithm_t alg)
{
    return pf_psa_mac_setup(operation, key, alg, 1);
}

pf_psa_status_t pf_psa_mac_verify_setup(pf_psa_mac_operation_t *operation,
                                  pf_mbedtls_svc_key_id_t key,
                                  pf_psa_algorithm_t alg)
{
    return pf_psa_mac_setup(operation, key, alg, 0);
}

pf_psa_status_t pf_psa_mac_update(pf_psa_mac_operation_t *operation,
                            const uint8_t *input_external,
                            size_t input_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(input_external, input);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        return status;
    }

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if (input_length == 0) {
        status = PF_PSA_SUCCESS;
        return status;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    status = pf_psa_driver_wrapper_mac_update(operation, input, input_length);

    if (status != PF_PSA_SUCCESS) {
        pf_psa_mac_abort(operation);
    }

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(input_external, input);

    return status;
}

pf_psa_status_t pf_psa_mac_sign_finish(pf_psa_mac_operation_t *operation,
                                 uint8_t *mac_external,
                                 size_t mac_size,
                                 size_t *mac_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t abort_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_OUTPUT_DECLARE(mac_external, mac);
    LOCAL_OUTPUT_ALLOC(mac_external, mac_size, mac);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!operation->is_sign) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Sanity check. This will guarantee that mac_size != 0 (and so mac != NULL)
     * once all the error checks are done. */
    if (operation->mac_size == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (mac_size < operation->mac_size) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }


    status = pf_psa_driver_wrapper_mac_sign_finish(operation,
                                                mac, operation->mac_size,
                                                mac_length);

exit:
    /* In case of success, set the potential excess room in the output buffer
     * to an invalid value, to avoid potentially leaking a longer MAC.
     * In case of error, set the output length and content to a safe default,
     * such that in case the caller misses an error check, the output would be
     * an unachievable MAC.
     */
    if (status != PF_PSA_SUCCESS) {
        *mac_length = mac_size;
        operation->mac_size = 0;
    }

    if (mac != NULL) {
        pf_psa_wipe_tag_output_buffer(mac, status, mac_size, *mac_length);
    }

    abort_status = pf_psa_mac_abort(operation);
    LOCAL_OUTPUT_FREE(mac_external, mac);

    return status == PF_PSA_SUCCESS ? abort_status : status;
}

pf_psa_status_t pf_psa_mac_verify_finish(pf_psa_mac_operation_t *operation,
                                   const uint8_t *mac_external,
                                   size_t mac_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t abort_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(mac_external, mac);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->is_sign) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->mac_size != mac_length) {
        status = PF_PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(mac_external, mac_length, mac);
    status = pf_psa_driver_wrapper_mac_verify_finish(operation,
                                                  mac, mac_length);

exit:
    abort_status = pf_psa_mac_abort(operation);
    LOCAL_INPUT_FREE(mac_external, mac);

    return status == PF_PSA_SUCCESS ? abort_status : status;
}

static pf_psa_status_t pf_psa_mac_compute_internal(pf_mbedtls_svc_key_id_t key,
                                             pf_psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             uint8_t *mac,
                                             size_t mac_size,
                                             size_t *mac_length,
                                             int is_sign)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;
    uint8_t operation_mac_size = 0;

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key,
        &slot,
        is_sign ? PF_PSA_KEY_USAGE_SIGN_MESSAGE : PF_PSA_KEY_USAGE_VERIFY_MESSAGE,
        alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_mac_finalize_alg_and_key_validation(alg, &slot->attr,
                                                     &operation_mac_size);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (mac_size < operation_mac_size) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = pf_psa_driver_wrapper_mac_compute(
        &slot->attr,
        slot->key.data, slot->key.bytes,
        alg,
        input, input_length,
        mac, operation_mac_size, mac_length);

exit:
    /* In case of success, set the potential excess room in the output buffer
     * to an invalid value, to avoid potentially leaking a longer MAC.
     * In case of error, set the output length and content to a safe default,
     * such that in case the caller misses an error check, the output would be
     * an unachievable MAC.
     */
    if (status != PF_PSA_SUCCESS) {
        *mac_length = mac_size;
        operation_mac_size = 0;
    }

    pf_psa_wipe_tag_output_buffer(mac, status, mac_size, *mac_length);

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_mac_compute(pf_mbedtls_svc_key_id_t key,
                             pf_psa_algorithm_t alg,
                             const uint8_t *input_external,
                             size_t input_length,
                             uint8_t *mac_external,
                             size_t mac_size,
                             size_t *mac_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_OUTPUT_DECLARE(mac_external, mac);

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_OUTPUT_ALLOC(mac_external, mac_size, mac);
    status = pf_psa_mac_compute_internal(key, alg,
                                      input, input_length,
                                      mac, mac_size, mac_length, 1);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_OUTPUT_FREE(mac_external, mac);

    return status;
}

pf_psa_status_t pf_psa_mac_verify(pf_mbedtls_svc_key_id_t key,
                            pf_psa_algorithm_t alg,
                            const uint8_t *input_external,
                            size_t input_length,
                            const uint8_t *mac_external,
                            size_t mac_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t actual_mac[PF_PSA_MAC_MAX_SIZE];
    size_t actual_mac_length;
    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_INPUT_DECLARE(mac_external, mac);

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    status = pf_psa_mac_compute_internal(key, alg,
                                      input, input_length,
                                      actual_mac, sizeof(actual_mac),
                                      &actual_mac_length, 0);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (mac_length != actual_mac_length) {
        status = PF_PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(mac_external, mac_length, mac);
    if (pf_mbedtls_ct_memcmp(mac, actual_mac, actual_mac_length) != 0) {
        status = PF_PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    pf_mbedtls_platform_zeroize(actual_mac, sizeof(actual_mac));
    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_INPUT_FREE(mac_external, mac);

    return status;
}

/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

static pf_psa_status_t pf_psa_sign_verify_check_alg(int input_is_message,
                                              pf_psa_algorithm_t alg)
{
    if (input_is_message) {
        if (!PF_PSA_ALG_IS_SIGN_MESSAGE(alg)) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    pf_psa_algorithm_t hash_alg = 0;
    if (PF_PSA_ALG_IS_SIGN_HASH(alg)) {
        hash_alg = PF_PSA_ALG_SIGN_GET_HASH(alg);
    }

    /* Now hash_alg==0 if alg by itself doesn't need a hash.
     * This is good enough for sign-hash, but a guaranteed failure for
     * sign-message which needs to hash first for all algorithms
     * supported at the moment. */

    if (hash_alg == 0 && input_is_message) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
    if (hash_alg == PF_PSA_ALG_ANY_HASH) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Give up immediately if the hash is not supported. This has
     * several advantages:
     * - For mechanisms that don't use the hash at all (e.g.
     *   ECDSA verification, randomized ECDSA signature), without
     *   this check, the operation would succeed even though it has
     *   been given an invalid argument. This would not be insecure
     *   since the hash was not necessary, but it would be weird.
     * - For mechanisms that do use the hash, we avoid an error
     *   deep inside the execution. In principle this doesn't matter,
     *   but there is a little more risk of a bug in error handling
     *   deep inside than in this preliminary check.
     * - When calling a driver, the driver might be capable of using
     *   a hash that the core doesn't support. This could potentially
     *   result in a buffer overflow if the hash is larger than the
     *   maximum hash size assumed by the core.
     * - Returning a consistent error makes it possible to test
     *   not-supported hashes in a consistent way.
     */
    if (hash_alg != 0 && !is_hash_supported(hash_alg)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_sign_internal(pf_mbedtls_svc_key_id_t key,
                                      int input_is_message,
                                      pf_psa_algorithm_t alg,
                                      const uint8_t *input,
                                      size_t input_length,
                                      uint8_t *signature,
                                      size_t signature_size,
                                      size_t *signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    *signature_length = 0;

    status = pf_psa_sign_verify_check_alg(input_is_message, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    /* Immediately reject a zero-length signature buffer. This guarantees
     * that signature must be a valid pointer. (On the other hand, the input
     * buffer can in principle be empty since it doesn't actually have
     * to be a hash.) */
    if (signature_size == 0) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key, &slot,
        input_is_message ? PF_PSA_KEY_USAGE_SIGN_MESSAGE :
        PF_PSA_KEY_USAGE_SIGN_HASH,
        alg);

    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (!PF_PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (input_is_message) {
        status = pf_psa_driver_wrapper_sign_message(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_size, signature_length);
    } else {

        status = pf_psa_driver_wrapper_sign_hash(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_size, signature_length);
    }


exit:
    pf_psa_wipe_tag_output_buffer(signature, status, signature_size,
                               *signature_length);

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

static pf_psa_status_t pf_psa_verify_internal(pf_mbedtls_svc_key_id_t key,
                                        int input_is_message,
                                        pf_psa_algorithm_t alg,
                                        const uint8_t *input,
                                        size_t input_length,
                                        const uint8_t *signature,
                                        size_t signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    status = pf_psa_sign_verify_check_alg(input_is_message, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key, &slot,
        input_is_message ? PF_PSA_KEY_USAGE_VERIFY_MESSAGE :
        PF_PSA_KEY_USAGE_VERIFY_HASH,
        alg);

    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    if (input_is_message) {
        status = pf_psa_driver_wrapper_verify_message(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_length);
    } else {
        status = pf_psa_driver_wrapper_verify_hash(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_length);
    }

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;

}

pf_psa_status_t pf_psa_sign_message_builtin(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    pf_psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (PF_PSA_ALG_IS_SIGN_HASH(alg)) {
        size_t hash_length;
        uint8_t hash[PF_PSA_HASH_MAX_SIZE];

        status = pf_psa_driver_wrapper_hash_compute(
            PF_PSA_ALG_SIGN_GET_HASH(alg),
            input, input_length,
            hash, sizeof(hash), &hash_length);

        if (status != PF_PSA_SUCCESS) {
            return status;
        }

        return pf_psa_driver_wrapper_sign_hash(
            attributes, key_buffer, key_buffer_size,
            alg, hash, hash_length,
            signature, signature_size, signature_length);
    }

    return PF_PSA_ERROR_NOT_SUPPORTED;
}

pf_psa_status_t pf_psa_sign_message(pf_mbedtls_svc_key_id_t key,
                              pf_psa_algorithm_t alg,
                              const uint8_t *input_external,
                              size_t input_length,
                              uint8_t *signature_external,
                              size_t signature_size,
                              size_t *signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_OUTPUT_DECLARE(signature_external, signature);

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_OUTPUT_ALLOC(signature_external, signature_size, signature);
    status = pf_psa_sign_internal(key, 1, alg, input, input_length, signature,
                               signature_size, signature_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_OUTPUT_FREE(signature_external, signature);
    return status;
}

pf_psa_status_t pf_psa_verify_message_builtin(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    pf_psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (PF_PSA_ALG_IS_SIGN_HASH(alg)) {
        size_t hash_length;
        uint8_t hash[PF_PSA_HASH_MAX_SIZE];

        status = pf_psa_driver_wrapper_hash_compute(
            PF_PSA_ALG_SIGN_GET_HASH(alg),
            input, input_length,
            hash, sizeof(hash), &hash_length);

        if (status != PF_PSA_SUCCESS) {
            return status;
        }

        return pf_psa_driver_wrapper_verify_hash(
            attributes, key_buffer, key_buffer_size,
            alg, hash, hash_length,
            signature, signature_length);
    }

    return PF_PSA_ERROR_NOT_SUPPORTED;
}

pf_psa_status_t pf_psa_verify_message(pf_mbedtls_svc_key_id_t key,
                                pf_psa_algorithm_t alg,
                                const uint8_t *input_external,
                                size_t input_length,
                                const uint8_t *signature_external,
                                size_t signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_INPUT_DECLARE(signature_external, signature);

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_INPUT_ALLOC(signature_external, signature_length, signature);
    status = pf_psa_verify_internal(key, 1, alg, input, input_length, signature,
                                 signature_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_INPUT_FREE(signature_external, signature);

    return status;
}

pf_psa_status_t pf_psa_sign_hash_builtin(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    pf_psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    if (attributes->type == PF_PSA_KEY_TYPE_RSA_KEY_PAIR) {
        if (PF_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||
            PF_PSA_ALG_IS_RSA_PSS(alg)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
            return pf_mbedtls_psa_rsa_sign_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_size, signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS) */
        } else {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    } else if (PF_PSA_KEY_TYPE_IS_ECC(attributes->type)) {
        if (PF_PSA_ALG_IS_ECDSA(alg)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
            return pf_mbedtls_psa_ecdsa_sign_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_size, signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */
        } else {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    (void) key_buffer;
    (void) key_buffer_size;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    return PF_PSA_ERROR_NOT_SUPPORTED;
}

pf_psa_status_t pf_psa_sign_hash(pf_mbedtls_svc_key_id_t key,
                           pf_psa_algorithm_t alg,
                           const uint8_t *hash_external,
                           size_t hash_length,
                           uint8_t *signature_external,
                           size_t signature_size,
                           size_t *signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(hash_external, hash);
    LOCAL_OUTPUT_DECLARE(signature_external, signature);

    LOCAL_INPUT_ALLOC(hash_external, hash_length, hash);
    LOCAL_OUTPUT_ALLOC(signature_external, signature_size, signature);
    status = pf_psa_sign_internal(key, 0, alg, hash, hash_length, signature,
                               signature_size, signature_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(hash_external, hash);
    LOCAL_OUTPUT_FREE(signature_external, signature);

    return status;
}

pf_psa_status_t pf_psa_verify_hash_builtin(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    pf_psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    if (PF_PSA_KEY_TYPE_IS_RSA(attributes->type)) {
        if (PF_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||
            PF_PSA_ALG_IS_RSA_PSS(alg)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
            return pf_mbedtls_psa_rsa_verify_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS) */
        } else {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    } else if (PF_PSA_KEY_TYPE_IS_ECC(attributes->type)) {
        if (PF_PSA_ALG_IS_ECDSA(alg)) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
            return pf_mbedtls_psa_ecdsa_verify_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */
        } else {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    (void) key_buffer;
    (void) key_buffer_size;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;

    return PF_PSA_ERROR_NOT_SUPPORTED;
}

pf_psa_status_t pf_psa_verify_hash(pf_mbedtls_svc_key_id_t key,
                             pf_psa_algorithm_t alg,
                             const uint8_t *hash_external,
                             size_t hash_length,
                             const uint8_t *signature_external,
                             size_t signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(hash_external, hash);
    LOCAL_INPUT_DECLARE(signature_external, signature);

    LOCAL_INPUT_ALLOC(hash_external, hash_length, hash);
    LOCAL_INPUT_ALLOC(signature_external, signature_length, signature);
    status = pf_psa_verify_internal(key, 0, alg, hash, hash_length, signature,
                                 signature_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(hash_external, hash);
    LOCAL_INPUT_FREE(signature_external, signature);

    return status;
}

pf_psa_status_t pf_psa_asymmetric_encrypt(pf_mbedtls_svc_key_id_t key,
                                    pf_psa_algorithm_t alg,
                                    const uint8_t *input_external,
                                    size_t input_length,
                                    const uint8_t *salt_external,
                                    size_t salt_length,
                                    uint8_t *output_external,
                                    size_t output_size,
                                    size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_INPUT_DECLARE(salt_external, salt);
    LOCAL_OUTPUT_DECLARE(output_external, output);

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if (!PF_PSA_ALG_IS_RSA_OAEP(alg) && salt_length != 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key, &slot, PF_PSA_KEY_USAGE_ENCRYPT, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }
    if (!(PF_PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attr.type) ||
          PF_PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type))) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_INPUT_ALLOC(salt_external, salt_length, salt);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_driver_wrapper_asymmetric_encrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, input, input_length, salt, salt_length,
        output, output_size, output_length);
exit:
    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_INPUT_FREE(salt_external, salt);
    LOCAL_OUTPUT_FREE(output_external, output);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_asymmetric_decrypt(pf_mbedtls_svc_key_id_t key,
                                    pf_psa_algorithm_t alg,
                                    const uint8_t *input_external,
                                    size_t input_length,
                                    const uint8_t *salt_external,
                                    size_t salt_length,
                                    uint8_t *output_external,
                                    size_t output_size,
                                    size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_INPUT_DECLARE(salt_external, salt);
    LOCAL_OUTPUT_DECLARE(output_external, output);

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if (!PF_PSA_ALG_IS_RSA_OAEP(alg) && salt_length != 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key, &slot, PF_PSA_KEY_USAGE_DECRYPT, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }
    if (!PF_PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_INPUT_ALLOC(salt_external, salt_length, salt);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_driver_wrapper_asymmetric_decrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, input, input_length, salt, salt_length,
        output, output_size, output_length);

exit:
    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_INPUT_FREE(salt_external, salt);
    LOCAL_OUTPUT_FREE(output_external, output);

    /* Don't branch on status as it is a sensitive value
     * (it reveals whether padding was valid).
     * Instead branch on unlock_status. That means when both status and
     * unlock_status were errors, we'll return the unlock error while we would
     * normally return the first error, but that's better than leaking info. */
    return (unlock_status != PF_PSA_SUCCESS) ? unlock_status : status;
}

/****************************************************************/
/* Asymmetric interruptible cryptography                        */
/****************************************************************/

static uint32_t pf_psa_interruptible_max_ops = PF_PSA_INTERRUPTIBLE_MAX_OPS_UNLIMITED;

void pf_psa_interruptible_set_max_ops(uint32_t max_ops)
{
    pf_psa_interruptible_max_ops = max_ops;
}

uint32_t pf_psa_interruptible_get_max_ops(void)
{
    return pf_psa_interruptible_max_ops;
}

uint32_t pf_psa_sign_hash_get_num_ops(
    const pf_psa_sign_hash_interruptible_operation_t *operation)
{
    return operation->num_ops;
}

uint32_t pf_psa_verify_hash_get_num_ops(
    const pf_psa_verify_hash_interruptible_operation_t *operation)
{
    return operation->num_ops;
}

static pf_psa_status_t pf_psa_sign_hash_abort_internal(
    pf_psa_sign_hash_interruptible_operation_t *operation)
{
    if (operation->id == 0) {
        /* The object has (apparently) been initialized but it is not (yet)
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PF_PSA_SUCCESS;
    }

    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    status = pf_psa_driver_wrapper_sign_hash_abort(operation);

    operation->id = 0;

    /* Do not clear either the error_occurred or num_ops elements here as they
     * only want to be cleared by the application calling abort, not by abort
     * being called at completion of an operation. */

    return status;
}

pf_psa_status_t pf_psa_sign_hash_start(
    pf_psa_sign_hash_interruptible_operation_t *operation,
    pf_mbedtls_svc_key_id_t key, pf_psa_algorithm_t alg,
    const uint8_t *hash_external, size_t hash_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    LOCAL_INPUT_DECLARE(hash_external, hash);

    /* Check that start has not been previously called, or operation has not
     * previously errored. */
    if (operation->id != 0 || operation->error_occurred) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    status = pf_psa_sign_verify_check_alg(0, alg);
    if (status != PF_PSA_SUCCESS) {
        operation->error_occurred = 1;
        return status;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PF_PSA_KEY_USAGE_SIGN_HASH,
                                                   alg);

    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (!PF_PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(hash_external, hash_length, hash);

    /* Ensure ops count gets reset, in case of operation re-use. */
    operation->num_ops = 0;

    status = pf_psa_driver_wrapper_sign_hash_start(operation, &slot->attr,
                                                slot->key.data,
                                                slot->key.bytes, alg,
                                                hash, hash_length);
exit:

    if (status != PF_PSA_SUCCESS) {
        operation->error_occurred = 1;
        pf_psa_sign_hash_abort_internal(operation);
    }

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    if (unlock_status != PF_PSA_SUCCESS) {
        operation->error_occurred = 1;
    }

    LOCAL_INPUT_FREE(hash_external, hash);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}


pf_psa_status_t pf_psa_sign_hash_complete(
    pf_psa_sign_hash_interruptible_operation_t *operation,
    uint8_t *signature_external, size_t signature_size,
    size_t *signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    LOCAL_OUTPUT_DECLARE(signature_external, signature);

    *signature_length = 0;

    /* Check that start has been called first, and that operation has not
     * previously errored. */
    if (operation->id == 0 || operation->error_occurred) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Immediately reject a zero-length signature buffer. This guarantees that
     * signature must be a valid pointer. */
    if (signature_size == 0) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    LOCAL_OUTPUT_ALLOC(signature_external, signature_size, signature);

    status = pf_psa_driver_wrapper_sign_hash_complete(operation, signature,
                                                   signature_size,
                                                   signature_length);

    /* Update ops count with work done. */
    operation->num_ops = pf_psa_driver_wrapper_sign_hash_get_num_ops(operation);

exit:

    if (signature != NULL) {
        pf_psa_wipe_tag_output_buffer(signature, status, signature_size,
                                   *signature_length);
    }

    if (status != PF_PSA_OPERATION_INCOMPLETE) {
        if (status != PF_PSA_SUCCESS) {
            operation->error_occurred = 1;
        }

        pf_psa_sign_hash_abort_internal(operation);
    }

    LOCAL_OUTPUT_FREE(signature_external, signature);

    return status;
}

pf_psa_status_t pf_psa_sign_hash_abort(
    pf_psa_sign_hash_interruptible_operation_t *operation)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    status = pf_psa_sign_hash_abort_internal(operation);

    /* We clear the number of ops done here, so that it is not cleared when
     * the operation fails or succeeds, only on manual abort. */
    operation->num_ops = 0;

    /* Likewise, failure state. */
    operation->error_occurred = 0;

    return status;
}

static pf_psa_status_t pf_psa_verify_hash_abort_internal(
    pf_psa_verify_hash_interruptible_operation_t *operation)
{
    if (operation->id == 0) {
        /* The object has (apparently) been initialized but it is not (yet)
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PF_PSA_SUCCESS;
    }

    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    status = pf_psa_driver_wrapper_verify_hash_abort(operation);

    operation->id = 0;

    /* Do not clear either the error_occurred or num_ops elements here as they
     * only want to be cleared by the application calling abort, not by abort
     * being called at completion of an operation. */

    return status;
}

pf_psa_status_t pf_psa_verify_hash_start(
    pf_psa_verify_hash_interruptible_operation_t *operation,
    pf_mbedtls_svc_key_id_t key, pf_psa_algorithm_t alg,
    const uint8_t *hash_external, size_t hash_length,
    const uint8_t *signature_external, size_t signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    LOCAL_INPUT_DECLARE(hash_external, hash);
    LOCAL_INPUT_DECLARE(signature_external, signature);

    /* Check that start has not been previously called, or operation has not
     * previously errored. */
    if (operation->id != 0 || operation->error_occurred) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    status = pf_psa_sign_verify_check_alg(0, alg);
    if (status != PF_PSA_SUCCESS) {
        operation->error_occurred = 1;
        return status;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PF_PSA_KEY_USAGE_VERIFY_HASH,
                                                   alg);

    if (status != PF_PSA_SUCCESS) {
        operation->error_occurred = 1;
        return status;
    }

    LOCAL_INPUT_ALLOC(hash_external, hash_length, hash);
    LOCAL_INPUT_ALLOC(signature_external, signature_length, signature);

    /* Ensure ops count gets reset, in case of operation re-use. */
    operation->num_ops = 0;

    status = pf_psa_driver_wrapper_verify_hash_start(operation, &slot->attr,
                                                  slot->key.data,
                                                  slot->key.bytes,
                                                  alg, hash, hash_length,
                                                  signature, signature_length);
#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif

    if (status != PF_PSA_SUCCESS) {
        operation->error_occurred = 1;
        pf_psa_verify_hash_abort_internal(operation);
    }

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    if (unlock_status != PF_PSA_SUCCESS) {
        operation->error_occurred = 1;
    }

    LOCAL_INPUT_FREE(hash_external, hash);
    LOCAL_INPUT_FREE(signature_external, signature);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_verify_hash_complete(
    pf_psa_verify_hash_interruptible_operation_t *operation)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    /* Check that start has been called first, and that operation has not
     * previously errored. */
    if (operation->id == 0 || operation->error_occurred) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = pf_psa_driver_wrapper_verify_hash_complete(operation);

    /* Update ops count with work done. */
    operation->num_ops = pf_psa_driver_wrapper_verify_hash_get_num_ops(
        operation);

exit:

    if (status != PF_PSA_OPERATION_INCOMPLETE) {
        if (status != PF_PSA_SUCCESS) {
            operation->error_occurred = 1;
        }

        pf_psa_verify_hash_abort_internal(operation);
    }

    return status;
}

pf_psa_status_t pf_psa_verify_hash_abort(
    pf_psa_verify_hash_interruptible_operation_t *operation)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    status = pf_psa_verify_hash_abort_internal(operation);

    /* We clear the number of ops done here, so that it is not cleared when
     * the operation fails or succeeds, only on manual abort. */
    operation->num_ops = 0;

    /* Likewise, failure state. */
    operation->error_occurred = 0;

    return status;
}

/****************************************************************/
/* Asymmetric interruptible cryptography internal               */
/* implementations                                              */
/****************************************************************/

void pf_mbedtls_psa_interruptible_set_max_ops(uint32_t max_ops)
{

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    /* Internal implementation uses zero to indicate infinite number max ops,
     * therefore avoid this value, and set to minimum possible. */
    if (max_ops == 0) {
        max_ops = 1;
    }

    pf_mbedtls_ecp_set_max_ops(max_ops);
#else
    (void) max_ops;
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

uint32_t pf_mbedtls_psa_sign_hash_get_num_ops(
    const pf_mbedtls_psa_sign_hash_interruptible_operation_t *operation)
{
#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    return operation->num_ops;
#else
    (void) operation;
    return 0;
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

uint32_t pf_mbedtls_psa_verify_hash_get_num_ops(
    const pf_mbedtls_psa_verify_hash_interruptible_operation_t *operation)
{
    #if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    return operation->num_ops;
#else
    (void) operation;
    return 0;
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

/* Detect supported interruptible sign/verify mechanisms precisely.
 * This is not strictly needed: we could accept everything, and let the
 * code fail later during complete() if the mechanism is unsupported
 * (e.g. attempting deterministic ECDSA when only the randomized variant
 * is available). But it's easier for applications and especially for our
 * test code to detect all not-supported errors during start().
 *
 * Note that this function ignores the hash component. The core code
 * is supposed to check the hash part by calling is_hash_supported().
 */
static inline int can_do_interruptible_sign_verify(pf_psa_algorithm_t alg)
{
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
    if (PF_PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA)
    if (PF_PSA_ALG_IS_RANDOMIZED_ECDSA(alg)) {
        return 1;
    }
#endif
#endif /* defined(MBEDTLS_ECP_RESTARTABLE) */
    (void) alg;
    return 0;
}

pf_psa_status_t pf_mbedtls_psa_sign_hash_start(
    pf_mbedtls_psa_sign_hash_interruptible_operation_t *operation,
    const pf_psa_key_attributes_t *attributes, const uint8_t *key_buffer,
    size_t key_buffer_size, pf_psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    size_t required_hash_length;

    if (!PF_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes->type)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }
    pf_psa_ecc_family_t curve = PF_PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type);
    if (!PF_PSA_ECC_FAMILY_IS_WEIERSTRASS(curve)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!can_do_interruptible_sign_verify(alg)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    pf_mbedtls_ecdsa_restart_init(&operation->restart_ctx);

    /* Ensure num_ops is zero'ed in case of context re-use. */
    operation->num_ops = 0;

    status = pf_mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &operation->ctx);

    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    operation->coordinate_bytes = PF_PSA_BITS_TO_BYTES(
        operation->ctx->grp.nbits);

    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_SIGN_GET_HASH(alg);
    operation->md_alg = pf_mbedtls_md_type_from_psa_alg(hash_alg);
    operation->alg = alg;

    /* We only need to store the same length of hash as the private key size
     * here, it would be truncated by the internal implementation anyway. */
    required_hash_length = (hash_length < operation->coordinate_bytes ?
                            hash_length : operation->coordinate_bytes);

    if (required_hash_length > sizeof(operation->hash)) {
        /* Shouldn't happen, but better safe than sorry. */
        return PF_PSA_ERROR_CORRUPTION_DETECTED;
    }

    memcpy(operation->hash, hash, required_hash_length);
    operation->hash_length = required_hash_length;

    return PF_PSA_SUCCESS;

#else
    (void) operation;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) status;
    (void) required_hash_length;

    return PF_PSA_ERROR_NOT_SUPPORTED;
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

pf_psa_status_t pf_mbedtls_psa_sign_hash_complete(
    pf_mbedtls_psa_sign_hash_interruptible_operation_t *operation,
    uint8_t *signature, size_t signature_size,
    size_t *signature_length)
{
#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi r;
    pf_mbedtls_mpi s;

    pf_mbedtls_mpi_init(&r);
    pf_mbedtls_mpi_init(&s);

    /* Ensure max_ops is set to the current value (or default). */
    pf_mbedtls_psa_interruptible_set_max_ops(pf_psa_interruptible_get_max_ops());

    if (signature_size < 2 * operation->coordinate_bytes) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (PF_PSA_ALG_ECDSA_IS_DETERMINISTIC(operation->alg)) {

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
        status = pf_mbedtls_to_psa_error(
            pf_mbedtls_ecdsa_sign_det_restartable(&operation->ctx->grp,
                                               &r,
                                               &s,
                                               &operation->ctx->d,
                                               operation->hash,
                                               operation->hash_length,
                                               operation->md_alg,
                                               pf_mbedtls_psa_get_random,
                                               PF_MBEDTLS_PSA_RANDOM_STATE,
                                               &operation->restart_ctx));
#else /* defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */
        status = PF_PSA_ERROR_NOT_SUPPORTED;
        goto exit;
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */
    } else {
        status = pf_mbedtls_to_psa_error(
            pf_mbedtls_ecdsa_sign_restartable(&operation->ctx->grp,
                                           &r,
                                           &s,
                                           &operation->ctx->d,
                                           operation->hash,
                                           operation->hash_length,
                                           pf_mbedtls_psa_get_random,
                                           PF_MBEDTLS_PSA_RANDOM_STATE,
                                           pf_mbedtls_psa_get_random,
                                           PF_MBEDTLS_PSA_RANDOM_STATE,
                                           &operation->restart_ctx));
    }

    /* Hide the fact that the restart context only holds a delta of number of
     * ops done during the last operation, not an absolute value. */
    operation->num_ops += operation->restart_ctx.ecp.ops_done;

    if (status == PF_PSA_SUCCESS) {
        status =  pf_mbedtls_to_psa_error(
            pf_mbedtls_mpi_write_binary(&r,
                                     signature,
                                     operation->coordinate_bytes)
            );

        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }

        status =  pf_mbedtls_to_psa_error(
            pf_mbedtls_mpi_write_binary(&s,
                                     signature +
                                     operation->coordinate_bytes,
                                     operation->coordinate_bytes)
            );

        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }

        *signature_length = operation->coordinate_bytes * 2;

        status = PF_PSA_SUCCESS;
    }

exit:

    pf_mbedtls_mpi_free(&r);
    pf_mbedtls_mpi_free(&s);
    return status;

 #else

    (void) operation;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    return PF_PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

pf_psa_status_t pf_mbedtls_psa_sign_hash_abort(
    pf_mbedtls_psa_sign_hash_interruptible_operation_t *operation)
{

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    if (operation->ctx) {
        pf_mbedtls_ecdsa_free(operation->ctx);
        pf_mbedtls_free(operation->ctx);
        operation->ctx = NULL;
    }

    pf_mbedtls_ecdsa_restart_free(&operation->restart_ctx);

    operation->num_ops = 0;

    return PF_PSA_SUCCESS;

#else

    (void) operation;

    return PF_PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

pf_psa_status_t pf_mbedtls_psa_verify_hash_start(
    pf_mbedtls_psa_verify_hash_interruptible_operation_t *operation,
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    pf_psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    size_t coordinate_bytes = 0;
    size_t required_hash_length = 0;

    if (!PF_PSA_KEY_TYPE_IS_ECC(attributes->type)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }
    pf_psa_ecc_family_t curve = PF_PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type);
    if (!PF_PSA_ECC_FAMILY_IS_WEIERSTRASS(curve)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!can_do_interruptible_sign_verify(alg)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    pf_mbedtls_ecdsa_restart_init(&operation->restart_ctx);
    pf_mbedtls_mpi_init(&operation->r);
    pf_mbedtls_mpi_init(&operation->s);

    /* Ensure num_ops is zero'ed in case of context re-use. */
    operation->num_ops = 0;

    status = pf_mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &operation->ctx);

    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    coordinate_bytes = PF_PSA_BITS_TO_BYTES(operation->ctx->grp.nbits);

    if (signature_length != 2 * coordinate_bytes) {
        return PF_PSA_ERROR_INVALID_SIGNATURE;
    }

    status = pf_mbedtls_to_psa_error(
        pf_mbedtls_mpi_read_binary(&operation->r,
                                signature,
                                coordinate_bytes));

    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_mbedtls_to_psa_error(
        pf_mbedtls_mpi_read_binary(&operation->s,
                                signature +
                                coordinate_bytes,
                                coordinate_bytes));

    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_mbedtls_psa_ecp_load_public_part(operation->ctx);

    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    /* We only need to store the same length of hash as the private key size
     * here, it would be truncated by the internal implementation anyway. */
    required_hash_length = (hash_length < coordinate_bytes ? hash_length :
                            coordinate_bytes);

    if (required_hash_length > sizeof(operation->hash)) {
        /* Shouldn't happen, but better safe than sorry. */
        return PF_PSA_ERROR_CORRUPTION_DETECTED;
    }

    memcpy(operation->hash, hash, required_hash_length);
    operation->hash_length = required_hash_length;

    return PF_PSA_SUCCESS;
#else
    (void) operation;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    (void) status;
    (void) coordinate_bytes;
    (void) required_hash_length;

    return PF_PSA_ERROR_NOT_SUPPORTED;
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

pf_psa_status_t pf_mbedtls_psa_verify_hash_complete(
    pf_mbedtls_psa_verify_hash_interruptible_operation_t *operation)
{

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    /* Ensure max_ops is set to the current value (or default). */
    pf_mbedtls_psa_interruptible_set_max_ops(pf_psa_interruptible_get_max_ops());

    status = pf_mbedtls_to_psa_error(
        pf_mbedtls_ecdsa_verify_restartable(&operation->ctx->grp,
                                         operation->hash,
                                         operation->hash_length,
                                         &operation->ctx->Q,
                                         &operation->r,
                                         &operation->s,
                                         &operation->restart_ctx));

    /* Hide the fact that the restart context only holds a delta of number of
     * ops done during the last operation, not an absolute value. */
    operation->num_ops += operation->restart_ctx.ecp.ops_done;

    return status;
#else
    (void) operation;

    return PF_PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

pf_psa_status_t pf_mbedtls_psa_verify_hash_abort(
    pf_mbedtls_psa_verify_hash_interruptible_operation_t *operation)
{

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    if (operation->ctx) {
        pf_mbedtls_ecdsa_free(operation->ctx);
        pf_mbedtls_free(operation->ctx);
        operation->ctx = NULL;
    }

    pf_mbedtls_ecdsa_restart_free(&operation->restart_ctx);

    operation->num_ops = 0;

    pf_mbedtls_mpi_free(&operation->r);
    pf_mbedtls_mpi_free(&operation->s);

    return PF_PSA_SUCCESS;

#else
    (void) operation;

    return PF_PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

static pf_psa_status_t pf_psa_generate_random_internal(uint8_t *output,
                                                 size_t output_size)
{
    GUARD_MODULE_INITIALIZED;

#if defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

    pf_psa_status_t status;
    size_t output_length = 0;
    status = pf_mbedtls_psa_external_get_random(&global_data.rng,
                                             output, output_size,
                                             &output_length);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }
    /* Breaking up a request into smaller chunks is currently not supported
     * for the external RNG interface. */
    if (output_length != output_size) {
        return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    return PF_PSA_SUCCESS;

#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
    return pf_psa_random_internal_generate(&global_data.rng,
                                        output, output_size);
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
}


/****************************************************************/
/* Symmetric cryptography */
/****************************************************************/

static pf_psa_status_t pf_psa_cipher_setup(pf_psa_cipher_operation_t *operation,
                                     pf_mbedtls_svc_key_id_t key,
                                     pf_psa_algorithm_t alg,
                                     pf_mbedtls_operation_t cipher_operation)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;
    pf_psa_key_usage_t usage = (cipher_operation == PF_MBEDTLS_ENCRYPT ?
                             PF_PSA_KEY_USAGE_ENCRYPT :
                             PF_PSA_KEY_USAGE_DECRYPT);

    /* A context must be freshly initialized before it can be set up. */
    if (operation->id != 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!PF_PSA_ALG_IS_CIPHER(alg)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot, usage, alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    /* Initialize the operation struct members, except for id. The id member
     * is used to indicate to psa_cipher_abort that there are resources to free,
     * so we only set it (in the driver wrapper) after resources have been
     * allocated/initialized. */
    operation->iv_set = 0;
    if (alg == PF_PSA_ALG_ECB_NO_PADDING) {
        operation->iv_required = 0;
    } else {
        operation->iv_required = 1;
    }
    operation->default_iv_length = PF_PSA_CIPHER_IV_LENGTH(slot->attr.type, alg);


    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    /* Try doing the operation through a driver before using software fallback. */
    if (cipher_operation == PF_MBEDTLS_ENCRYPT) {
        status = pf_psa_driver_wrapper_cipher_encrypt_setup(operation,
                                                         &slot->attr,
                                                         slot->key.data,
                                                         slot->key.bytes,
                                                         alg);
    } else {
        status = pf_psa_driver_wrapper_cipher_decrypt_setup(operation,
                                                         &slot->attr,
                                                         slot->key.data,
                                                         slot->key.bytes,
                                                         alg);
    }

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_cipher_abort(operation);
    }

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_cipher_encrypt_setup(pf_psa_cipher_operation_t *operation,
                                      pf_mbedtls_svc_key_id_t key,
                                      pf_psa_algorithm_t alg)
{
    return pf_psa_cipher_setup(operation, key, alg, PF_MBEDTLS_ENCRYPT);
}

pf_psa_status_t pf_psa_cipher_decrypt_setup(pf_psa_cipher_operation_t *operation,
                                      pf_mbedtls_svc_key_id_t key,
                                      pf_psa_algorithm_t alg)
{
    return pf_psa_cipher_setup(operation, key, alg, PF_MBEDTLS_DECRYPT);
}

pf_psa_status_t pf_psa_cipher_generate_iv(pf_psa_cipher_operation_t *operation,
                                    uint8_t *iv_external,
                                    size_t iv_size,
                                    size_t *iv_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    size_t default_iv_length = 0;

    LOCAL_OUTPUT_DECLARE(iv_external, iv);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_set || !operation->iv_required) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    default_iv_length = operation->default_iv_length;
    if (iv_size < default_iv_length) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (default_iv_length > PF_PSA_CIPHER_IV_MAX_SIZE) {
        status = PF_PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    LOCAL_OUTPUT_ALLOC(iv_external, default_iv_length, iv);

    status = pf_psa_generate_random_internal(iv, default_iv_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_driver_wrapper_cipher_set_iv(operation,
                                              iv, default_iv_length);

exit:
    if (status == PF_PSA_SUCCESS) {
        *iv_length = default_iv_length;
        operation->iv_set = 1;
    } else {
        *iv_length = 0;
        pf_psa_cipher_abort(operation);
        if (iv != NULL) {
            pf_mbedtls_platform_zeroize(iv, default_iv_length);
        }
    }

    LOCAL_OUTPUT_FREE(iv_external, iv);
    return status;
}

pf_psa_status_t pf_psa_cipher_set_iv(pf_psa_cipher_operation_t *operation,
                               const uint8_t *iv_external,
                               size_t iv_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    LOCAL_INPUT_DECLARE(iv_external, iv);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_set || !operation->iv_required) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (iv_length > PF_PSA_CIPHER_IV_MAX_SIZE) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(iv_external, iv_length, iv);

    status = pf_psa_driver_wrapper_cipher_set_iv(operation,
                                              iv,
                                              iv_length);

exit:
    if (status == PF_PSA_SUCCESS) {
        operation->iv_set = 1;
    } else {
        pf_psa_cipher_abort(operation);
    }

    LOCAL_INPUT_FREE(iv_external, iv);

    return status;
}

pf_psa_status_t pf_psa_cipher_update(pf_psa_cipher_operation_t *operation,
                               const uint8_t *input_external,
                               size_t input_length,
                               uint8_t *output_external,
                               size_t output_size,
                               size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_OUTPUT_DECLARE(output_external, output);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_required && !operation->iv_set) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_driver_wrapper_cipher_update(operation,
                                              input,
                                              input_length,
                                              output,
                                              output_size,
                                              output_length);

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_cipher_abort(operation);
    }

    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_OUTPUT_FREE(output_external, output);

    return status;
}

pf_psa_status_t pf_psa_cipher_finish(pf_psa_cipher_operation_t *operation,
                               uint8_t *output_external,
                               size_t output_size,
                               size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_GENERIC_ERROR;

    LOCAL_OUTPUT_DECLARE(output_external, output);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_required && !operation->iv_set) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_driver_wrapper_cipher_finish(operation,
                                              output,
                                              output_size,
                                              output_length);

exit:
    /* C99 doesn't allow a declaration to follow a label */;
    pf_psa_status_t abort_status = pf_psa_cipher_abort(operation);
    /* Normally abort shouldn't fail unless the operation is in a bad
     * state, in which case we'd expect finish to fail with the same error.
     * So it doesn't matter much which call's error code we pick when both
     * fail. However, in unauthenticated decryption specifically, the
     * distinction between PSA_SUCCESS and PSA_ERROR_INVALID_PADDING is
     * security-sensitive (risk of a padding oracle attack), so here we
     * must not have a code path that depends on the value of status. */
    if (abort_status != PF_PSA_SUCCESS) {
        status = abort_status;
    }

    /* Set *output_length to 0 if status != PSA_SUCCESS, without
     * leaking the value of status through a timing side channel
     * (status == PSA_ERROR_INVALID_PADDING is sensitive when doing
     * unpadded decryption, due to the risk of padding oracle attack). */
    pf_mbedtls_ct_condition_t success =
        pf_mbedtls_ct_bool_not(pf_mbedtls_ct_bool(status));
    *output_length = pf_mbedtls_ct_size_if_else_0(success, *output_length);

    LOCAL_OUTPUT_FREE(output_external, output);

    return status;
}

pf_psa_status_t pf_psa_cipher_abort(pf_psa_cipher_operation_t *operation)
{
    if (operation->id == 0) {
        /* The object has (apparently) been initialized but it is not (yet)
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PF_PSA_SUCCESS;
    }

    pf_psa_driver_wrapper_cipher_abort(operation);

    operation->id = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_cipher_encrypt(pf_mbedtls_svc_key_id_t key,
                                pf_psa_algorithm_t alg,
                                const uint8_t *input_external,
                                size_t input_length,
                                uint8_t *output_external,
                                size_t output_size,
                                size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;
    uint8_t local_iv[PF_PSA_CIPHER_IV_MAX_SIZE];
    size_t default_iv_length = 0;

    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_OUTPUT_DECLARE(output_external, output);

    if (!PF_PSA_ALG_IS_CIPHER(alg)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PF_PSA_KEY_USAGE_ENCRYPT,
                                                   alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    default_iv_length = PF_PSA_CIPHER_IV_LENGTH(slot->attr.type, alg);
    if (default_iv_length > PF_PSA_CIPHER_IV_MAX_SIZE) {
        status = PF_PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (default_iv_length > 0) {
        if (output_size < default_iv_length) {
            status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
            goto exit;
        }

        status = pf_psa_generate_random_internal(local_iv, default_iv_length);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_driver_wrapper_cipher_encrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, local_iv, default_iv_length, input, input_length,
        pf_psa_crypto_buffer_offset(output, default_iv_length),
        output_size - default_iv_length, output_length);

exit:
    unlock_status = pf_psa_unregister_read_under_mutex(slot);
    if (status == PF_PSA_SUCCESS) {
        status = unlock_status;
    }

    if (status == PF_PSA_SUCCESS) {
        if (default_iv_length > 0) {
            memcpy(output, local_iv, default_iv_length);
        }
        *output_length += default_iv_length;
    } else {
        *output_length = 0;
    }

    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_OUTPUT_FREE(output_external, output);

    return status;
}

pf_psa_status_t pf_psa_cipher_decrypt(pf_mbedtls_svc_key_id_t key,
                                pf_psa_algorithm_t alg,
                                const uint8_t *input_external,
                                size_t input_length,
                                uint8_t *output_external,
                                size_t output_size,
                                size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;

    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_OUTPUT_DECLARE(output_external, output);

    if (!PF_PSA_ALG_IS_CIPHER(alg)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PF_PSA_KEY_USAGE_DECRYPT,
                                                   alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (input_length < PF_PSA_CIPHER_IV_LENGTH(slot->attr.type, alg)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_driver_wrapper_cipher_decrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, input, input_length,
        output, output_size, output_length);

exit:
    unlock_status = pf_psa_unregister_read_under_mutex(slot);
    if (unlock_status != PF_PSA_SUCCESS) {
        status = unlock_status;
    }

    /* Set *output_length to 0 if status != PSA_SUCCESS, without
     * leaking the value of status through a timing side channel
     * (status == PSA_ERROR_INVALID_PADDING is sensitive when doing
     * unpadded decryption, due to the risk of padding oracle attack). */
    pf_mbedtls_ct_condition_t success =
        pf_mbedtls_ct_bool_not(pf_mbedtls_ct_bool(status));
    *output_length = pf_mbedtls_ct_size_if_else_0(success, *output_length);

    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_OUTPUT_FREE(output_external, output);

    return status;
}


/****************************************************************/
/* AEAD */
/****************************************************************/

/* Helper function to get the base algorithm from its variants. */
static pf_psa_algorithm_t pf_psa_aead_get_base_algorithm(pf_psa_algorithm_t alg)
{
    return PF_PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);
}

/* Helper function to perform common nonce length checks. */
static pf_psa_status_t pf_psa_aead_check_nonce_length(pf_psa_algorithm_t alg,
                                                size_t nonce_length)
{
    pf_psa_algorithm_t base_alg = pf_psa_aead_get_base_algorithm(alg);

    switch (base_alg) {
#if defined(PF_PSA_WANT_ALG_GCM)
        case PF_PSA_ALG_GCM:
            /* Not checking max nonce size here as GCM spec allows almost
             * arbitrarily large nonces. Please note that we do not generally
             * recommend the usage of nonces of greater length than
             * PSA_AEAD_NONCE_MAX_SIZE, as large nonces are hashed to a shorter
             * size, which can then lead to collisions if you encrypt a very
             * large number of messages.*/
            if (nonce_length != 0) {
                return PF_PSA_SUCCESS;
            }
            break;
#endif /* PSA_WANT_ALG_GCM */
#if defined(PF_PSA_WANT_ALG_CCM)
        case PF_PSA_ALG_CCM:
            if (nonce_length >= 7 && nonce_length <= 13) {
                return PF_PSA_SUCCESS;
            }
            break;
#endif /* PSA_WANT_ALG_CCM */
#if defined(PF_PSA_WANT_ALG_CHACHA20_POLY1305)
        case PF_PSA_ALG_CHACHA20_POLY1305:
            if (nonce_length == 12) {
                return PF_PSA_SUCCESS;
            } else if (nonce_length == 8) {
                return PF_PSA_ERROR_NOT_SUPPORTED;
            }
            break;
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 */
        default:
            (void) nonce_length;
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_ERROR_INVALID_ARGUMENT;
}

static pf_psa_status_t pf_psa_aead_check_algorithm(pf_psa_algorithm_t alg)
{
    if (!PF_PSA_ALG_IS_AEAD(alg) || PF_PSA_ALG_IS_WILDCARD(alg)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_aead_encrypt(pf_mbedtls_svc_key_id_t key,
                              pf_psa_algorithm_t alg,
                              const uint8_t *nonce_external,
                              size_t nonce_length,
                              const uint8_t *additional_data_external,
                              size_t additional_data_length,
                              const uint8_t *plaintext_external,
                              size_t plaintext_length,
                              uint8_t *ciphertext_external,
                              size_t ciphertext_size,
                              size_t *ciphertext_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    LOCAL_INPUT_DECLARE(nonce_external, nonce);
    LOCAL_INPUT_DECLARE(additional_data_external, additional_data);
    LOCAL_INPUT_DECLARE(plaintext_external, plaintext);
    LOCAL_OUTPUT_DECLARE(ciphertext_external, ciphertext);

    *ciphertext_length = 0;

    status = pf_psa_aead_check_algorithm(alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key, &slot, PF_PSA_KEY_USAGE_ENCRYPT, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    LOCAL_INPUT_ALLOC(nonce_external, nonce_length, nonce);
    LOCAL_INPUT_ALLOC(additional_data_external, additional_data_length, additional_data);
    LOCAL_INPUT_ALLOC(plaintext_external, plaintext_length, plaintext);
    LOCAL_OUTPUT_ALLOC(ciphertext_external, ciphertext_size, ciphertext);

    status = pf_psa_aead_check_nonce_length(alg, nonce_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_driver_wrapper_aead_encrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg,
        nonce, nonce_length,
        additional_data, additional_data_length,
        plaintext, plaintext_length,
        ciphertext, ciphertext_size, ciphertext_length);

    if (status != PF_PSA_SUCCESS && ciphertext_size != 0) {
        memset(ciphertext, 0, ciphertext_size);
    }

exit:
    LOCAL_INPUT_FREE(nonce_external, nonce);
    LOCAL_INPUT_FREE(additional_data_external, additional_data);
    LOCAL_INPUT_FREE(plaintext_external, plaintext);
    LOCAL_OUTPUT_FREE(ciphertext_external, ciphertext);

    pf_psa_unregister_read_under_mutex(slot);

    return status;
}

pf_psa_status_t pf_psa_aead_decrypt(pf_mbedtls_svc_key_id_t key,
                              pf_psa_algorithm_t alg,
                              const uint8_t *nonce_external,
                              size_t nonce_length,
                              const uint8_t *additional_data_external,
                              size_t additional_data_length,
                              const uint8_t *ciphertext_external,
                              size_t ciphertext_length,
                              uint8_t *plaintext_external,
                              size_t plaintext_size,
                              size_t *plaintext_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    LOCAL_INPUT_DECLARE(nonce_external, nonce);
    LOCAL_INPUT_DECLARE(additional_data_external, additional_data);
    LOCAL_INPUT_DECLARE(ciphertext_external, ciphertext);
    LOCAL_OUTPUT_DECLARE(plaintext_external, plaintext);

    *plaintext_length = 0;

    status = pf_psa_aead_check_algorithm(alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(
        key, &slot, PF_PSA_KEY_USAGE_DECRYPT, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    LOCAL_INPUT_ALLOC(nonce_external, nonce_length, nonce);
    LOCAL_INPUT_ALLOC(additional_data_external, additional_data_length,
                      additional_data);
    LOCAL_INPUT_ALLOC(ciphertext_external, ciphertext_length, ciphertext);
    LOCAL_OUTPUT_ALLOC(plaintext_external, plaintext_size, plaintext);

    status = pf_psa_aead_check_nonce_length(alg, nonce_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_driver_wrapper_aead_decrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg,
        nonce, nonce_length,
        additional_data, additional_data_length,
        ciphertext, ciphertext_length,
        plaintext, plaintext_size, plaintext_length);

    if (status != PF_PSA_SUCCESS && plaintext_size != 0) {
        memset(plaintext, 0, plaintext_size);
    }

exit:
    LOCAL_INPUT_FREE(nonce_external, nonce);
    LOCAL_INPUT_FREE(additional_data_external, additional_data);
    LOCAL_INPUT_FREE(ciphertext_external, ciphertext);
    LOCAL_OUTPUT_FREE(plaintext_external, plaintext);

    pf_psa_unregister_read_under_mutex(slot);

    return status;
}

static pf_psa_status_t pf_psa_validate_tag_length(pf_psa_algorithm_t alg)
{
    const uint8_t tag_len = PF_PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

    switch (PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0)) {
#if defined(PF_PSA_WANT_ALG_CCM)
        case PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, 0):
            /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16.*/
            if (tag_len < 4 || tag_len > 16 || tag_len % 2) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif /* PSA_WANT_ALG_CCM */

#if defined(PF_PSA_WANT_ALG_GCM)
        case PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_GCM, 0):
            /* GCM allows the following tag lengths: 4, 8, 12, 13, 14, 15, 16. */
            if (tag_len != 4 && tag_len != 8 && (tag_len < 12 || tag_len > 16)) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif /* PSA_WANT_ALG_GCM */

#if defined(PF_PSA_WANT_ALG_CHACHA20_POLY1305)
        case PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CHACHA20_POLY1305, 0):
            /* We only support the default tag length. */
            if (tag_len != 16) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 */

        default:
            (void) tag_len;
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }
    return PF_PSA_SUCCESS;
}

/* Set the key for a multipart authenticated operation. */
static pf_psa_status_t pf_psa_aead_setup(pf_psa_aead_operation_t *operation,
                                   int is_encrypt,
                                   pf_mbedtls_svc_key_id_t key,
                                   pf_psa_algorithm_t alg)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;
    pf_psa_key_usage_t key_usage = 0;

    status = pf_psa_aead_check_algorithm(alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (operation->id != 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->nonce_set || operation->lengths_set ||
        operation->ad_started || operation->body_started) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    if (is_encrypt) {
        key_usage = PF_PSA_KEY_USAGE_ENCRYPT;
    } else {
        key_usage = PF_PSA_KEY_USAGE_DECRYPT;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(key, &slot, key_usage,
                                                   alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if ((status = pf_psa_validate_tag_length(alg)) != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (is_encrypt) {
        status = pf_psa_driver_wrapper_aead_encrypt_setup(operation,
                                                       &slot->attr,
                                                       slot->key.data,
                                                       slot->key.bytes,
                                                       alg);
    } else {
        status = pf_psa_driver_wrapper_aead_decrypt_setup(operation,
                                                       &slot->attr,
                                                       slot->key.data,
                                                       slot->key.bytes,
                                                       alg);
    }
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    operation->key_type = pf_psa_get_key_type(&slot->attr);

exit:
    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    if (status == PF_PSA_SUCCESS) {
        status = unlock_status;
        operation->alg = pf_psa_aead_get_base_algorithm(alg);
        operation->is_encrypt = is_encrypt;
    } else {
        pf_psa_aead_abort(operation);
    }

    return status;
}

/* Set the key for a multipart authenticated encryption operation. */
pf_psa_status_t pf_psa_aead_encrypt_setup(pf_psa_aead_operation_t *operation,
                                    pf_mbedtls_svc_key_id_t key,
                                    pf_psa_algorithm_t alg)
{
    return pf_psa_aead_setup(operation, 1, key, alg);
}

/* Set the key for a multipart authenticated decryption operation. */
pf_psa_status_t pf_psa_aead_decrypt_setup(pf_psa_aead_operation_t *operation,
                                    pf_mbedtls_svc_key_id_t key,
                                    pf_psa_algorithm_t alg)
{
    return pf_psa_aead_setup(operation, 0, key, alg);
}

static pf_psa_status_t pf_psa_aead_set_nonce_internal(pf_psa_aead_operation_t *operation,
                                                const uint8_t *nonce,
                                                size_t nonce_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->nonce_set) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = pf_psa_aead_check_nonce_length(operation->alg, nonce_length);
    if (status != PF_PSA_SUCCESS) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = pf_psa_driver_wrapper_aead_set_nonce(operation, nonce,
                                               nonce_length);

exit:
    if (status == PF_PSA_SUCCESS) {
        operation->nonce_set = 1;
    } else {
        pf_psa_aead_abort(operation);
    }

    return status;
}

/* Generate a random nonce / IV for multipart AEAD operation */
pf_psa_status_t pf_psa_aead_generate_nonce(pf_psa_aead_operation_t *operation,
                                     uint8_t *nonce_external,
                                     size_t nonce_size,
                                     size_t *nonce_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t local_nonce[PF_PSA_AEAD_NONCE_MAX_SIZE];
    size_t required_nonce_size = 0;

    LOCAL_OUTPUT_DECLARE(nonce_external, nonce);
    LOCAL_OUTPUT_ALLOC(nonce_external, nonce_size, nonce);

    *nonce_length = 0;

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->nonce_set || !operation->is_encrypt) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* For CCM, this size may not be correct according to the PSA
     * specification. The PSA Crypto 1.0.1 specification states:
     *
     * CCM encodes the plaintext length pLen in L octets, with L the smallest
     * integer >= 2 where pLen < 2^(8L). The nonce length is then 15 - L bytes.
     *
     * However this restriction that L has to be the smallest integer is not
     * applied in practice, and it is not implementable here since the
     * plaintext length may or may not be known at this time. */
    required_nonce_size = PF_PSA_AEAD_NONCE_LENGTH(operation->key_type,
                                                operation->alg);
    if (nonce_size < required_nonce_size) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = pf_psa_generate_random_internal(local_nonce, required_nonce_size);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_aead_set_nonce_internal(operation, local_nonce,
                                         required_nonce_size);

exit:
    if (status == PF_PSA_SUCCESS) {
        memcpy(nonce, local_nonce, required_nonce_size);
        *nonce_length = required_nonce_size;
    } else {
        pf_psa_aead_abort(operation);
    }

    LOCAL_OUTPUT_FREE(nonce_external, nonce);

    return status;
}

/* Set the nonce for a multipart authenticated encryption or decryption
   operation.*/
pf_psa_status_t pf_psa_aead_set_nonce(pf_psa_aead_operation_t *operation,
                                const uint8_t *nonce_external,
                                size_t nonce_length)
{
    pf_psa_status_t status;

    LOCAL_INPUT_DECLARE(nonce_external, nonce);
    LOCAL_INPUT_ALLOC(nonce_external, nonce_length, nonce);

    status = pf_psa_aead_set_nonce_internal(operation, nonce, nonce_length);

/* Exit label is only needed for buffer copying, prevent unused warnings. */
#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif

    LOCAL_INPUT_FREE(nonce_external, nonce);

    return status;
}

/* Declare the lengths of the message and additional data for multipart AEAD. */
pf_psa_status_t pf_psa_aead_set_lengths(pf_psa_aead_operation_t *operation,
                                  size_t ad_length,
                                  size_t plaintext_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->lengths_set || operation->ad_started ||
        operation->body_started) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    switch (operation->alg) {
#if defined(PF_PSA_WANT_ALG_GCM)
        case PF_PSA_ALG_GCM:
            /* Lengths can only be too large for GCM if size_t is bigger than 32
             * bits. Without the guard this code will generate warnings on 32bit
             * builds. */
#if SIZE_MAX > UINT32_MAX
            if (((uint64_t) ad_length) >> 61 != 0 ||
                ((uint64_t) plaintext_length) > 0xFFFFFFFE0ull) {
                status = PF_PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
#endif
            break;
#endif /* PSA_WANT_ALG_GCM */
#if defined(PF_PSA_WANT_ALG_CCM)
        case PF_PSA_ALG_CCM:
            if (ad_length > 0xFF00) {
                status = PF_PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
            break;
#endif /* PSA_WANT_ALG_CCM */
#if defined(PF_PSA_WANT_ALG_CHACHA20_POLY1305)
        case PF_PSA_ALG_CHACHA20_POLY1305:
#if SIZE_MAX > UINT32_MAX
            if (plaintext_length > (size_t) UINT32_MAX *
                64U) {
                status = PF_PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
#endif
            break;
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 */
        default:
            break;
    }

    status = pf_psa_driver_wrapper_aead_set_lengths(operation, ad_length,
                                                 plaintext_length);

exit:
    if (status == PF_PSA_SUCCESS) {
        operation->ad_remaining = ad_length;
        operation->body_remaining = plaintext_length;
        operation->lengths_set = 1;
    } else {
        pf_psa_aead_abort(operation);
    }

    return status;
}

/* Pass additional data to an active multipart AEAD operation. */
pf_psa_status_t pf_psa_aead_update_ad(pf_psa_aead_operation_t *operation,
                                const uint8_t *input_external,
                                size_t input_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_INPUT_ALLOC(input_external, input_length, input);

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!operation->nonce_set || operation->body_started) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* No input to add (zero length), nothing to do. */
    if (input_length == 0) {
        status = PF_PSA_SUCCESS;
        goto exit;
    }

    if (operation->lengths_set) {
        if (operation->ad_remaining < input_length) {
            status = PF_PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->ad_remaining -= input_length;
    }
#if defined(PF_PSA_WANT_ALG_CCM)
    else if (operation->alg == PF_PSA_ALG_CCM) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }
#endif /* PSA_WANT_ALG_CCM */

    status = pf_psa_driver_wrapper_aead_update_ad(operation, input,
                                               input_length);

exit:
    if (status == PF_PSA_SUCCESS) {
        operation->ad_started = 1;
    } else {
        pf_psa_aead_abort(operation);
    }

    LOCAL_INPUT_FREE(input_external, input);

    return status;
}

/* Encrypt or decrypt a message fragment in an active multipart AEAD
   operation.*/
pf_psa_status_t pf_psa_aead_update(pf_psa_aead_operation_t *operation,
                             const uint8_t *input_external,
                             size_t input_length,
                             uint8_t *output_external,
                             size_t output_size,
                             size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;


    LOCAL_INPUT_DECLARE(input_external, input);
    LOCAL_OUTPUT_DECLARE(output_external, output);

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    *output_length = 0;

    if (operation->id == 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!operation->nonce_set) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->lengths_set) {
        /* Additional data length was supplied, but not all the additional
           data was supplied.*/
        if (operation->ad_remaining != 0) {
            status = PF_PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        /* Too much data provided. */
        if (operation->body_remaining < input_length) {
            status = PF_PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->body_remaining -= input_length;
    }
#if defined(PF_PSA_WANT_ALG_CCM)
    else if (operation->alg == PF_PSA_ALG_CCM) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }
#endif /* PSA_WANT_ALG_CCM */

    status = pf_psa_driver_wrapper_aead_update(operation, input, input_length,
                                            output, output_size,
                                            output_length);

exit:
    if (status == PF_PSA_SUCCESS) {
        operation->body_started = 1;
    } else {
        pf_psa_aead_abort(operation);
    }

    LOCAL_INPUT_FREE(input_external, input);
    LOCAL_OUTPUT_FREE(output_external, output);

    return status;
}

static pf_psa_status_t pf_psa_aead_final_checks(const pf_psa_aead_operation_t *operation)
{
    if (operation->alg == PF_PSA_ALG_CCM && !operation->lengths_set) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (operation->id == 0 || !operation->nonce_set) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (operation->lengths_set && (operation->ad_remaining != 0 ||
                                   operation->body_remaining != 0)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    return PF_PSA_SUCCESS;
}

/* Finish encrypting a message in a multipart AEAD operation. */
pf_psa_status_t pf_psa_aead_finish(pf_psa_aead_operation_t *operation,
                             uint8_t *ciphertext_external,
                             size_t ciphertext_size,
                             size_t *ciphertext_length,
                             uint8_t *tag_external,
                             size_t tag_size,
                             size_t *tag_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    LOCAL_OUTPUT_DECLARE(ciphertext_external, ciphertext);
    LOCAL_OUTPUT_DECLARE(tag_external, tag);

    LOCAL_OUTPUT_ALLOC(ciphertext_external, ciphertext_size, ciphertext);
    LOCAL_OUTPUT_ALLOC(tag_external, tag_size, tag);

    *ciphertext_length = 0;
    *tag_length = tag_size;

    status = pf_psa_aead_final_checks(operation);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (!operation->is_encrypt) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = pf_psa_driver_wrapper_aead_finish(operation, ciphertext,
                                            ciphertext_size,
                                            ciphertext_length,
                                            tag, tag_size, tag_length);

exit:


    /* In case the operation fails and the user fails to check for failure or
     * the zero tag size, make sure the tag is set to something implausible.
     * Even if the operation succeeds, make sure we clear the rest of the
     * buffer to prevent potential leakage of anything previously placed in
     * the same buffer.*/
    pf_psa_wipe_tag_output_buffer(tag, status, tag_size, *tag_length);

    pf_psa_aead_abort(operation);

    LOCAL_OUTPUT_FREE(ciphertext_external, ciphertext);
    LOCAL_OUTPUT_FREE(tag_external, tag);

    return status;
}

/* Finish authenticating and decrypting a message in a multipart AEAD
   operation.*/
pf_psa_status_t pf_psa_aead_verify(pf_psa_aead_operation_t *operation,
                             uint8_t *plaintext_external,
                             size_t plaintext_size,
                             size_t *plaintext_length,
                             const uint8_t *tag_external,
                             size_t tag_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    LOCAL_OUTPUT_DECLARE(plaintext_external, plaintext);
    LOCAL_INPUT_DECLARE(tag_external, tag);

    LOCAL_OUTPUT_ALLOC(plaintext_external, plaintext_size, plaintext);
    LOCAL_INPUT_ALLOC(tag_external, tag_length, tag);

    *plaintext_length = 0;

    status = pf_psa_aead_final_checks(operation);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (operation->is_encrypt) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = pf_psa_driver_wrapper_aead_verify(operation, plaintext,
                                            plaintext_size,
                                            plaintext_length,
                                            tag, tag_length);

exit:
    pf_psa_aead_abort(operation);

    LOCAL_OUTPUT_FREE(plaintext_external, plaintext);
    LOCAL_INPUT_FREE(tag_external, tag);

    return status;
}

/* Abort an AEAD operation. */
pf_psa_status_t pf_psa_aead_abort(pf_psa_aead_operation_t *operation)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        /* The object has (apparently) been initialized but it is not (yet)
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PF_PSA_SUCCESS;
    }

    status = pf_psa_driver_wrapper_aead_abort(operation);

    memset(operation, 0, sizeof(*operation));

    return status;
}

/****************************************************************/
/* Key derivation: output generation */
/****************************************************************/

#if defined(BUILTIN_ALG_ANY_HKDF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS) || \
    defined(PF_PSA_HAVE_SOFT_PBKDF2)
#define AT_LEAST_ONE_BUILTIN_KDF
#endif /* At least one builtin KDF */

#if defined(BUILTIN_ALG_ANY_HKDF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)

/** Internal helper to set up an HMAC operation with a key passed directly.
 *
 * \param[in,out] operation     A MAC operation object. It does not need to
 *                              be initialized.
 * \param hash_alg              The hash algorithm used for HMAC.
 * \param hmac_key              The HMAC key.
 * \param hmac_key_length       Length of \p hmac_key in bytes.
 *
 * \return A PSA status code.
 */
static pf_psa_status_t pf_psa_key_derivation_start_hmac(
    pf_psa_mac_operation_t *operation,
    pf_psa_algorithm_t hash_alg,
    const uint8_t *hmac_key,
    size_t hmac_key_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_HMAC);
    pf_psa_set_key_bits(&attributes, PF_PSA_BYTES_TO_BITS(hmac_key_length));
    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_SIGN_HASH);

    /* Make sure the whole the operation is zeroed.
     * It isn't enough to require the caller to initialize operation to
     * PSA_MAC_OPERATION_INIT, since one field is a union and initializing
     * a union does not necessarily initialize all of its members.
     * psa_mac_setup() would handle PSA_MAC_OPERATION_INIT, but here we
     * bypass it and call lower-level functions directly. */
    memset(operation, 0, sizeof(*operation));

    operation->is_sign = 1;
    operation->mac_size = PF_PSA_HASH_LENGTH(hash_alg);

    status = pf_psa_driver_wrapper_mac_sign_setup(operation,
                                               &attributes,
                                               hmac_key, hmac_key_length,
                                               PF_PSA_ALG_HMAC(hash_alg));

    pf_psa_reset_key_attributes(&attributes);
    return status;
}
#endif /* KDF algorithms reliant on HMAC */

#define HKDF_STATE_INIT 0 /* no input yet */
#define HKDF_STATE_STARTED 1 /* got salt */
#define HKDF_STATE_KEYED 2 /* got key */
#define HKDF_STATE_OUTPUT 3 /* output started */

static pf_psa_algorithm_t pf_psa_key_derivation_get_kdf_alg(
    const pf_psa_key_derivation_operation_t *operation)
{
    if (PF_PSA_ALG_IS_KEY_AGREEMENT(operation->alg)) {
        return PF_PSA_ALG_KEY_AGREEMENT_GET_KDF(operation->alg);
    } else {
        return operation->alg;
    }
}

pf_psa_status_t pf_psa_key_derivation_abort(pf_psa_key_derivation_operation_t *operation)
{
    pf_psa_status_t status = PF_PSA_SUCCESS;
    pf_psa_algorithm_t kdf_alg = pf_psa_key_derivation_get_kdf_alg(operation);
    if (kdf_alg == 0) {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
    } else
#if defined(BUILTIN_ALG_ANY_HKDF)
    if (PF_PSA_ALG_IS_ANY_HKDF(kdf_alg)) {
        pf_mbedtls_free(operation->ctx.hkdf.info);
        status = pf_psa_mac_abort(&operation->ctx.hkdf.hmac);
    } else
#endif /* BUILTIN_ALG_ANY_HKDF */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if (PF_PSA_ALG_IS_TLS12_PRF(kdf_alg) ||
        /* TLS-1.2 PSK-to-MS KDF uses the same core as TLS-1.2 PRF */
        PF_PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg)) {
        if (operation->ctx.tls12_prf.secret != NULL) {
            pf_mbedtls_zeroize_and_free(operation->ctx.tls12_prf.secret,
                                     operation->ctx.tls12_prf.secret_length);
        }

        if (operation->ctx.tls12_prf.seed != NULL) {
            pf_mbedtls_zeroize_and_free(operation->ctx.tls12_prf.seed,
                                     operation->ctx.tls12_prf.seed_length);
        }

        if (operation->ctx.tls12_prf.label != NULL) {
            pf_mbedtls_zeroize_and_free(operation->ctx.tls12_prf.label,
                                     operation->ctx.tls12_prf.label_length);
        }
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
        if (operation->ctx.tls12_prf.other_secret != NULL) {
            pf_mbedtls_zeroize_and_free(operation->ctx.tls12_prf.other_secret,
                                     operation->ctx.tls12_prf.other_secret_length);
        }
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */
        status = PF_PSA_SUCCESS;

        /* We leave the fields Ai and output_block to be erased safely by the
         * mbedtls_platform_zeroize() in the end of this function. */
    } else
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS) */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if (kdf_alg == PF_PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        pf_mbedtls_platform_zeroize(operation->ctx.tls12_ecjpake_to_pms.data,
                                 sizeof(operation->ctx.tls12_ecjpake_to_pms.data));
    } else
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS) */
#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
    if (PF_PSA_ALG_IS_PBKDF2(kdf_alg)) {
        if (operation->ctx.pbkdf2.salt != NULL) {
            pf_mbedtls_zeroize_and_free(operation->ctx.pbkdf2.salt,
                                     operation->ctx.pbkdf2.salt_length);
        }

        status = PF_PSA_SUCCESS;
    } else
#endif /* defined(PSA_HAVE_SOFT_PBKDF2) */
    {
        status = PF_PSA_ERROR_BAD_STATE;
    }
    pf_mbedtls_platform_zeroize(operation, sizeof(*operation));
    return status;
}

pf_psa_status_t pf_psa_key_derivation_get_capacity(const pf_psa_key_derivation_operation_t *operation,
                                             size_t *capacity)
{
    if (operation->alg == 0) {
        /* This is a blank key derivation operation. */
        return PF_PSA_ERROR_BAD_STATE;
    }

    *capacity = operation->capacity;
    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_key_derivation_set_capacity(pf_psa_key_derivation_operation_t *operation,
                                             size_t capacity)
{
    if (operation->alg == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }
    if (capacity > operation->capacity) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
    operation->capacity = capacity;
    return PF_PSA_SUCCESS;
}

#if defined(BUILTIN_ALG_ANY_HKDF)
/* Read some bytes from an HKDF-based operation. */
static pf_psa_status_t pf_psa_key_derivation_hkdf_read(pf_psa_hkdf_key_derivation_t *hkdf,
                                                 pf_psa_algorithm_t kdf_alg,
                                                 uint8_t *output,
                                                 size_t output_length)
{
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_HKDF_GET_HASH(kdf_alg);
    uint8_t hash_length = PF_PSA_HASH_LENGTH(hash_alg);
    size_t hmac_output_length;
    pf_psa_status_t status;
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
    const uint8_t last_block = PF_PSA_ALG_IS_HKDF_EXTRACT(kdf_alg) ? 0 : 0xff;
#else
    const uint8_t last_block = 0xff;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT */

    if (hkdf->state < HKDF_STATE_KEYED ||
        (!hkdf->info_set
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
         && !PF_PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT */
        )) {
        return PF_PSA_ERROR_BAD_STATE;
    }
    hkdf->state = HKDF_STATE_OUTPUT;

    while (output_length != 0) {
        /* Copy what remains of the current block */
        uint8_t n = hash_length - hkdf->offset_in_block;
        if (n > output_length) {
            n = (uint8_t) output_length;
        }
        memcpy(output, hkdf->output_block + hkdf->offset_in_block, n);
        output += n;
        output_length -= n;
        hkdf->offset_in_block += n;
        if (output_length == 0) {
            break;
        }
        /* We can't be wanting more output after the last block, otherwise
         * the capacity check in psa_key_derivation_output_bytes() would have
         * prevented this call. It could happen only if the operation
         * object was corrupted or if this function is called directly
         * inside the library. */
        if (hkdf->block_number == last_block) {
            return PF_PSA_ERROR_BAD_STATE;
        }

        /* We need a new block */
        ++hkdf->block_number;
        hkdf->offset_in_block = 0;

        status = pf_psa_key_derivation_start_hmac(&hkdf->hmac,
                                               hash_alg,
                                               hkdf->prk,
                                               hash_length);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }

        if (hkdf->block_number != 1) {
            status = pf_psa_mac_update(&hkdf->hmac,
                                    hkdf->output_block,
                                    hash_length);
            if (status != PF_PSA_SUCCESS) {
                return status;
            }
        }
        status = pf_psa_mac_update(&hkdf->hmac,
                                hkdf->info,
                                hkdf->info_length);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
        status = pf_psa_mac_update(&hkdf->hmac,
                                &hkdf->block_number, 1);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
        status = pf_psa_mac_sign_finish(&hkdf->hmac,
                                     hkdf->output_block,
                                     sizeof(hkdf->output_block),
                                     &hmac_output_length);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
    }

    return PF_PSA_SUCCESS;
}
#endif /* BUILTIN_ALG_ANY_HKDF */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
static pf_psa_status_t pf_psa_key_derivation_tls12_prf_generate_next_block(
    pf_psa_tls12_prf_key_derivation_t *tls12_prf,
    pf_psa_algorithm_t alg)
{
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_HKDF_GET_HASH(alg);
    uint8_t hash_length = PF_PSA_HASH_LENGTH(hash_alg);
    pf_psa_mac_operation_t hmac;
    size_t hmac_output_length;
    pf_psa_status_t status, cleanup_status;

    /* We can't be wanting more output after block 0xff, otherwise
     * the capacity check in psa_key_derivation_output_bytes() would have
     * prevented this call. It could happen only if the operation
     * object was corrupted or if this function is called directly
     * inside the library. */
    if (tls12_prf->block_number == 0xff) {
        return PF_PSA_ERROR_CORRUPTION_DETECTED;
    }

    /* We need a new block */
    ++tls12_prf->block_number;
    tls12_prf->left_in_block = hash_length;

    /* Recall the definition of the TLS-1.2-PRF from RFC 5246:
     *
     * PRF(secret, label, seed) = P_<hash>(secret, label + seed)
     *
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) +
     *                        HMAC_hash(secret, A(3) + seed) + ...
     *
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i-1))
     *
     * The `psa_tls12_prf_key_derivation` structure saves the block
     * `HMAC_hash(secret, A(i) + seed)` from which the output
     * is currently extracted as `output_block` and where i is
     * `block_number`.
     */

    status = pf_psa_key_derivation_start_hmac(&hmac,
                                           hash_alg,
                                           tls12_prf->secret,
                                           tls12_prf->secret_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }

    /* Calculate A(i) where i = tls12_prf->block_number. */
    if (tls12_prf->block_number == 1) {
        /* A(1) = HMAC_hash(secret, A(0)), where A(0) = seed. (The RFC overloads
         * the variable seed and in this instance means it in the context of the
         * P_hash function, where seed = label + seed.) */
        status = pf_psa_mac_update(&hmac,
                                tls12_prf->label,
                                tls12_prf->label_length);
        if (status != PF_PSA_SUCCESS) {
            goto cleanup;
        }
        status = pf_psa_mac_update(&hmac,
                                tls12_prf->seed,
                                tls12_prf->seed_length);
        if (status != PF_PSA_SUCCESS) {
            goto cleanup;
        }
    } else {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        status = pf_psa_mac_update(&hmac, tls12_prf->Ai, hash_length);
        if (status != PF_PSA_SUCCESS) {
            goto cleanup;
        }
    }

    status = pf_psa_mac_sign_finish(&hmac,
                                 tls12_prf->Ai, hash_length,
                                 &hmac_output_length);
    if (hmac_output_length != hash_length) {
        status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }

    /* Calculate HMAC_hash(secret, A(i) + label + seed). */
    status = pf_psa_key_derivation_start_hmac(&hmac,
                                           hash_alg,
                                           tls12_prf->secret,
                                           tls12_prf->secret_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_mac_update(&hmac, tls12_prf->Ai, hash_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_mac_update(&hmac, tls12_prf->label, tls12_prf->label_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_mac_update(&hmac, tls12_prf->seed, tls12_prf->seed_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_mac_sign_finish(&hmac,
                                 tls12_prf->output_block, hash_length,
                                 &hmac_output_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }


cleanup:
    cleanup_status = pf_psa_mac_abort(&hmac);
    if (status == PF_PSA_SUCCESS && cleanup_status != PF_PSA_SUCCESS) {
        status = cleanup_status;
    }

    return status;
}

static pf_psa_status_t pf_psa_key_derivation_tls12_prf_read(
    pf_psa_tls12_prf_key_derivation_t *tls12_prf,
    pf_psa_algorithm_t alg,
    uint8_t *output,
    size_t output_length)
{
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_TLS12_PRF_GET_HASH(alg);
    uint8_t hash_length = PF_PSA_HASH_LENGTH(hash_alg);
    pf_psa_status_t status;
    uint8_t offset, length;

    switch (tls12_prf->state) {
        case PF_PSA_TLS12_PRF_STATE_LABEL_SET:
            tls12_prf->state = PF_PSA_TLS12_PRF_STATE_OUTPUT;
            break;
        case PF_PSA_TLS12_PRF_STATE_OUTPUT:
            break;
        default:
            return PF_PSA_ERROR_BAD_STATE;
    }

    while (output_length != 0) {
        /* Check if we have fully processed the current block. */
        if (tls12_prf->left_in_block == 0) {
            status = pf_psa_key_derivation_tls12_prf_generate_next_block(tls12_prf,
                                                                      alg);
            if (status != PF_PSA_SUCCESS) {
                return status;
            }

            continue;
        }

        if (tls12_prf->left_in_block > output_length) {
            length = (uint8_t) output_length;
        } else {
            length = tls12_prf->left_in_block;
        }

        offset = hash_length - tls12_prf->left_in_block;
        memcpy(output, tls12_prf->output_block + offset, length);
        output += length;
        output_length -= length;
        tls12_prf->left_in_block -= length;
    }

    return PF_PSA_SUCCESS;
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF ||
        * MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
static pf_psa_status_t pf_psa_key_derivation_tls12_ecjpake_to_pms_read(
    pf_psa_tls12_ecjpake_to_pms_t *ecjpake,
    uint8_t *output,
    size_t output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    size_t output_size = 0;

    if (output_length != 32) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    status = pf_psa_hash_compute(PF_PSA_ALG_SHA_256, ecjpake->data,
                              PF_PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE, output, output_length,
                              &output_size);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    if (output_size != output_length) {
        return PF_PSA_ERROR_GENERIC_ERROR;
    }

    return PF_PSA_SUCCESS;
}
#endif

#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
static pf_psa_status_t pf_psa_key_derivation_pbkdf2_generate_block(
    pf_psa_pbkdf2_key_derivation_t *pbkdf2,
    pf_psa_algorithm_t prf_alg,
    uint8_t prf_output_length,
    pf_psa_key_attributes_t *attributes)
{
    pf_psa_status_t status;
    pf_psa_mac_operation_t mac_operation;
    /* Make sure the whole the operation is zeroed.
     * PSA_MAC_OPERATION_INIT does not necessarily do it fully,
     * since one field is a union and initializing a union does not
     * necessarily initialize all of its members.
     * psa_mac_setup() would do it, but here we bypass it and call
     * lower-level functions directly. */
    memset(&mac_operation, 0, sizeof(mac_operation));
    size_t mac_output_length;
    uint8_t U_i[PF_PSA_MAC_MAX_SIZE];
    uint8_t *U_accumulator = pbkdf2->output_block;
    uint64_t i;
    uint8_t block_counter[4];

    mac_operation.is_sign = 1;
    mac_operation.mac_size = prf_output_length;
    PF_MBEDTLS_PUT_UINT32_BE(pbkdf2->block_number, block_counter, 0);

    status = pf_psa_driver_wrapper_mac_sign_setup(&mac_operation,
                                               attributes,
                                               pbkdf2->password,
                                               pbkdf2->password_length,
                                               prf_alg);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_mac_update(&mac_operation, pbkdf2->salt, pbkdf2->salt_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_mac_update(&mac_operation, block_counter, sizeof(block_counter));
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_mac_sign_finish(&mac_operation, U_i, sizeof(U_i),
                                 &mac_output_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }

    if (mac_output_length != prf_output_length) {
        status = PF_PSA_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

    memcpy(U_accumulator, U_i, prf_output_length);

    for (i = 1; i < pbkdf2->input_cost; i++) {
        /* We are passing prf_output_length as mac_size because the driver
         * function directly sets mac_output_length as mac_size upon success.
         * See https://github.com/Mbed-TLS/mbedtls/issues/7801 */
        status = pf_psa_driver_wrapper_mac_compute(attributes,
                                                pbkdf2->password,
                                                pbkdf2->password_length,
                                                prf_alg, U_i, prf_output_length,
                                                U_i, prf_output_length,
                                                &mac_output_length);
        if (status != PF_PSA_SUCCESS) {
            goto cleanup;
        }

        pf_mbedtls_xor(U_accumulator, U_accumulator, U_i, prf_output_length);
    }

cleanup:
    /* Zeroise buffers to clear sensitive data from memory. */
    pf_mbedtls_platform_zeroize(U_i, PF_PSA_MAC_MAX_SIZE);
    return status;
}

static pf_psa_status_t pf_psa_key_derivation_pbkdf2_read(
    pf_psa_pbkdf2_key_derivation_t *pbkdf2,
    pf_psa_algorithm_t kdf_alg,
    uint8_t *output,
    size_t output_length)
{
    pf_psa_status_t status;
    pf_psa_algorithm_t prf_alg;
    uint8_t prf_output_length;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_set_key_bits(&attributes, PF_PSA_BYTES_TO_BITS(pbkdf2->password_length));
    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_SIGN_MESSAGE);

    if (PF_PSA_ALG_IS_PBKDF2_HMAC(kdf_alg)) {
        prf_alg = PF_PSA_ALG_HMAC(PF_PSA_ALG_PBKDF2_HMAC_GET_HASH(kdf_alg));
        prf_output_length = PF_PSA_HASH_LENGTH(prf_alg);
        pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_HMAC);
    } else if (kdf_alg == PF_PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
        prf_alg = PF_PSA_ALG_CMAC;
        prf_output_length = PF_PSA_MAC_LENGTH(PF_PSA_KEY_TYPE_AES, 128U, PF_PSA_ALG_CMAC);
        pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_AES);
    } else {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (pbkdf2->state) {
        case PF_PSA_PBKDF2_STATE_PASSWORD_SET:
            /* Initially we need a new block so bytes_used is equal to block size*/
            pbkdf2->bytes_used = prf_output_length;
            pbkdf2->state = PF_PSA_PBKDF2_STATE_OUTPUT;
            break;
        case PF_PSA_PBKDF2_STATE_OUTPUT:
            break;
        default:
            return PF_PSA_ERROR_BAD_STATE;
    }

    while (output_length != 0) {
        uint8_t n = prf_output_length - pbkdf2->bytes_used;
        if (n > output_length) {
            n = (uint8_t) output_length;
        }
        memcpy(output, pbkdf2->output_block + pbkdf2->bytes_used, n);
        output += n;
        output_length -= n;
        pbkdf2->bytes_used += n;

        if (output_length == 0) {
            break;
        }

        /* We need a new block */
        pbkdf2->bytes_used = 0;
        pbkdf2->block_number++;

        status = pf_psa_key_derivation_pbkdf2_generate_block(pbkdf2, prf_alg,
                                                          prf_output_length,
                                                          &attributes);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
    }

    return PF_PSA_SUCCESS;
}
#endif /* PSA_HAVE_SOFT_PBKDF2 */

pf_psa_status_t pf_psa_key_derivation_output_bytes(
    pf_psa_key_derivation_operation_t *operation,
    uint8_t *output_external,
    size_t output_length)
{
    pf_psa_status_t status;
    LOCAL_OUTPUT_DECLARE(output_external, output);

    pf_psa_algorithm_t kdf_alg = pf_psa_key_derivation_get_kdf_alg(operation);

    if (operation->alg == 0) {
        /* This is a blank operation. */
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (output_length == 0 && operation->capacity == 0) {
        /* Edge case: this is a finished operation, and 0 bytes
         * were requested. The right error in this case could
         * be either INSUFFICIENT_CAPACITY or BAD_STATE. Return
         * INSUFFICIENT_CAPACITY, which is right for a finished
         * operation, for consistency with the case when
         * output_length > 0. */
        return PF_PSA_ERROR_INSUFFICIENT_DATA;
    }

    LOCAL_OUTPUT_ALLOC(output_external, output_length, output);
    if (output_length > operation->capacity) {
        operation->capacity = 0;
        /* Go through the error path to wipe all confidential data now
         * that the operation object is useless. */
        status = PF_PSA_ERROR_INSUFFICIENT_DATA;
        goto exit;
    }

    operation->capacity -= output_length;

#if defined(BUILTIN_ALG_ANY_HKDF)
    if (PF_PSA_ALG_IS_ANY_HKDF(kdf_alg)) {
        status = pf_psa_key_derivation_hkdf_read(&operation->ctx.hkdf, kdf_alg,
                                              output, output_length);
    } else
#endif /* BUILTIN_ALG_ANY_HKDF */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if (PF_PSA_ALG_IS_TLS12_PRF(kdf_alg) ||
        PF_PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg)) {
        status = pf_psa_key_derivation_tls12_prf_read(&operation->ctx.tls12_prf,
                                                   kdf_alg, output,
                                                   output_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF ||
        * MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if (kdf_alg == PF_PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        status = pf_psa_key_derivation_tls12_ecjpake_to_pms_read(
            &operation->ctx.tls12_ecjpake_to_pms, output, output_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS */
#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
    if (PF_PSA_ALG_IS_PBKDF2(kdf_alg)) {
        status = pf_psa_key_derivation_pbkdf2_read(&operation->ctx.pbkdf2, kdf_alg,
                                                output, output_length);
    } else
#endif /* PSA_HAVE_SOFT_PBKDF2 */

    {
        (void) kdf_alg;
        status = PF_PSA_ERROR_BAD_STATE;
        LOCAL_OUTPUT_FREE(output_external, output);

        return status;
    }

exit:
    if (status != PF_PSA_SUCCESS) {
        /* Preserve the algorithm upon errors, but clear all sensitive state.
         * This allows us to differentiate between exhausted operations and
         * blank operations, so we can return PSA_ERROR_BAD_STATE on blank
         * operations. */
        pf_psa_algorithm_t alg = operation->alg;
        pf_psa_key_derivation_abort(operation);
        operation->alg = alg;
        if (output != NULL) {
            memset(output, '!', output_length);
        }
    }

    LOCAL_OUTPUT_FREE(output_external, output);
    return status;
}

#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
static void pf_psa_des_set_key_parity(uint8_t *data, size_t data_size)
{
    if (data_size >= 8) {
        pf_mbedtls_des_key_set_parity(data);
    }
    if (data_size >= 16) {
        pf_mbedtls_des_key_set_parity(data + 8);
    }
    if (data_size >= 24) {
        pf_mbedtls_des_key_set_parity(data + 16);
    }
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES */

/*
 * ECC keys on a Weierstrass elliptic curve require the generation
 * of a private key which is an integer
 * in the range [1, N - 1], where N is the boundary of the private key domain:
 * N is the prime p for Diffie-Hellman, or the order of the
 * curve’s base point for ECC.
 *
 * Let m be the bit size of N, such that 2^m > N >= 2^(m-1).
 * This function generates the private key using the following process:
 *
 * 1. Draw a byte string of length ceiling(m/8) bytes.
 * 2. If m is not a multiple of 8, set the most significant
 *    (8 * ceiling(m/8) - m) bits of the first byte in the string to zero.
 * 3. Convert the string to integer k by decoding it as a big-endian byte string.
 * 4. If k > N - 2, discard the result and return to step 1.
 * 5. Output k + 1 as the private key.
 *
 * This method allows compliance to NIST standards, specifically the methods titled
 * Key-Pair Generation by Testing Candidates in the following publications:
 * - NIST Special Publication 800-56A: Recommendation for Pair-Wise Key-Establishment
 *   Schemes Using Discrete Logarithm Cryptography [SP800-56A] §5.6.1.1.4 for
 *   Diffie-Hellman keys.
 *
 * - [SP800-56A] §5.6.1.2.2 or FIPS Publication 186-4: Digital Signature
 *   Standard (DSS) [FIPS186-4] §B.4.2 for elliptic curve keys.
 *
 * Note: Function allocates memory for *data buffer, so given *data should be
 *       always NULL.
 */
#if defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
static pf_psa_status_t pf_psa_generate_derived_ecc_key_weierstrass_helper(
    pf_psa_key_slot_t *slot,
    size_t bits,
    pf_psa_key_derivation_operation_t *operation,
    uint8_t **data
    )
{
    unsigned key_out_of_range = 1;
    pf_mbedtls_mpi k;
    pf_mbedtls_mpi diff_N_2;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    size_t m;
    size_t m_bytes = 0;

    pf_mbedtls_mpi_init(&k);
    pf_mbedtls_mpi_init(&diff_N_2);

    pf_psa_ecc_family_t curve = PF_PSA_KEY_TYPE_ECC_GET_FAMILY(
        slot->attr.type);
    pf_mbedtls_ecp_group_id grp_id =
        pf_mbedtls_ecc_group_from_psa(curve, bits);

    if (grp_id == PF_MBEDTLS_ECP_DP_NONE) {
        ret = PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
        goto cleanup;
    }

    pf_mbedtls_ecp_group ecp_group;
    pf_mbedtls_ecp_group_init(&ecp_group);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_group_load(&ecp_group, grp_id));

    /* N is the boundary of the private key domain (ecp_group.N). */
    /* Let m be the bit size of N. */
    m = ecp_group.nbits;

    m_bytes = PF_PSA_BITS_TO_BYTES(m);

    /* Calculate N - 2 - it will be needed later. */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_int(&diff_N_2, &ecp_group.N, 2));

    /* Note: This function is always called with *data == NULL and it
     * allocates memory for the data buffer. */
    *data = pf_mbedtls_calloc(1, m_bytes);
    if (*data == NULL) {
        ret = PF_MBEDTLS_ERR_ASN1_ALLOC_FAILED;
        goto cleanup;
    }

    while (key_out_of_range) {
        /* 1. Draw a byte string of length ceiling(m/8) bytes. */
        if ((status = pf_psa_key_derivation_output_bytes(operation, *data, m_bytes)) != 0) {
            goto cleanup;
        }

        /* 2. If m is not a multiple of 8 */
        if (m % 8 != 0) {
            /* Set the most significant
             * (8 * ceiling(m/8) - m) bits of the first byte in
             * the string to zero.
             */
            uint8_t clear_bit_mask = (1 << (m % 8)) - 1;
            (*data)[0] &= clear_bit_mask;
        }

        /* 3. Convert the string to integer k by decoding it as a
         *    big-endian byte string.
         */
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary(&k, *data, m_bytes));

        /* 4. If k > N - 2, discard the result and return to step 1.
         *    Result of comparison is returned. When it indicates error
         *    then this function is called again.
         */
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lt_mpi_ct(&diff_N_2, &k, &key_out_of_range));
    }

    /* 5. Output k + 1 as the private key. */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_int(&k, &k, 1));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_binary(&k, *data, m_bytes));
cleanup:
    if (ret != 0) {
        status = pf_mbedtls_to_psa_error(ret);
    }
    if (status != PF_PSA_SUCCESS) {
        pf_mbedtls_zeroize_and_free(*data, m_bytes);
        *data = NULL;
    }
    pf_mbedtls_mpi_free(&k);
    pf_mbedtls_mpi_free(&diff_N_2);
    return status;
}

/* ECC keys on a Montgomery elliptic curve draws a byte string whose length
 * is determined by the curve, and sets the mandatory bits accordingly. That is:
 *
 * - Curve25519 (PSA_ECC_FAMILY_MONTGOMERY, 255 bits):
 *   draw a 32-byte string and process it as specified in
 *   Elliptic Curves for Security [RFC7748] §5.
 *
 * - Curve448 (PSA_ECC_FAMILY_MONTGOMERY, 448 bits):
 *   draw a 56-byte string and process it as specified in [RFC7748] §5.
 *
 * Note: Function allocates memory for *data buffer, so given *data should be
 *       always NULL.
 */

static pf_psa_status_t pf_psa_generate_derived_ecc_key_montgomery_helper(
    size_t bits,
    pf_psa_key_derivation_operation_t *operation,
    uint8_t **data
    )
{
    size_t output_length;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    switch (bits) {
        case 255:
            output_length = 32;
            break;
        case 448:
            output_length = 56;
            break;
        default:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
            break;
    }

    *data = pf_mbedtls_calloc(1, output_length);

    if (*data == NULL) {
        return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = pf_psa_key_derivation_output_bytes(operation, *data, output_length);

    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    switch (bits) {
        case 255:
            (*data)[0] &= 248;
            (*data)[31] &= 127;
            (*data)[31] |= 64;
            break;
        case 448:
            (*data)[0] &= 252;
            (*data)[55] |= 128;
            break;
        default:
            return PF_PSA_ERROR_CORRUPTION_DETECTED;
            break;
    }

    return status;
}
#else /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE */
static pf_psa_status_t pf_psa_generate_derived_ecc_key_weierstrass_helper(
    pf_psa_key_slot_t *slot, size_t bits,
    pf_psa_key_derivation_operation_t *operation, uint8_t **data)
{
    (void) slot;
    (void) bits;
    (void) operation;
    (void) data;
    return PF_PSA_ERROR_NOT_SUPPORTED;
}

static pf_psa_status_t pf_psa_generate_derived_ecc_key_montgomery_helper(
    size_t bits, pf_psa_key_derivation_operation_t *operation, uint8_t **data)
{
    (void) bits;
    (void) operation;
    (void) data;
    return PF_PSA_ERROR_NOT_SUPPORTED;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE */
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE */

static pf_psa_status_t pf_psa_generate_derived_key_internal(
    pf_psa_key_slot_t *slot,
    size_t bits,
    pf_psa_key_derivation_operation_t *operation)
{
    uint8_t *data = NULL;
    size_t bytes = PF_PSA_BITS_TO_BYTES(bits);
    size_t storage_size = bytes;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (PF_PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attr.type)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
    if (PF_PSA_KEY_TYPE_IS_ECC(slot->attr.type)) {
        pf_psa_ecc_family_t curve = PF_PSA_KEY_TYPE_ECC_GET_FAMILY(slot->attr.type);
        if (PF_PSA_ECC_FAMILY_IS_WEIERSTRASS(curve)) {
            /* Weierstrass elliptic curve */
            status = pf_psa_generate_derived_ecc_key_weierstrass_helper(slot, bits, operation, &data);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
        } else {
            /* Montgomery elliptic curve */
            status = pf_psa_generate_derived_ecc_key_montgomery_helper(bits, operation, &data);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
        }
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE) ||
          defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE) */
    if (key_type_is_raw_bytes(slot->attr.type)) {
        if (bits % 8 != 0) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
        data = pf_mbedtls_calloc(1, bytes);
        if (data == NULL) {
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        status = pf_psa_key_derivation_output_bytes(operation, data, bytes);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
        if (slot->attr.type == PF_PSA_KEY_TYPE_DES) {
            pf_psa_des_set_key_parity(data, bytes);
        }
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES) */
    } else {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    slot->attr.bits = (pf_psa_key_bits_t) bits;

    if (pf_psa_key_lifetime_is_external(slot->attr.lifetime)) {
        status = pf_psa_driver_wrapper_get_key_buffer_size(&slot->attr,
                                                        &storage_size);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }
    status = pf_psa_allocate_buffer_to_slot(slot, storage_size);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_driver_wrapper_import_key(&slot->attr,
                                           data, bytes,
                                           slot->key.data,
                                           slot->key.bytes,
                                           &slot->key.bytes, &bits);
    if (bits != slot->attr.bits) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
    }

exit:
    pf_mbedtls_zeroize_and_free(data, bytes);
    return status;
}

static const pf_psa_custom_key_parameters_t default_custom_production =
    PF_PSA_CUSTOM_KEY_PARAMETERS_INIT;

int pf_psa_custom_key_parameters_are_default(
    const pf_psa_custom_key_parameters_t *custom,
    size_t custom_data_length)
{
    if (custom->flags != 0) {
        return 0;
    }
    if (custom_data_length != 0) {
        return 0;
    }
    return 1;
}

pf_psa_status_t pf_psa_key_derivation_output_key_custom(
    const pf_psa_key_attributes_t *attributes,
    pf_psa_key_derivation_operation_t *operation,
    const pf_psa_custom_key_parameters_t *custom,
    const uint8_t *custom_data,
    size_t custom_data_length,
    pf_mbedtls_svc_key_id_t *key)
{
    pf_psa_status_t status;
    pf_psa_key_slot_t *slot = NULL;
    pf_psa_se_drv_table_entry_t *driver = NULL;

    *key = PF_MBEDTLS_SVC_KEY_ID_INIT;

    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if (pf_psa_get_key_bits(attributes) == 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    (void) custom_data;         /* We only accept 0-length data */
    if (!pf_psa_custom_key_parameters_are_default(custom, custom_data_length)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (operation->alg == PF_PSA_ALG_NONE) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (!operation->can_output_key) {
        return PF_PSA_ERROR_NOT_PERMITTED;
    }

    status = pf_psa_start_key_creation(PF_PSA_KEY_CREATION_DERIVE, attributes,
                                    &slot, &driver);
#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    if (driver != NULL) {
        /* Deriving a key in a secure element is not implemented yet. */
        status = PF_PSA_ERROR_NOT_SUPPORTED;
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    if (status == PF_PSA_SUCCESS) {
        status = pf_psa_generate_derived_key_internal(slot,
                                                   attributes->bits,
                                                   operation);
    }
    if (status == PF_PSA_SUCCESS) {
        status = pf_psa_finish_key_creation(slot, driver, key);
    }
    if (status != PF_PSA_SUCCESS) {
        pf_psa_fail_key_creation(slot, driver);
    }

    return status;
}

pf_psa_status_t pf_psa_key_derivation_output_key_ext(
    const pf_psa_key_attributes_t *attributes,
    pf_psa_key_derivation_operation_t *operation,
    const pf_psa_key_production_parameters_t *params,
    size_t params_data_length,
    pf_mbedtls_svc_key_id_t *key)
{
    return pf_psa_key_derivation_output_key_custom(
        attributes, operation,
        (const pf_psa_custom_key_parameters_t *) params,
        params->data, params_data_length,
        key);
}

pf_psa_status_t pf_psa_key_derivation_output_key(
    const pf_psa_key_attributes_t *attributes,
    pf_psa_key_derivation_operation_t *operation,
    pf_mbedtls_svc_key_id_t *key)
{
    return pf_psa_key_derivation_output_key_custom(attributes, operation,
                                                &default_custom_production,
                                                NULL, 0,
                                                key);
}


/****************************************************************/
/* Key derivation: operation management */
/****************************************************************/

#if defined(AT_LEAST_ONE_BUILTIN_KDF)
static int is_kdf_alg_supported(pf_psa_algorithm_t kdf_alg)
{
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF)
    if (PF_PSA_ALG_IS_HKDF(kdf_alg)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
    if (PF_PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
    if (PF_PSA_ALG_IS_HKDF_EXPAND(kdf_alg)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF)
    if (PF_PSA_ALG_IS_TLS12_PRF(kdf_alg)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if (PF_PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if (kdf_alg == PF_PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_HMAC)
    if (PF_PSA_ALG_IS_PBKDF2_HMAC(kdf_alg)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_AES_CMAC_PRF_128)
    if (kdf_alg == PF_PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
        return 1;
    }
#endif
    return 0;
}

static pf_psa_status_t pf_psa_hash_try_support(pf_psa_algorithm_t alg)
{
    pf_psa_hash_operation_t operation = PF_PSA_HASH_OPERATION_INIT;
    pf_psa_status_t status = pf_psa_hash_setup(&operation, alg);
    pf_psa_hash_abort(&operation);
    return status;
}

static pf_psa_status_t pf_psa_key_derivation_set_maximum_capacity(
    pf_psa_key_derivation_operation_t *operation,
    pf_psa_algorithm_t kdf_alg)
{
#if defined(PF_PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS)
    if (kdf_alg == PF_PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        operation->capacity = PF_PSA_HASH_LENGTH(PF_PSA_ALG_SHA_256);
        return PF_PSA_SUCCESS;
    }
#endif
#if defined(PF_PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
    if (kdf_alg == PF_PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
#if (SIZE_MAX > UINT32_MAX)
        operation->capacity = UINT32_MAX * (size_t) PF_PSA_MAC_LENGTH(
            PF_PSA_KEY_TYPE_AES,
            128U,
            PF_PSA_ALG_CMAC);
#else
        operation->capacity = SIZE_MAX;
#endif
        return PF_PSA_SUCCESS;
    }
#endif /* PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128 */

    /* After this point, if kdf_alg is not valid then value of hash_alg may be
     * invalid or meaningless but it does not affect this function */
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_GET_HASH(kdf_alg);
    size_t hash_size = PF_PSA_HASH_LENGTH(hash_alg);
    if (hash_size == 0) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    /* Make sure that hash_alg is a supported hash algorithm. Otherwise
     * we might fail later, which is somewhat unfriendly and potentially
     * risk-prone. */
    pf_psa_status_t status = pf_psa_hash_try_support(hash_alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

#if defined(PF_PSA_WANT_ALG_HKDF)
    if (PF_PSA_ALG_IS_HKDF(kdf_alg)) {
        operation->capacity = 255 * hash_size;
    } else
#endif
#if defined(PF_PSA_WANT_ALG_HKDF_EXTRACT)
    if (PF_PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)) {
        operation->capacity = hash_size;
    } else
#endif
#if defined(PF_PSA_WANT_ALG_HKDF_EXPAND)
    if (PF_PSA_ALG_IS_HKDF_EXPAND(kdf_alg)) {
        operation->capacity = 255 * hash_size;
    } else
#endif
#if defined(PF_PSA_WANT_ALG_TLS12_PRF)
    if (PF_PSA_ALG_IS_TLS12_PRF(kdf_alg) &&
        (hash_alg == PF_PSA_ALG_SHA_256 || hash_alg == PF_PSA_ALG_SHA_384)) {
        operation->capacity = SIZE_MAX;
    } else
#endif
#if defined(PF_PSA_WANT_ALG_TLS12_PSK_TO_MS)
    if (PF_PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg) &&
        (hash_alg == PF_PSA_ALG_SHA_256 || hash_alg == PF_PSA_ALG_SHA_384)) {
        /* Master Secret is always 48 bytes
         * https://datatracker.ietf.org/doc/html/rfc5246.html#section-8.1 */
        operation->capacity = 48U;
    } else
#endif
#if defined(PF_PSA_WANT_ALG_PBKDF2_HMAC)
    if (PF_PSA_ALG_IS_PBKDF2_HMAC(kdf_alg)) {
#if (SIZE_MAX > UINT32_MAX)
        operation->capacity = UINT32_MAX * hash_size;
#else
        operation->capacity = SIZE_MAX;
#endif
    } else
#endif /* PSA_WANT_ALG_PBKDF2_HMAC */
    {
        (void) hash_size;
        status = PF_PSA_ERROR_NOT_SUPPORTED;
    }
    return status;
}

static pf_psa_status_t pf_psa_key_derivation_setup_kdf(
    pf_psa_key_derivation_operation_t *operation,
    pf_psa_algorithm_t kdf_alg)
{
    /* Make sure that operation->ctx is properly zero-initialised. (Macro
     * initialisers for this union leave some bytes unspecified.) */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    /* Make sure that kdf_alg is a supported key derivation algorithm. */
    if (!is_kdf_alg_supported(kdf_alg)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    pf_psa_status_t status = pf_psa_key_derivation_set_maximum_capacity(operation,
                                                                  kdf_alg);
    return status;
}

static pf_psa_status_t pf_psa_key_agreement_try_support(pf_psa_algorithm_t alg)
{
#if defined(PF_PSA_WANT_ALG_ECDH)
    if (alg == PF_PSA_ALG_ECDH) {
        return PF_PSA_SUCCESS;
    }
#endif
#if defined(PF_PSA_WANT_ALG_FFDH)
    if (alg == PF_PSA_ALG_FFDH) {
        return PF_PSA_SUCCESS;
    }
#endif
    (void) alg;
    return PF_PSA_ERROR_NOT_SUPPORTED;
}

static int pf_psa_key_derivation_allows_free_form_secret_input(
    pf_psa_algorithm_t kdf_alg)
{
#if defined(PF_PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS)
    if (kdf_alg == PF_PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        return 0;
    }
#endif
    (void) kdf_alg;
    return 1;
}
#endif /* AT_LEAST_ONE_BUILTIN_KDF */

pf_psa_status_t pf_psa_key_derivation_setup(pf_psa_key_derivation_operation_t *operation,
                                      pf_psa_algorithm_t alg)
{
#if defined(AT_LEAST_ONE_BUILTIN_KDF)
    pf_psa_status_t status;
#endif

    if (operation->alg != 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (PF_PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    } else if (PF_PSA_ALG_IS_KEY_AGREEMENT(alg)) {
#if defined(AT_LEAST_ONE_BUILTIN_KDF)
        pf_psa_algorithm_t kdf_alg = PF_PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
        pf_psa_algorithm_t ka_alg = PF_PSA_ALG_KEY_AGREEMENT_GET_BASE(alg);
        status = pf_psa_key_agreement_try_support(ka_alg);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
        if (!pf_psa_key_derivation_allows_free_form_secret_input(kdf_alg)) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
        status = pf_psa_key_derivation_setup_kdf(operation, kdf_alg);
#else
        return PF_PSA_ERROR_NOT_SUPPORTED;
#endif /* AT_LEAST_ONE_BUILTIN_KDF */
    } else if (PF_PSA_ALG_IS_KEY_DERIVATION(alg)) {
#if defined(AT_LEAST_ONE_BUILTIN_KDF)
        status = pf_psa_key_derivation_setup_kdf(operation, alg);
#else
        return PF_PSA_ERROR_NOT_SUPPORTED;
#endif /* AT_LEAST_ONE_BUILTIN_KDF */
    } else {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(AT_LEAST_ONE_BUILTIN_KDF)
    if (status == PF_PSA_SUCCESS) {
        operation->alg = alg;
    }
    return status;
#endif /* AT_LEAST_ONE_BUILTIN_KDF */
}

#if defined(BUILTIN_ALG_ANY_HKDF)
static pf_psa_status_t pf_psa_hkdf_input(pf_psa_hkdf_key_derivation_t *hkdf,
                                   pf_psa_algorithm_t kdf_alg,
                                   pf_psa_key_derivation_step_t step,
                                   const uint8_t *data,
                                   size_t data_length)
{
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_HKDF_GET_HASH(kdf_alg);
    pf_psa_status_t status;
    switch (step) {
        case PF_PSA_KEY_DERIVATION_INPUT_SALT:
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
            if (PF_PSA_ALG_IS_HKDF_EXPAND(kdf_alg)) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND */
            if (hkdf->state != HKDF_STATE_INIT) {
                return PF_PSA_ERROR_BAD_STATE;
            } else {
                status = pf_psa_key_derivation_start_hmac(&hkdf->hmac,
                                                       hash_alg,
                                                       data, data_length);
                if (status != PF_PSA_SUCCESS) {
                    return status;
                }
                hkdf->state = HKDF_STATE_STARTED;
                return PF_PSA_SUCCESS;
            }
        case PF_PSA_KEY_DERIVATION_INPUT_SECRET:
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
            if (PF_PSA_ALG_IS_HKDF_EXPAND(kdf_alg)) {
                /* We shouldn't be in different state as HKDF_EXPAND only allows
                 * two inputs: SECRET (this case) and INFO which does not modify
                 * the state. It could happen only if the hkdf
                 * object was corrupted. */
                if (hkdf->state != HKDF_STATE_INIT) {
                    return PF_PSA_ERROR_BAD_STATE;
                }

                /* Allow only input that fits expected prk size */
                if (data_length != PF_PSA_HASH_LENGTH(hash_alg)) {
                    return PF_PSA_ERROR_INVALID_ARGUMENT;
                }

                memcpy(hkdf->prk, data, data_length);
            } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND */
            {
                /* HKDF: If no salt was provided, use an empty salt.
                 * HKDF-EXTRACT: salt is mandatory. */
                if (hkdf->state == HKDF_STATE_INIT) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
                    if (PF_PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)) {
                        return PF_PSA_ERROR_BAD_STATE;
                    }
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT */
                    status = pf_psa_key_derivation_start_hmac(&hkdf->hmac,
                                                           hash_alg,
                                                           NULL, 0);
                    if (status != PF_PSA_SUCCESS) {
                        return status;
                    }
                    hkdf->state = HKDF_STATE_STARTED;
                }
                if (hkdf->state != HKDF_STATE_STARTED) {
                    return PF_PSA_ERROR_BAD_STATE;
                }
                status = pf_psa_mac_update(&hkdf->hmac,
                                        data, data_length);
                if (status != PF_PSA_SUCCESS) {
                    return status;
                }
                status = pf_psa_mac_sign_finish(&hkdf->hmac,
                                             hkdf->prk,
                                             sizeof(hkdf->prk),
                                             &data_length);
                if (status != PF_PSA_SUCCESS) {
                    return status;
                }
            }

            hkdf->state = HKDF_STATE_KEYED;
            hkdf->block_number = 0;
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
            if (PF_PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)) {
                /* The only block of output is the PRK. */
                memcpy(hkdf->output_block, hkdf->prk, PF_PSA_HASH_LENGTH(hash_alg));
                hkdf->offset_in_block = 0;
            } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT */
            {
                /* Block 0 is empty, and the next block will be
                 * generated by psa_key_derivation_hkdf_read(). */
                hkdf->offset_in_block = PF_PSA_HASH_LENGTH(hash_alg);
            }

            return PF_PSA_SUCCESS;
        case PF_PSA_KEY_DERIVATION_INPUT_INFO:
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
            if (PF_PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)) {
                return PF_PSA_ERROR_INVALID_ARGUMENT;
            }
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
            if (PF_PSA_ALG_IS_HKDF_EXPAND(kdf_alg) &&
                hkdf->state == HKDF_STATE_INIT) {
                return PF_PSA_ERROR_BAD_STATE;
            }
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT */
            if (hkdf->state == HKDF_STATE_OUTPUT) {
                return PF_PSA_ERROR_BAD_STATE;
            }
            if (hkdf->info_set) {
                return PF_PSA_ERROR_BAD_STATE;
            }
            hkdf->info_length = data_length;
            if (data_length != 0) {
                hkdf->info = pf_mbedtls_calloc(1, data_length);
                if (hkdf->info == NULL) {
                    return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
                }
                memcpy(hkdf->info, data, data_length);
            }
            hkdf->info_set = 1;
            return PF_PSA_SUCCESS;
        default:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
}
#endif /* BUILTIN_ALG_ANY_HKDF */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
static pf_psa_status_t pf_psa_tls12_prf_set_seed(pf_psa_tls12_prf_key_derivation_t *prf,
                                           const uint8_t *data,
                                           size_t data_length)
{
    if (prf->state != PF_PSA_TLS12_PRF_STATE_INIT) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (data_length != 0) {
        prf->seed = pf_mbedtls_calloc(1, data_length);
        if (prf->seed == NULL) {
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        memcpy(prf->seed, data, data_length);
        prf->seed_length = data_length;
    }

    prf->state = PF_PSA_TLS12_PRF_STATE_SEED_SET;

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_tls12_prf_set_key(pf_psa_tls12_prf_key_derivation_t *prf,
                                          const uint8_t *data,
                                          size_t data_length)
{
    if (prf->state != PF_PSA_TLS12_PRF_STATE_SEED_SET &&
        prf->state != PF_PSA_TLS12_PRF_STATE_OTHER_KEY_SET) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (data_length != 0) {
        prf->secret = pf_mbedtls_calloc(1, data_length);
        if (prf->secret == NULL) {
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        memcpy(prf->secret, data, data_length);
        prf->secret_length = data_length;
    }

    prf->state = PF_PSA_TLS12_PRF_STATE_KEY_SET;

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_tls12_prf_set_label(pf_psa_tls12_prf_key_derivation_t *prf,
                                            const uint8_t *data,
                                            size_t data_length)
{
    if (prf->state != PF_PSA_TLS12_PRF_STATE_KEY_SET) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (data_length != 0) {
        prf->label = pf_mbedtls_calloc(1, data_length);
        if (prf->label == NULL) {
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        memcpy(prf->label, data, data_length);
        prf->label_length = data_length;
    }

    prf->state = PF_PSA_TLS12_PRF_STATE_LABEL_SET;

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_tls12_prf_input(pf_psa_tls12_prf_key_derivation_t *prf,
                                        pf_psa_key_derivation_step_t step,
                                        const uint8_t *data,
                                        size_t data_length)
{
    switch (step) {
        case PF_PSA_KEY_DERIVATION_INPUT_SEED:
            return pf_psa_tls12_prf_set_seed(prf, data, data_length);
        case PF_PSA_KEY_DERIVATION_INPUT_SECRET:
            return pf_psa_tls12_prf_set_key(prf, data, data_length);
        case PF_PSA_KEY_DERIVATION_INPUT_LABEL:
            return pf_psa_tls12_prf_set_label(prf, data, data_length);
        default:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) ||
        * MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
static pf_psa_status_t pf_psa_tls12_prf_psk_to_ms_set_key(
    pf_psa_tls12_prf_key_derivation_t *prf,
    const uint8_t *data,
    size_t data_length)
{
    pf_psa_status_t status;
    const size_t pms_len = (prf->state == PF_PSA_TLS12_PRF_STATE_OTHER_KEY_SET ?
                            4 + data_length + prf->other_secret_length :
                            4 + 2 * data_length);

    if (data_length > PF_PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t *pms = pf_mbedtls_calloc(1, pms_len);
    if (pms == NULL) {
        return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    uint8_t *cur = pms;

    /* pure-PSK:
     * Quoting RFC 4279, Section 2:
     *
     * The premaster secret is formed as follows: if the PSK is N octets
     * long, concatenate a uint16 with the value N, N zero octets, a second
     * uint16 with the value N, and the PSK itself.
     *
     * mixed-PSK:
     * In a DHE-PSK, RSA-PSK, ECDHE-PSK the premaster secret is formed as
     * follows: concatenate a uint16 with the length of the other secret,
     * the other secret itself, uint16 with the length of PSK, and the
     * PSK itself.
     * For details please check:
     * - RFC 4279, Section 4 for the definition of RSA-PSK,
     * - RFC 4279, Section 3 for the definition of DHE-PSK,
     * - RFC 5489 for the definition of ECDHE-PSK.
     */

    if (prf->state == PF_PSA_TLS12_PRF_STATE_OTHER_KEY_SET) {
        *cur++ = PF_MBEDTLS_BYTE_1(prf->other_secret_length);
        *cur++ = PF_MBEDTLS_BYTE_0(prf->other_secret_length);
        if (prf->other_secret_length != 0) {
            memcpy(cur, prf->other_secret, prf->other_secret_length);
            pf_mbedtls_platform_zeroize(prf->other_secret, prf->other_secret_length);
            cur += prf->other_secret_length;
        }
    } else {
        *cur++ = PF_MBEDTLS_BYTE_1(data_length);
        *cur++ = PF_MBEDTLS_BYTE_0(data_length);
        memset(cur, 0, data_length);
        cur += data_length;
    }

    *cur++ = PF_MBEDTLS_BYTE_1(data_length);
    *cur++ = PF_MBEDTLS_BYTE_0(data_length);
    memcpy(cur, data, data_length);
    cur += data_length;

    status = pf_psa_tls12_prf_set_key(prf, pms, (size_t) (cur - pms));

    pf_mbedtls_zeroize_and_free(pms, pms_len);
    return status;
}

static pf_psa_status_t pf_psa_tls12_prf_psk_to_ms_set_other_key(
    pf_psa_tls12_prf_key_derivation_t *prf,
    const uint8_t *data,
    size_t data_length)
{
    if (prf->state != PF_PSA_TLS12_PRF_STATE_SEED_SET) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (data_length != 0) {
        prf->other_secret = pf_mbedtls_calloc(1, data_length);
        if (prf->other_secret == NULL) {
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        memcpy(prf->other_secret, data, data_length);
        prf->other_secret_length = data_length;
    } else {
        prf->other_secret_length = 0;
    }

    prf->state = PF_PSA_TLS12_PRF_STATE_OTHER_KEY_SET;

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_tls12_prf_psk_to_ms_input(
    pf_psa_tls12_prf_key_derivation_t *prf,
    pf_psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length)
{
    switch (step) {
        case PF_PSA_KEY_DERIVATION_INPUT_SECRET:
            return pf_psa_tls12_prf_psk_to_ms_set_key(prf,
                                                   data, data_length);
            break;
        case PF_PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            return pf_psa_tls12_prf_psk_to_ms_set_other_key(prf,
                                                         data,
                                                         data_length);
            break;
        default:
            return pf_psa_tls12_prf_input(prf, step, data, data_length);
            break;

    }
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
static pf_psa_status_t pf_psa_tls12_ecjpake_to_pms_input(
    pf_psa_tls12_ecjpake_to_pms_t *ecjpake,
    pf_psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length)
{
    if (data_length != PF_PSA_TLS12_ECJPAKE_TO_PMS_INPUT_SIZE ||
        step != PF_PSA_KEY_DERIVATION_INPUT_SECRET) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check if the passed point is in an uncompressed form */
    if (data[0] != 0x04) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Only K.X has to be extracted - bytes 1 to 32 inclusive. */
    memcpy(ecjpake->data, data + 1, PF_PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE);

    return PF_PSA_SUCCESS;
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS */

#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
static pf_psa_status_t pf_psa_pbkdf2_set_input_cost(
    pf_psa_pbkdf2_key_derivation_t *pbkdf2,
    pf_psa_key_derivation_step_t step,
    uint64_t data)
{
    if (step != PF_PSA_KEY_DERIVATION_INPUT_COST) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (pbkdf2->state != PF_PSA_PBKDF2_STATE_INIT) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (data > PF_PSA_VENDOR_PBKDF2_MAX_ITERATIONS) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    if (data == 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    pbkdf2->input_cost = data;
    pbkdf2->state = PF_PSA_PBKDF2_STATE_INPUT_COST_SET;

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_pbkdf2_set_salt(pf_psa_pbkdf2_key_derivation_t *pbkdf2,
                                        const uint8_t *data,
                                        size_t data_length)
{
    if (pbkdf2->state == PF_PSA_PBKDF2_STATE_INPUT_COST_SET) {
        pbkdf2->state = PF_PSA_PBKDF2_STATE_SALT_SET;
    } else if (pbkdf2->state == PF_PSA_PBKDF2_STATE_SALT_SET) {
        /* Appending to existing salt. No state change. */
    } else {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (data_length == 0) {
        /* Appending an empty string, nothing to do. */
    } else {
        uint8_t *next_salt;

        next_salt = pf_mbedtls_calloc(1, data_length + pbkdf2->salt_length);
        if (next_salt == NULL) {
            return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        if (pbkdf2->salt_length != 0) {
            memcpy(next_salt, pbkdf2->salt, pbkdf2->salt_length);
        }
        memcpy(next_salt + pbkdf2->salt_length, data, data_length);
        pbkdf2->salt_length += data_length;
        pf_mbedtls_free(pbkdf2->salt);
        pbkdf2->salt = next_salt;
    }
    return PF_PSA_SUCCESS;
}

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_HMAC)
static pf_psa_status_t pf_psa_pbkdf2_hmac_set_password(pf_psa_algorithm_t hash_alg,
                                                 const uint8_t *input,
                                                 size_t input_len,
                                                 uint8_t *output,
                                                 size_t *output_len)
{
    pf_psa_status_t status = PF_PSA_SUCCESS;
    if (input_len > PF_PSA_HASH_BLOCK_LENGTH(hash_alg)) {
        return pf_psa_hash_compute(hash_alg, input, input_len, output,
                                PF_PSA_HMAC_MAX_HASH_BLOCK_SIZE, output_len);
    } else if (input_len > 0) {
        memcpy(output, input, input_len);
    }
    *output_len = PF_PSA_HASH_BLOCK_LENGTH(hash_alg);
    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_HMAC */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_AES_CMAC_PRF_128)
static pf_psa_status_t pf_psa_pbkdf2_cmac_set_password(const uint8_t *input,
                                                 size_t input_len,
                                                 uint8_t *output,
                                                 size_t *output_len)
{
    pf_psa_status_t status = PF_PSA_SUCCESS;
    if (input_len != PF_PSA_MAC_LENGTH(PF_PSA_KEY_TYPE_AES, 128U, PF_PSA_ALG_CMAC)) {
        pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
        uint8_t zeros[16] = { 0 };
        pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_AES);
        pf_psa_set_key_bits(&attributes, PF_PSA_BYTES_TO_BITS(sizeof(zeros)));
        pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_SIGN_MESSAGE);
        /* Passing PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, 128U, PSA_ALG_CMAC) as
         * mac_size as the driver function sets mac_output_length = mac_size
         * on success. See https://github.com/Mbed-TLS/mbedtls/issues/7801 */
        status = pf_psa_driver_wrapper_mac_compute(&attributes,
                                                zeros, sizeof(zeros),
                                                PF_PSA_ALG_CMAC, input, input_len,
                                                output,
                                                PF_PSA_MAC_LENGTH(PF_PSA_KEY_TYPE_AES,
                                                               128U,
                                                               PF_PSA_ALG_CMAC),
                                                output_len);
    } else {
        memcpy(output, input, input_len);
        *output_len = PF_PSA_MAC_LENGTH(PF_PSA_KEY_TYPE_AES, 128U, PF_PSA_ALG_CMAC);
    }
    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_AES_CMAC_PRF_128 */

static pf_psa_status_t pf_psa_pbkdf2_set_password(pf_psa_pbkdf2_key_derivation_t *pbkdf2,
                                            pf_psa_algorithm_t kdf_alg,
                                            const uint8_t *data,
                                            size_t data_length)
{
    pf_psa_status_t status = PF_PSA_SUCCESS;
    if (pbkdf2->state != PF_PSA_PBKDF2_STATE_SALT_SET) {
        return PF_PSA_ERROR_BAD_STATE;
    }

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_HMAC)
    if (PF_PSA_ALG_IS_PBKDF2_HMAC(kdf_alg)) {
        pf_psa_algorithm_t hash_alg = PF_PSA_ALG_PBKDF2_HMAC_GET_HASH(kdf_alg);
        status = pf_psa_pbkdf2_hmac_set_password(hash_alg, data, data_length,
                                              pbkdf2->password,
                                              &pbkdf2->password_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_HMAC */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_AES_CMAC_PRF_128)
    if (kdf_alg == PF_PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
        status = pf_psa_pbkdf2_cmac_set_password(data, data_length,
                                              pbkdf2->password,
                                              &pbkdf2->password_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_PBKDF2_AES_CMAC_PRF_128 */
    {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    pbkdf2->state = PF_PSA_PBKDF2_STATE_PASSWORD_SET;

    return status;
}

static pf_psa_status_t pf_psa_pbkdf2_input(pf_psa_pbkdf2_key_derivation_t *pbkdf2,
                                     pf_psa_algorithm_t kdf_alg,
                                     pf_psa_key_derivation_step_t step,
                                     const uint8_t *data,
                                     size_t data_length)
{
    switch (step) {
        case PF_PSA_KEY_DERIVATION_INPUT_SALT:
            return pf_psa_pbkdf2_set_salt(pbkdf2, data, data_length);
        case PF_PSA_KEY_DERIVATION_INPUT_PASSWORD:
            return pf_psa_pbkdf2_set_password(pbkdf2, kdf_alg, data, data_length);
        default:
            return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
}
#endif /* PSA_HAVE_SOFT_PBKDF2 */

/** Check whether the given key type is acceptable for the given
 * input step of a key derivation.
 *
 * Secret inputs must have the type #PSA_KEY_TYPE_DERIVE.
 * Non-secret inputs must have the type #PSA_KEY_TYPE_RAW_DATA.
 * Both secret and non-secret inputs can alternatively have the type
 * #PSA_KEY_TYPE_NONE, which is never the type of a key object, meaning
 * that the input was passed as a buffer rather than via a key object.
 */
static int pf_psa_key_derivation_check_input_type(
    pf_psa_key_derivation_step_t step,
    pf_psa_key_type_t key_type)
{
    switch (step) {
        case PF_PSA_KEY_DERIVATION_INPUT_SECRET:
            if (key_type == PF_PSA_KEY_TYPE_DERIVE) {
                return PF_PSA_SUCCESS;
            }
            if (key_type == PF_PSA_KEY_TYPE_NONE) {
                return PF_PSA_SUCCESS;
            }
            break;
        case PF_PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            if (key_type == PF_PSA_KEY_TYPE_DERIVE) {
                return PF_PSA_SUCCESS;
            }
            if (key_type == PF_PSA_KEY_TYPE_NONE) {
                return PF_PSA_SUCCESS;
            }
            break;
        case PF_PSA_KEY_DERIVATION_INPUT_LABEL:
        case PF_PSA_KEY_DERIVATION_INPUT_SALT:
        case PF_PSA_KEY_DERIVATION_INPUT_INFO:
        case PF_PSA_KEY_DERIVATION_INPUT_SEED:
            if (key_type == PF_PSA_KEY_TYPE_RAW_DATA) {
                return PF_PSA_SUCCESS;
            }
            if (key_type == PF_PSA_KEY_TYPE_NONE) {
                return PF_PSA_SUCCESS;
            }
            break;
        case PF_PSA_KEY_DERIVATION_INPUT_PASSWORD:
            if (key_type == PF_PSA_KEY_TYPE_PASSWORD) {
                return PF_PSA_SUCCESS;
            }
            if (key_type == PF_PSA_KEY_TYPE_DERIVE) {
                return PF_PSA_SUCCESS;
            }
            if (key_type == PF_PSA_KEY_TYPE_NONE) {
                return PF_PSA_SUCCESS;
            }
            break;
    }
    return PF_PSA_ERROR_INVALID_ARGUMENT;
}

static pf_psa_status_t pf_psa_key_derivation_input_internal(
    pf_psa_key_derivation_operation_t *operation,
    pf_psa_key_derivation_step_t step,
    pf_psa_key_type_t key_type,
    const uint8_t *data,
    size_t data_length)
{
    pf_psa_status_t status;
    pf_psa_algorithm_t kdf_alg = pf_psa_key_derivation_get_kdf_alg(operation);

    if (kdf_alg == PF_PSA_ALG_NONE) {
        /* This is a blank or aborted operation. */
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = pf_psa_key_derivation_check_input_type(step, key_type);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

#if defined(BUILTIN_ALG_ANY_HKDF)
    if (PF_PSA_ALG_IS_ANY_HKDF(kdf_alg)) {
        status = pf_psa_hkdf_input(&operation->ctx.hkdf, kdf_alg,
                                step, data, data_length);
    } else
#endif /* BUILTIN_ALG_ANY_HKDF */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF)
    if (PF_PSA_ALG_IS_TLS12_PRF(kdf_alg)) {
        status = pf_psa_tls12_prf_input(&operation->ctx.tls12_prf,
                                     step, data, data_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if (PF_PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg)) {
        status = pf_psa_tls12_prf_psk_to_ms_input(&operation->ctx.tls12_prf,
                                               step, data, data_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if (kdf_alg == PF_PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        status = pf_psa_tls12_ecjpake_to_pms_input(
            &operation->ctx.tls12_ecjpake_to_pms, step, data, data_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS */
#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
    if (PF_PSA_ALG_IS_PBKDF2(kdf_alg)) {
        status = pf_psa_pbkdf2_input(&operation->ctx.pbkdf2, kdf_alg,
                                  step, data, data_length);
    } else
#endif /* PSA_HAVE_SOFT_PBKDF2 */
    {
        /* This can't happen unless the operation object was not initialized */
        (void) data;
        (void) data_length;
        (void) kdf_alg;
        return PF_PSA_ERROR_BAD_STATE;
    }

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_key_derivation_abort(operation);
    }
    return status;
}

static pf_psa_status_t pf_psa_key_derivation_input_integer_internal(
    pf_psa_key_derivation_operation_t *operation,
    pf_psa_key_derivation_step_t step,
    uint64_t value)
{
    pf_psa_status_t status;
    pf_psa_algorithm_t kdf_alg = pf_psa_key_derivation_get_kdf_alg(operation);

    if (kdf_alg == PF_PSA_ALG_NONE) {
        /* This is a blank or aborted operation. */
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
    if (PF_PSA_ALG_IS_PBKDF2(kdf_alg)) {
        status = pf_psa_pbkdf2_set_input_cost(
            &operation->ctx.pbkdf2, step, value);
    } else
#endif /* PSA_HAVE_SOFT_PBKDF2 */
    {
        (void) step;
        (void) value;
        (void) kdf_alg;
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
    }

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_key_derivation_abort(operation);
    }
    return status;
}

pf_psa_status_t pf_psa_key_derivation_input_bytes(
    pf_psa_key_derivation_operation_t *operation,
    pf_psa_key_derivation_step_t step,
    const uint8_t *data_external,
    size_t data_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(data_external, data);

    LOCAL_INPUT_ALLOC(data_external, data_length, data);

    status = pf_psa_key_derivation_input_internal(operation, step,
                                               PF_PSA_KEY_TYPE_NONE,
                                               data, data_length);
#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_INPUT_FREE(data_external, data);
    return status;
}

pf_psa_status_t pf_psa_key_derivation_input_integer(
    pf_psa_key_derivation_operation_t *operation,
    pf_psa_key_derivation_step_t step,
    uint64_t value)
{
    return pf_psa_key_derivation_input_integer_internal(operation, step, value);
}

pf_psa_status_t pf_psa_key_derivation_input_key(
    pf_psa_key_derivation_operation_t *operation,
    pf_psa_key_derivation_step_t step,
    pf_mbedtls_svc_key_id_t key)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;

    status = pf_psa_get_and_lock_transparent_key_slot_with_policy(
        key, &slot, PF_PSA_KEY_USAGE_DERIVE, operation->alg);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_key_derivation_abort(operation);
        return status;
    }

    /* Passing a key object as a SECRET or PASSWORD input unlocks the
     * permission to output to a key object. */
    if (step == PF_PSA_KEY_DERIVATION_INPUT_SECRET ||
        step == PF_PSA_KEY_DERIVATION_INPUT_PASSWORD) {
        operation->can_output_key = 1;
    }

    status = pf_psa_key_derivation_input_internal(operation,
                                               step, slot->attr.type,
                                               slot->key.data,
                                               slot->key.bytes);

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}



/****************************************************************/
/* Key agreement */
/****************************************************************/

pf_psa_status_t pf_psa_key_agreement_raw_builtin(const pf_psa_key_attributes_t *attributes,
                                           const uint8_t *key_buffer,
                                           size_t key_buffer_size,
                                           pf_psa_algorithm_t alg,
                                           const uint8_t *peer_key,
                                           size_t peer_key_length,
                                           uint8_t *shared_secret,
                                           size_t shared_secret_size,
                                           size_t *shared_secret_length)
{
    switch (alg) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDH)
        case PF_PSA_ALG_ECDH:
            return pf_mbedtls_psa_key_agreement_ecdh(attributes, key_buffer,
                                                  key_buffer_size, alg,
                                                  peer_key, peer_key_length,
                                                  shared_secret,
                                                  shared_secret_size,
                                                  shared_secret_length);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ECDH */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_FFDH)
        case PF_PSA_ALG_FFDH:
            return pf_mbedtls_psa_ffdh_key_agreement(attributes,
                                                  peer_key,
                                                  peer_key_length,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  shared_secret,
                                                  shared_secret_size,
                                                  shared_secret_length);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_FFDH */

        default:
            (void) attributes;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) peer_key;
            (void) peer_key_length;
            (void) shared_secret;
            (void) shared_secret_size;
            (void) shared_secret_length;
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }
}

/** Internal function for raw key agreement
 *  Calls the driver wrapper which will hand off key agreement task
 *  to the driver's implementation if a driver is present.
 *  Fallback specified in the driver wrapper is built-in raw key agreement
 *  (psa_key_agreement_raw_builtin).
 */
static pf_psa_status_t pf_psa_key_agreement_raw_internal(pf_psa_algorithm_t alg,
                                                   pf_psa_key_slot_t *private_key,
                                                   const uint8_t *peer_key,
                                                   size_t peer_key_length,
                                                   uint8_t *shared_secret,
                                                   size_t shared_secret_size,
                                                   size_t *shared_secret_length)
{
    if (!PF_PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return pf_psa_driver_wrapper_key_agreement(&private_key->attr,
                                            private_key->key.data,
                                            private_key->key.bytes, alg,
                                            peer_key, peer_key_length,
                                            shared_secret,
                                            shared_secret_size,
                                            shared_secret_length);
}

/* Note that if this function fails, you must call psa_key_derivation_abort()
 * to potentially free embedded data structures and wipe confidential data.
 */
static pf_psa_status_t pf_psa_key_agreement_internal(pf_psa_key_derivation_operation_t *operation,
                                               pf_psa_key_derivation_step_t step,
                                               pf_psa_key_slot_t *private_key,
                                               const uint8_t *peer_key,
                                               size_t peer_key_length)
{
    pf_psa_status_t status;
    uint8_t shared_secret[PF_PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE] = { 0 };
    size_t shared_secret_length = 0;
    pf_psa_algorithm_t ka_alg = PF_PSA_ALG_KEY_AGREEMENT_GET_BASE(operation->alg);

    /* Step 1: run the secret agreement algorithm to generate the shared
     * secret. */
    status = pf_psa_key_agreement_raw_internal(ka_alg,
                                            private_key,
                                            peer_key, peer_key_length,
                                            shared_secret,
                                            sizeof(shared_secret),
                                            &shared_secret_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    /* Step 2: set up the key derivation to generate key material from
     * the shared secret. A shared secret is permitted wherever a key
     * of type DERIVE is permitted. */
    status = pf_psa_key_derivation_input_internal(operation, step,
                                               PF_PSA_KEY_TYPE_DERIVE,
                                               shared_secret,
                                               shared_secret_length);
exit:
    pf_mbedtls_platform_zeroize(shared_secret, shared_secret_length);
    return status;
}

pf_psa_status_t pf_psa_key_derivation_key_agreement(pf_psa_key_derivation_operation_t *operation,
                                              pf_psa_key_derivation_step_t step,
                                              pf_mbedtls_svc_key_id_t private_key,
                                              const uint8_t *peer_key_external,
                                              size_t peer_key_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot;
    LOCAL_INPUT_DECLARE(peer_key_external, peer_key);

    if (!PF_PSA_ALG_IS_KEY_AGREEMENT(operation->alg)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }
    status = pf_psa_get_and_lock_transparent_key_slot_with_policy(
        private_key, &slot, PF_PSA_KEY_USAGE_DERIVE, operation->alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    LOCAL_INPUT_ALLOC(peer_key_external, peer_key_length, peer_key);
    status = pf_psa_key_agreement_internal(operation, step,
                                        slot,
                                        peer_key, peer_key_length);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    if (status != PF_PSA_SUCCESS) {
        pf_psa_key_derivation_abort(operation);
    } else {
        /* If a private key has been added as SECRET, we allow the derived
         * key material to be used as a key in PSA Crypto. */
        if (step == PF_PSA_KEY_DERIVATION_INPUT_SECRET) {
            operation->can_output_key = 1;
        }
    }

    unlock_status = pf_psa_unregister_read_under_mutex(slot);
    LOCAL_INPUT_FREE(peer_key_external, peer_key);

    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_raw_key_agreement(pf_psa_algorithm_t alg,
                                   pf_mbedtls_svc_key_id_t private_key,
                                   const uint8_t *peer_key_external,
                                   size_t peer_key_length,
                                   uint8_t *output_external,
                                   size_t output_size,
                                   size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;
    size_t expected_length;
    LOCAL_INPUT_DECLARE(peer_key_external, peer_key);
    LOCAL_OUTPUT_DECLARE(output_external, output);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    if (!PF_PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    status = pf_psa_get_and_lock_transparent_key_slot_with_policy(
        private_key, &slot, PF_PSA_KEY_USAGE_DERIVE, alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    /* PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE() is in general an upper bound
     * for the output size. The PSA specification only guarantees that this
     * function works if output_size >= PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(...),
     * but it might be nice to allow smaller buffers if the output fits.
     * At the time of writing this comment, for both FFDH and ECDH,
     * PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE() is exact so the point is moot. */
    expected_length =
        PF_PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(slot->attr.type, slot->attr.bits);
    if (output_size < expected_length) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(peer_key_external, peer_key_length, peer_key);
    status = pf_psa_key_agreement_raw_internal(alg, slot,
                                            peer_key, peer_key_length,
                                            output, output_size,
                                            output_length);

exit:
    /* Check for successful allocation of output,
     * with an unsuccessful status. */
    if (output != NULL && status != PF_PSA_SUCCESS) {
        /* If an error happens and is not handled properly, the output
         * may be used as a key to protect sensitive data. Arrange for such
         * a key to be random, which is likely to result in decryption or
         * verification errors. This is better than filling the buffer with
         * some constant data such as zeros, which would result in the data
         * being protected with a reproducible, easily knowable key.
         */
        pf_psa_generate_random_internal(output, output_size);
        *output_length = output_size;
    }

    if (output == NULL) {
        /* output allocation failed. */
        *output_length = 0;
    }

    unlock_status = pf_psa_unregister_read_under_mutex(slot);

    LOCAL_INPUT_FREE(peer_key_external, peer_key);
    LOCAL_OUTPUT_FREE(output_external, output);
    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}


/****************************************************************/
/* Random generation */
/****************************************************************/

#if defined(PF_MBEDTLS_PSA_INJECT_ENTROPY)
#include "entropy_poll.h"
#endif

/** Initialize the PSA random generator.
 *
 *  Note: the mbedtls_threading_psa_rngdata_mutex should be held when calling
 *  this function if mutexes are enabled.
 */
static void pf_mbedtls_psa_random_init(pf_mbedtls_psa_random_context_t *rng)
{
#if defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    memset(rng, 0, sizeof(*rng));
#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
    pf_psa_random_internal_init(rng);
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
}

/** Deinitialize the PSA random generator.
 *
 *  Note: the mbedtls_threading_psa_rngdata_mutex should be held when calling
 *  this function if mutexes are enabled.
 */
static void pf_mbedtls_psa_random_free(pf_mbedtls_psa_random_context_t *rng)
{
#if defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    memset(rng, 0, sizeof(*rng));
#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
    pf_psa_random_internal_free(rng);
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
}

/** Seed the PSA random generator.
 */
static pf_psa_status_t pf_mbedtls_psa_random_seed(pf_mbedtls_psa_random_context_t *rng)
{
#if defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    /* Do nothing: the external RNG seeds itself. */
    (void) rng;
    return PF_PSA_SUCCESS;
#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
    return pf_psa_random_internal_seed(rng);
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
}

pf_psa_status_t pf_psa_random_reseed(const uint8_t *perso, size_t perso_size)
{
    GUARD_MODULE_INITIALIZED;
#if defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    (void) perso;
    (void) perso_size;
    return PF_PSA_ERROR_NOT_SUPPORTED;
#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex) != 0) {
        return PF_PSA_ERROR_SERVICE_FAILURE;
    }
#endif /* defined(MBEDTLS_THREADING_C) */
    int ret = pf_mbedtls_psa_drbg_reseed(&global_data.rng.drbg,
                                      perso, perso_size);
#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */
    return pf_mbedtls_to_psa_error(ret);
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
}

pf_psa_status_t pf_psa_random_deplete(void)
{
    GUARD_MODULE_INITIALIZED;
#if defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    return PF_PSA_ERROR_NOT_SUPPORTED;
#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex) != 0) {
        return PF_PSA_ERROR_SERVICE_FAILURE;
    }
#endif /* defined(MBEDTLS_THREADING_C) */
    pf_mbedtls_psa_drbg_deplete(&global_data.rng.drbg);
#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */
    return PF_PSA_SUCCESS;
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
}

pf_psa_status_t pf_psa_random_set_prediction_resistance(unsigned enabled)
{
    GUARD_MODULE_INITIALIZED;

#if defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    (void) enabled;
    return PF_PSA_ERROR_NOT_SUPPORTED;
#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

    if (enabled != 0 && enabled != 1) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

#if PF_MBEDTLS_ENTROPY_TRUE_SOURCES > 0
#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex) != 0) {
        return PF_PSA_ERROR_SERVICE_FAILURE;
    }
#endif /* defined(MBEDTLS_THREADING_C) */
    pf_mbedtls_psa_drbg_set_prediction_resistance(&global_data.rng.drbg, enabled);
#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */
    return PF_PSA_SUCCESS;

#else /* MBEDTLS_ENTROPY_TRUE_SOURCES > 0 */
    if (enabled) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    } else {
        return PF_PSA_SUCCESS;
    }

#endif /* MBEDTLS_ENTROPY_TRUE_SOURCES > 0 */
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
}

pf_psa_status_t pf_psa_generate_random(uint8_t *output_external,
                                 size_t output_size)
{
    pf_psa_status_t status;

    LOCAL_OUTPUT_DECLARE(output_external, output);
    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_generate_random_internal(output, output_size);

#if !defined(PF_MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
exit:
#endif
    LOCAL_OUTPUT_FREE(output_external, output);
    return status;
}

#if defined(PF_MBEDTLS_PSA_INJECT_ENTROPY)
pf_psa_status_t pf_mbedtls_psa_inject_entropy(const uint8_t *seed,
                                        size_t seed_size)
{
    if (pf_psa_get_initialized()) {
        return PF_PSA_ERROR_NOT_PERMITTED;
    }

    if (((seed_size < PF_MBEDTLS_ENTROPY_MIN_PLATFORM) ||
         (seed_size < PF_MBEDTLS_ENTROPY_BLOCK_SIZE)) ||
        (seed_size > PF_MBEDTLS_ENTROPY_MAX_SEED_SIZE)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    return pf_mbedtls_psa_storage_inject_entropy(seed, seed_size);
}
#endif /* MBEDTLS_PSA_INJECT_ENTROPY */

/** Validate the key type and size for key generation
 *
 * \param  type  The key type
 * \param  bits  The number of bits of the key
 *
 * \retval #PSA_SUCCESS
 *         The key type and size are valid.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size in bits of the key is not valid.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The type and/or the size in bits of the key or the combination of
 *         the two is not supported.
 */
static pf_psa_status_t pf_psa_validate_key_type_and_size_for_key_generation(
    pf_psa_key_type_t type, size_t bits)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (key_type_is_raw_bytes(type)) {
        status = pf_psa_validate_unstructured_key_bit_size(type, bits);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
    } else
#if defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
    if (PF_PSA_KEY_TYPE_IS_RSA(type) && PF_PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        if (bits > PF_PSA_VENDOR_RSA_MAX_KEY_BITS) {
            return PF_PSA_ERROR_NOT_SUPPORTED;
        }
        if (bits < PF_PSA_VENDOR_RSA_GENERATE_MIN_KEY_BITS) {
            return PF_PSA_ERROR_NOT_SUPPORTED;
        }

        /* Accept only byte-aligned keys, for the same reasons as
         * in psa_import_rsa_key(). */
        if (bits % 8 != 0) {
            return PF_PSA_ERROR_NOT_SUPPORTED;
        }
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE) */

#if defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
    if (PF_PSA_KEY_TYPE_IS_ECC(type) && PF_PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        /* To avoid empty block, return successfully here. */
        return PF_PSA_SUCCESS;
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE) */

#if defined(PF_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE)
    if (PF_PSA_KEY_TYPE_IS_DH(type) && PF_PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        if (pf_psa_is_dh_key_size_valid(bits) == 0) {
            return PF_PSA_ERROR_NOT_SUPPORTED;
        }
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE) */
    {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_generate_key_internal(
    const pf_psa_key_attributes_t *attributes,
    const pf_psa_custom_key_parameters_t *custom,
    const uint8_t *custom_data,
    size_t custom_data_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_type_t type = attributes->type;

    /* Only used for RSA */
    (void) custom;
    (void) custom_data;
    (void) custom_data_length;

    if (key_type_is_raw_bytes(type)) {
        status = pf_psa_generate_random_internal(key_buffer, key_buffer_size);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }

#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
        if (type == PF_PSA_KEY_TYPE_DES) {
            pf_psa_des_set_key_parity(key_buffer, key_buffer_size);
        }
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES */
    } else

#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
    if (type == PF_PSA_KEY_TYPE_RSA_KEY_PAIR) {
        return pf_mbedtls_psa_rsa_generate_key(attributes,
                                            custom_data, custom_data_length,
                                            key_buffer,
                                            key_buffer_size,
                                            key_buffer_length);
    } else
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_GENERATE) */

#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
    if (PF_PSA_KEY_TYPE_IS_ECC(type) && PF_PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        return pf_mbedtls_psa_ecp_generate_key(attributes,
                                            key_buffer,
                                            key_buffer_size,
                                            key_buffer_length);
    } else
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_GENERATE) */

#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE)
    if (PF_PSA_KEY_TYPE_IS_DH(type) && PF_PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        return pf_mbedtls_psa_ffdh_generate_key(attributes,
                                             key_buffer,
                                             key_buffer_size,
                                             key_buffer_length);
    } else
#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE) */
    {
        (void) key_buffer_length;
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_generate_key_custom(const pf_psa_key_attributes_t *attributes,
                                     const pf_psa_custom_key_parameters_t *custom,
                                     const uint8_t *custom_data,
                                     size_t custom_data_length,
                                     pf_mbedtls_svc_key_id_t *key)
{
    pf_psa_status_t status;
    pf_psa_key_slot_t *slot = NULL;
    pf_psa_se_drv_table_entry_t *driver = NULL;
    size_t key_buffer_size;

    *key = PF_MBEDTLS_SVC_KEY_ID_INIT;

    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if (pf_psa_get_key_bits(attributes) == 0) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Reject any attempt to create a public key. */
    if (PF_PSA_KEY_TYPE_IS_PUBLIC_KEY(attributes->type)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
    if (attributes->type == PF_PSA_KEY_TYPE_RSA_KEY_PAIR) {
        if (custom->flags != 0) {
            return PF_PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif
    if (!pf_psa_custom_key_parameters_are_default(custom, custom_data_length)) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    status = pf_psa_start_key_creation(PF_PSA_KEY_CREATION_GENERATE, attributes,
                                    &slot, &driver);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    /* In the case of a transparent key or an opaque key stored in local
     * storage ( thus not in the case of generating a key in a secure element
     * with storage ( MBEDTLS_PSA_CRYPTO_SE_C ) ),we have to allocate a
     * buffer to hold the generated key material. */
    if (slot->key.bytes == 0) {
        if (PF_PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime) ==
            PF_PSA_KEY_LOCATION_LOCAL_STORAGE) {
            status = pf_psa_validate_key_type_and_size_for_key_generation(
                attributes->type, attributes->bits);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }

            key_buffer_size = PF_PSA_EXPORT_KEY_OUTPUT_SIZE(
                attributes->type,
                attributes->bits);
        } else {
            status = pf_psa_driver_wrapper_get_key_buffer_size(
                attributes, &key_buffer_size);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
        }

        status = pf_psa_allocate_buffer_to_slot(slot, key_buffer_size);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }

    status = pf_psa_driver_wrapper_generate_key(attributes,
                                             custom,
                                             custom_data, custom_data_length,
                                             slot->key.data, slot->key.bytes,
                                             &slot->key.bytes);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_remove_key_data_from_memory(slot);
    }

exit:
    if (status == PF_PSA_SUCCESS) {
        status = pf_psa_finish_key_creation(slot, driver, key);
    }
    if (status != PF_PSA_SUCCESS) {
        pf_psa_fail_key_creation(slot, driver);
    }

    return status;
}

pf_psa_status_t pf_psa_generate_key_ext(const pf_psa_key_attributes_t *attributes,
                                  const pf_psa_key_production_parameters_t *params,
                                  size_t params_data_length,
                                  pf_mbedtls_svc_key_id_t *key)
{
    return pf_psa_generate_key_custom(
        attributes,
        (const pf_psa_custom_key_parameters_t *) params,
        params->data, params_data_length,
        key);
}

pf_psa_status_t pf_psa_generate_key(const pf_psa_key_attributes_t *attributes,
                              pf_mbedtls_svc_key_id_t *key)
{
    return pf_psa_generate_key_custom(attributes,
                                   &default_custom_production,
                                   NULL, 0,
                                   key);
}



/****************************************************************/
/* Module setup */
/****************************************************************/

#if !defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
pf_psa_status_t pf_mbedtls_psa_crypto_configure_entropy_sources(
    void (* entropy_init)(pf_mbedtls_entropy_context *ctx),
    void (* entropy_free)(pf_mbedtls_entropy_context *ctx))
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    if (global_data.rng_state != RNG_NOT_INITIALIZED) {
        status = PF_PSA_ERROR_BAD_STATE;
    } else {
        global_data.rng.entropy_init = entropy_init;
        global_data.rng.entropy_free = entropy_free;
        status = PF_PSA_SUCCESS;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    return status;
}
#endif /* !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

void pf_mbedtls_psa_crypto_free(void)
{

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    /* Nothing to do to free transaction. */
    if (global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED) {
        global_data.initialized &= ~PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
    }

    if (global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED) {
        pf_psa_wipe_all_key_slots();
        global_data.initialized &= ~PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    if (global_data.rng_state != RNG_NOT_INITIALIZED) {
        pf_mbedtls_psa_random_free(&global_data.rng);
    }
    global_data.rng_state = RNG_NOT_INITIALIZED;
    pf_mbedtls_platform_zeroize(&global_data.rng, sizeof(global_data.rng));

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    /* Terminate drivers */
    if (global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED) {
        pf_psa_driver_wrapper_free();
        global_data.initialized &= ~PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

}

#if defined(PF_PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
/** Recover a transaction that was interrupted by a power failure.
 *
 * This function is called during initialization, before psa_crypto_init()
 * returns. If this function returns a failure status, the initialization
 * fails.
 */
static pf_psa_status_t pf_psa_crypto_recover_transaction(
    const pf_psa_crypto_transaction_t *transaction)
{
    switch (transaction->unknown.type) {
        case PF_PSA_CRYPTO_TRANSACTION_CREATE_KEY:
        case PF_PSA_CRYPTO_TRANSACTION_DESTROY_KEY:
        /* TODO - fall through to the failure case until this
         * is implemented.
         * https://github.com/ARMmbed/mbed-crypto/issues/218
         */
        default:
            /* We found an unsupported transaction in the storage.
             * We don't know what state the storage is in. Give up. */
            return PF_PSA_ERROR_DATA_INVALID;
    }
}
#endif /* PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS */

static pf_psa_status_t pf_mbedtls_psa_crypto_init_subsystem(pf_mbedtls_psa_crypto_subsystem subsystem)
{
    pf_psa_status_t status = PF_PSA_SUCCESS;
    uint8_t driver_wrappers_initialized = 0;

    switch (subsystem) {
        case PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS:

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            if (!(global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED)) {
                /* Init drivers */
                status = pf_psa_driver_wrapper_init();

                /* Drivers need shutdown regardless of startup errors. */
                global_data.initialized |= PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED;


            }
#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_unlock(
                                            &pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            break;

        case PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS:

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            if (!(global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED)) {
                status = pf_psa_initialize_key_slots();

                /* Need to wipe keys even if initialization fails. */
                global_data.initialized |= PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED;

            }
#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_unlock(
                                            &pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            break;

        case PF_PSA_CRYPTO_SUBSYSTEM_RNG:

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            driver_wrappers_initialized =
                (global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED);

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_unlock(
                                            &pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            /* Need to use separate mutex here, as initialisation can require
             * testing of init flags, which requires locking the global data
             * mutex. */
#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            /* Initialize and seed the random generator. */
            if (global_data.rng_state == RNG_NOT_INITIALIZED && driver_wrappers_initialized) {
                pf_mbedtls_psa_random_init(&global_data.rng);
                global_data.rng_state = RNG_INITIALIZED;

                status = pf_mbedtls_psa_random_seed(&global_data.rng);
                if (status == PF_PSA_SUCCESS) {
                    global_data.rng_state = RNG_SEEDED;
                }
            }

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_unlock(
                                            &pf_mbedtls_threading_psa_rngdata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            break;

        case PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION:

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            if (!(global_data.initialized & PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED)) {
#if defined(PF_PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
                status = pf_psa_crypto_load_transaction();
                if (status == PF_PSA_SUCCESS) {
                    status = pf_psa_crypto_recover_transaction(&pf_psa_crypto_transaction);
                    if (status == PF_PSA_SUCCESS) {
                        global_data.initialized |= PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
                    }
                    status = pf_psa_crypto_stop_transaction();
                } else if (status == PF_PSA_ERROR_DOES_NOT_EXIST) {
                    /* There's no transaction to complete. It's all good. */
                    global_data.initialized |= PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
                    status = PF_PSA_SUCCESS;
                }
#else /* defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS) */
                global_data.initialized |= PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
                status = PF_PSA_SUCCESS;
#endif /* defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS) */
            }

#if defined(PF_MBEDTLS_THREADING_C)
            PF_PSA_THREADING_CHK_GOTO_EXIT(pf_mbedtls_mutex_unlock(
                                            &pf_mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

            break;

        default:
            status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    }

    /* Exit label only required when using threading macros. */
#if defined(PF_MBEDTLS_THREADING_C)
exit:
#endif /* defined(MBEDTLS_THREADING_C) */

    return status;
}

pf_psa_status_t pf_psa_crypto_init(void)
{
    pf_psa_status_t status;

    /* Double initialization is explicitly allowed. Early out if everything is
     * done. */
    if (pf_psa_get_initialized()) {
        return PF_PSA_SUCCESS;
    }

    status = pf_mbedtls_psa_crypto_init_subsystem(PF_PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_mbedtls_psa_crypto_init_subsystem(PF_PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_mbedtls_psa_crypto_init_subsystem(PF_PSA_CRYPTO_SUBSYSTEM_RNG);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_mbedtls_psa_crypto_init_subsystem(PF_PSA_CRYPTO_SUBSYSTEM_TRANSACTION);

exit:

    if (status != PF_PSA_SUCCESS) {
        pf_mbedtls_psa_crypto_free();
    }

    return status;
}



/****************************************************************/
/* PAKE */
/****************************************************************/

#if defined(PF_PSA_WANT_ALG_SOME_PAKE)
pf_psa_status_t pf_psa_crypto_driver_pake_get_password_len(
    const pf_psa_crypto_driver_pake_inputs_t *inputs,
    size_t *password_len)
{
    if (inputs->password_len == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    *password_len = inputs->password_len;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_driver_pake_get_password(
    const pf_psa_crypto_driver_pake_inputs_t *inputs,
    uint8_t *buffer, size_t buffer_size, size_t *buffer_length)
{
    if (inputs->password_len == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (buffer_size < inputs->password_len) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(buffer, inputs->password, inputs->password_len);
    *buffer_length = inputs->password_len;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_driver_pake_get_user_len(
    const pf_psa_crypto_driver_pake_inputs_t *inputs,
    size_t *user_len)
{
    if (inputs->user_len == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    *user_len = inputs->user_len;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_driver_pake_get_user(
    const pf_psa_crypto_driver_pake_inputs_t *inputs,
    uint8_t *user_id, size_t user_id_size, size_t *user_id_len)
{
    if (inputs->user_len == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (user_id_size < inputs->user_len) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(user_id, inputs->user, inputs->user_len);
    *user_id_len = inputs->user_len;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_driver_pake_get_peer_len(
    const pf_psa_crypto_driver_pake_inputs_t *inputs,
    size_t *peer_len)
{
    if (inputs->peer_len == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    *peer_len = inputs->peer_len;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_driver_pake_get_peer(
    const pf_psa_crypto_driver_pake_inputs_t *inputs,
    uint8_t *peer_id, size_t peer_id_size, size_t *peer_id_length)
{
    if (inputs->peer_len == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (peer_id_size < inputs->peer_len) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(peer_id, inputs->peer, inputs->peer_len);
    *peer_id_length = inputs->peer_len;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_driver_pake_get_cipher_suite(
    const pf_psa_crypto_driver_pake_inputs_t *inputs,
    pf_psa_pake_cipher_suite_t *cipher_suite)
{
    if (inputs->cipher_suite.algorithm == PF_PSA_ALG_NONE) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    *cipher_suite = inputs->cipher_suite;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_pake_setup(
    pf_psa_pake_operation_t *operation,
    const pf_psa_pake_cipher_suite_t *cipher_suite)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_SETUP) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (PF_PSA_ALG_IS_PAKE(cipher_suite->algorithm) == 0 ||
        PF_PSA_ALG_IS_HASH(cipher_suite->hash) == 0) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Make sure the variable-purpose part of the operation is zeroed.
     * Initializing the operation does not necessarily take care of it,
     * since the context is a union and initializing a union does not
     * necessarily initialize all of its members. */
    memset(&operation->data, 0, sizeof(operation->data));

    operation->alg = cipher_suite->algorithm;
    operation->primitive = PF_PSA_PAKE_PRIMITIVE(cipher_suite->type,
                                              cipher_suite->family, cipher_suite->bits);
    operation->data.inputs.cipher_suite = *cipher_suite;

#if defined(PF_PSA_WANT_ALG_JPAKE)
    if (operation->alg == PF_PSA_ALG_JPAKE) {
        pf_psa_jpake_computation_stage_t *computation_stage =
            &operation->computation_stage.jpake;

        memset(computation_stage, 0, sizeof(*computation_stage));
        computation_stage->step = PF_PSA_PAKE_STEP_KEY_SHARE;
    } else
#endif /* PSA_WANT_ALG_JPAKE */
    {
        status = PF_PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    operation->stage = PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS;

    return PF_PSA_SUCCESS;
exit:
    pf_psa_pake_abort(operation);
    return status;
}

pf_psa_status_t pf_psa_pake_set_password_key(
    pf_psa_pake_operation_t *operation,
    pf_mbedtls_svc_key_id_t password)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t unlock_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_slot_t *slot = NULL;
    pf_psa_key_type_t type;

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = pf_psa_get_and_lock_key_slot_with_policy(password, &slot,
                                                   PF_PSA_KEY_USAGE_DERIVE,
                                                   operation->alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    type = pf_psa_get_key_type(&slot->attr);

    if (type != PF_PSA_KEY_TYPE_PASSWORD &&
        type != PF_PSA_KEY_TYPE_PASSWORD_HASH) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    operation->data.inputs.password = pf_mbedtls_calloc(1, slot->key.bytes);
    if (operation->data.inputs.password == NULL) {
        status = PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    memcpy(operation->data.inputs.password, slot->key.data, slot->key.bytes);
    operation->data.inputs.password_len = slot->key.bytes;
    operation->data.inputs.attributes = slot->attr;

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_psa_pake_abort(operation);
    }
    unlock_status = pf_psa_unregister_read_under_mutex(slot);
    return (status == PF_PSA_SUCCESS) ? unlock_status : status;
}

pf_psa_status_t pf_psa_pake_set_user(
    pf_psa_pake_operation_t *operation,
    const uint8_t *user_id_external,
    size_t user_id_len)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(user_id_external, user_id);

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (user_id_len == 0) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (operation->data.inputs.user_len != 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    operation->data.inputs.user = pf_mbedtls_calloc(1, user_id_len);
    if (operation->data.inputs.user == NULL) {
        status = PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(user_id_external, user_id_len, user_id);

    memcpy(operation->data.inputs.user, user_id, user_id_len);
    operation->data.inputs.user_len = user_id_len;

    status = PF_PSA_SUCCESS;

exit:
    LOCAL_INPUT_FREE(user_id_external, user_id);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_pake_abort(operation);
    }
    return status;
}

pf_psa_status_t pf_psa_pake_set_peer(
    pf_psa_pake_operation_t *operation,
    const uint8_t *peer_id_external,
    size_t peer_id_len)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    LOCAL_INPUT_DECLARE(peer_id_external, peer_id);

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (peer_id_len == 0) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (operation->data.inputs.peer_len != 0) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    operation->data.inputs.peer = pf_mbedtls_calloc(1, peer_id_len);
    if (operation->data.inputs.peer == NULL) {
        status = PF_PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    LOCAL_INPUT_ALLOC(peer_id_external, peer_id_len, peer_id);

    memcpy(operation->data.inputs.peer, peer_id, peer_id_len);
    operation->data.inputs.peer_len = peer_id_len;

    status = PF_PSA_SUCCESS;

exit:
    LOCAL_INPUT_FREE(peer_id_external, peer_id);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_pake_abort(operation);
    }
    return status;
}

pf_psa_status_t pf_psa_pake_set_role(
    pf_psa_pake_operation_t *operation,
    pf_psa_pake_role_t role)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    switch (operation->alg) {
#if defined(PF_PSA_WANT_ALG_JPAKE)
        case PF_PSA_ALG_JPAKE:
            if (role == PF_PSA_PAKE_ROLE_NONE) {
                return PF_PSA_SUCCESS;
            }
            status = PF_PSA_ERROR_INVALID_ARGUMENT;
            break;
#endif
        default:
            (void) role;
            status = PF_PSA_ERROR_NOT_SUPPORTED;
            goto exit;
    }
exit:
    pf_psa_pake_abort(operation);
    return status;
}

/* Auxiliary function to convert core computation stage to single driver step. */
#if defined(PF_PSA_WANT_ALG_JPAKE)
static pf_psa_crypto_driver_pake_step_t convert_jpake_computation_stage_to_driver_step(
    pf_psa_jpake_computation_stage_t *stage)
{
    pf_psa_crypto_driver_pake_step_t key_share_step;
    if (stage->round == PF_PSA_JPAKE_FIRST) {
        int is_x1;

        if (stage->io_mode == PF_PSA_JPAKE_OUTPUT) {
            is_x1 = (stage->outputs < 1);
        } else {
            is_x1 = (stage->inputs < 1);
        }

        key_share_step = is_x1 ?
                         PF_PSA_JPAKE_X1_STEP_KEY_SHARE :
                         PF_PSA_JPAKE_X2_STEP_KEY_SHARE;
    } else if (stage->round == PF_PSA_JPAKE_SECOND) {
        key_share_step = (stage->io_mode == PF_PSA_JPAKE_OUTPUT) ?
                         PF_PSA_JPAKE_X2S_STEP_KEY_SHARE :
                         PF_PSA_JPAKE_X4S_STEP_KEY_SHARE;
    } else {
        return PF_PSA_JPAKE_STEP_INVALID;
    }
    return (pf_psa_crypto_driver_pake_step_t) (key_share_step + stage->step - PF_PSA_PAKE_STEP_KEY_SHARE);
}
#endif /* PSA_WANT_ALG_JPAKE */

static pf_psa_status_t pf_psa_pake_complete_inputs(
    pf_psa_pake_operation_t *operation)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    /* Create copy of the inputs on stack as inputs share memory
       with the driver context which will be setup by the driver. */
    pf_psa_crypto_driver_pake_inputs_t inputs = operation->data.inputs;

    if (inputs.password_len == 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (operation->alg == PF_PSA_ALG_JPAKE) {
        if (inputs.user_len == 0 || inputs.peer_len == 0) {
            return PF_PSA_ERROR_BAD_STATE;
        }
    }

    /* Clear driver context */
    pf_mbedtls_platform_zeroize(&operation->data, sizeof(operation->data));

    status = pf_psa_driver_wrapper_pake_setup(operation, &inputs);

    /* Driver is responsible for creating its own copy of the password. */
    pf_mbedtls_zeroize_and_free(inputs.password, inputs.password_len);

    /* User and peer are translated to role. */
    pf_mbedtls_free(inputs.user);
    pf_mbedtls_free(inputs.peer);

    if (status == PF_PSA_SUCCESS) {
#if defined(PF_PSA_WANT_ALG_JPAKE)
        if (operation->alg == PF_PSA_ALG_JPAKE) {
            operation->stage = PF_PSA_PAKE_OPERATION_STAGE_COMPUTATION;
        } else
#endif /* PSA_WANT_ALG_JPAKE */
        {
            status = PF_PSA_ERROR_NOT_SUPPORTED;
        }
    }
    return status;
}

#if defined(PF_PSA_WANT_ALG_JPAKE)
static pf_psa_status_t pf_psa_jpake_prologue(
    pf_psa_pake_operation_t *operation,
    pf_psa_pake_step_t step,
    pf_psa_jpake_io_mode_t io_mode)
{
    if (step != PF_PSA_PAKE_STEP_KEY_SHARE &&
        step != PF_PSA_PAKE_STEP_ZK_PUBLIC &&
        step != PF_PSA_PAKE_STEP_ZK_PROOF) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    pf_psa_jpake_computation_stage_t *computation_stage =
        &operation->computation_stage.jpake;

    if (computation_stage->round != PF_PSA_JPAKE_FIRST &&
        computation_stage->round != PF_PSA_JPAKE_SECOND) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    /* Check that the step we are given is the one we were expecting */
    if (step != computation_stage->step) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    if (step == PF_PSA_PAKE_STEP_KEY_SHARE &&
        computation_stage->inputs == 0 &&
        computation_stage->outputs == 0) {
        /* Start of the round, so function decides whether we are inputting
         * or outputting */
        computation_stage->io_mode = io_mode;
    } else if (computation_stage->io_mode != io_mode) {
        /* Middle of the round so the mode we are in must match the function
         * called by the user */
        return PF_PSA_ERROR_BAD_STATE;
    }

    return PF_PSA_SUCCESS;
}

static pf_psa_status_t pf_psa_jpake_epilogue(
    pf_psa_pake_operation_t *operation,
    pf_psa_jpake_io_mode_t io_mode)
{
    pf_psa_jpake_computation_stage_t *stage =
        &operation->computation_stage.jpake;

    if (stage->step == PF_PSA_PAKE_STEP_ZK_PROOF) {
        /* End of an input/output */
        if (io_mode == PF_PSA_JPAKE_INPUT) {
            stage->inputs++;
            if (stage->inputs == PF_PSA_JPAKE_EXPECTED_INPUTS(stage->round)) {
                stage->io_mode = PF_PSA_JPAKE_OUTPUT;
            }
        }
        if (io_mode == PF_PSA_JPAKE_OUTPUT) {
            stage->outputs++;
            if (stage->outputs == PF_PSA_JPAKE_EXPECTED_OUTPUTS(stage->round)) {
                stage->io_mode = PF_PSA_JPAKE_INPUT;
            }
        }
        if (stage->inputs == PF_PSA_JPAKE_EXPECTED_INPUTS(stage->round) &&
            stage->outputs == PF_PSA_JPAKE_EXPECTED_OUTPUTS(stage->round)) {
            /* End of a round, move to the next round */
            stage->inputs = 0;
            stage->outputs = 0;
            stage->round++;
        }
        stage->step = PF_PSA_PAKE_STEP_KEY_SHARE;
    } else {
        stage->step++;
    }
    return PF_PSA_SUCCESS;
}

#endif /* PSA_WANT_ALG_JPAKE */

pf_psa_status_t pf_psa_pake_output(
    pf_psa_pake_operation_t *operation,
    pf_psa_pake_step_t step,
    uint8_t *output_external,
    size_t output_size,
    size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_crypto_driver_pake_step_t driver_step = PF_PSA_JPAKE_STEP_INVALID;
    LOCAL_OUTPUT_DECLARE(output_external, output);
    *output_length = 0;

    if (operation->stage == PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS) {
        status = pf_psa_pake_complete_inputs(operation);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_COMPUTATION) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (output_size == 0) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    switch (operation->alg) {
#if defined(PF_PSA_WANT_ALG_JPAKE)
        case PF_PSA_ALG_JPAKE:
            status = pf_psa_jpake_prologue(operation, step, PF_PSA_JPAKE_OUTPUT);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
            driver_step = convert_jpake_computation_stage_to_driver_step(
                &operation->computation_stage.jpake);
            break;
#endif /* PSA_WANT_ALG_JPAKE */
        default:
            (void) step;
            status = PF_PSA_ERROR_NOT_SUPPORTED;
            goto exit;
    }

    LOCAL_OUTPUT_ALLOC(output_external, output_size, output);

    status = pf_psa_driver_wrapper_pake_output(operation, driver_step,
                                            output, output_size, output_length);

    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    switch (operation->alg) {
#if defined(PF_PSA_WANT_ALG_JPAKE)
        case PF_PSA_ALG_JPAKE:
            status = pf_psa_jpake_epilogue(operation, PF_PSA_JPAKE_OUTPUT);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
            break;
#endif /* PSA_WANT_ALG_JPAKE */
        default:
            status = PF_PSA_ERROR_NOT_SUPPORTED;
            goto exit;
    }

exit:
    LOCAL_OUTPUT_FREE(output_external, output);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_pake_abort(operation);
    }
    return status;
}

pf_psa_status_t pf_psa_pake_input(
    pf_psa_pake_operation_t *operation,
    pf_psa_pake_step_t step,
    const uint8_t *input_external,
    size_t input_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_crypto_driver_pake_step_t driver_step = PF_PSA_JPAKE_STEP_INVALID;
    const size_t max_input_length = (size_t) PF_PSA_PAKE_INPUT_SIZE(operation->alg,
                                                                 operation->primitive,
                                                                 step);
    LOCAL_INPUT_DECLARE(input_external, input);

    if (operation->stage == PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS) {
        status = pf_psa_pake_complete_inputs(operation);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_COMPUTATION) {
        status =  PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (input_length == 0 || input_length > max_input_length) {
        status = PF_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    switch (operation->alg) {
#if defined(PF_PSA_WANT_ALG_JPAKE)
        case PF_PSA_ALG_JPAKE:
            status = pf_psa_jpake_prologue(operation, step, PF_PSA_JPAKE_INPUT);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
            driver_step = convert_jpake_computation_stage_to_driver_step(
                &operation->computation_stage.jpake);
            break;
#endif /* PSA_WANT_ALG_JPAKE */
        default:
            (void) step;
            status = PF_PSA_ERROR_NOT_SUPPORTED;
            goto exit;
    }

    LOCAL_INPUT_ALLOC(input_external, input_length, input);
    status = pf_psa_driver_wrapper_pake_input(operation, driver_step,
                                           input, input_length);

    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    switch (operation->alg) {
#if defined(PF_PSA_WANT_ALG_JPAKE)
        case PF_PSA_ALG_JPAKE:
            status = pf_psa_jpake_epilogue(operation, PF_PSA_JPAKE_INPUT);
            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }
            break;
#endif /* PSA_WANT_ALG_JPAKE */
        default:
            status = PF_PSA_ERROR_NOT_SUPPORTED;
            goto exit;
    }

exit:
    LOCAL_INPUT_FREE(input_external, input);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_pake_abort(operation);
    }
    return status;
}

pf_psa_status_t pf_psa_pake_get_implicit_key(
    pf_psa_pake_operation_t *operation,
    pf_psa_key_derivation_operation_t *output)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t abort_status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t shared_key[PF_MBEDTLS_PSA_JPAKE_BUFFER_SIZE];
    size_t shared_key_len = 0;

    if (operation->stage != PF_PSA_PAKE_OPERATION_STAGE_COMPUTATION) {
        status = PF_PSA_ERROR_BAD_STATE;
        goto exit;
    }

#if defined(PF_PSA_WANT_ALG_JPAKE)
    if (operation->alg == PF_PSA_ALG_JPAKE) {
        pf_psa_jpake_computation_stage_t *computation_stage =
            &operation->computation_stage.jpake;
        if (computation_stage->round != PF_PSA_JPAKE_FINISHED) {
            status = PF_PSA_ERROR_BAD_STATE;
            goto exit;
        }
    } else
#endif /* PSA_WANT_ALG_JPAKE */
    {
        status = PF_PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    status = pf_psa_driver_wrapper_pake_get_implicit_key(operation,
                                                      shared_key,
                                                      sizeof(shared_key),
                                                      &shared_key_len);

    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_key_derivation_input_bytes(output,
                                            PF_PSA_KEY_DERIVATION_INPUT_SECRET,
                                            shared_key,
                                            shared_key_len);

    pf_mbedtls_platform_zeroize(shared_key, sizeof(shared_key));
exit:
    abort_status = pf_psa_pake_abort(operation);
    return status == PF_PSA_SUCCESS ? abort_status : status;
}

pf_psa_status_t pf_psa_pake_abort(
    pf_psa_pake_operation_t *operation)
{
    pf_psa_status_t status = PF_PSA_SUCCESS;

    if (operation->stage == PF_PSA_PAKE_OPERATION_STAGE_COMPUTATION) {
        status = pf_psa_driver_wrapper_pake_abort(operation);
    }

    if (operation->stage == PF_PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS) {
        if (operation->data.inputs.password != NULL) {
            pf_mbedtls_zeroize_and_free(operation->data.inputs.password,
                                     operation->data.inputs.password_len);
        }
        if (operation->data.inputs.user != NULL) {
            pf_mbedtls_free(operation->data.inputs.user);
        }
        if (operation->data.inputs.peer != NULL) {
            pf_mbedtls_free(operation->data.inputs.peer);
        }
    }
    memset(operation, 0, sizeof(pf_psa_pake_operation_t));

    return status;
}
#endif /* PSA_WANT_ALG_SOME_PAKE */

/* Memory copying test hooks. These are called before input copy, after input
 * copy, before output copy and after output copy, respectively.
 * They are used by memory-poisoning tests to temporarily unpoison buffers
 * while they are copied. */
#if defined(PF_MBEDTLS_TEST_HOOKS)
void (*pf_psa_input_pre_copy_hook)(const uint8_t *input, size_t input_len) = NULL;
void (*pf_psa_input_post_copy_hook)(const uint8_t *input, size_t input_len) = NULL;
void (*pf_psa_output_pre_copy_hook)(const uint8_t *output, size_t output_len) = NULL;
void (*pf_psa_output_post_copy_hook)(const uint8_t *output, size_t output_len) = NULL;
#endif

/** Copy from an input buffer to a local copy.
 *
 * \param[in] input             Pointer to input buffer.
 * \param[in] input_len         Length of the input buffer.
 * \param[out] input_copy       Pointer to a local copy in which to store the input data.
 * \param[out] input_copy_len   Length of the local copy buffer.
 * \return                      #PSA_SUCCESS, if the buffer was successfully
 *                              copied.
 * \return                      #PSA_ERROR_CORRUPTION_DETECTED, if the local
 *                              copy is too small to hold contents of the
 *                              input buffer.
 */
PF_MBEDTLS_STATIC_TESTABLE
pf_psa_status_t pf_psa_crypto_copy_input(const uint8_t *input, size_t input_len,
                                   uint8_t *input_copy, size_t input_copy_len)
{
    if (input_len > input_copy_len) {
        return PF_PSA_ERROR_CORRUPTION_DETECTED;
    }

#if defined(PF_MBEDTLS_TEST_HOOKS)
    if (pf_psa_input_pre_copy_hook != NULL) {
        pf_psa_input_pre_copy_hook(input, input_len);
    }
#endif

    if (input_len > 0) {
        memcpy(input_copy, input, input_len);
    }

#if defined(PF_MBEDTLS_TEST_HOOKS)
    if (pf_psa_input_post_copy_hook != NULL) {
        pf_psa_input_post_copy_hook(input, input_len);
    }
#endif

    return PF_PSA_SUCCESS;
}

/** Copy from a local output buffer into a user-supplied one.
 *
 * \param[in] output_copy       Pointer to a local buffer containing the output.
 * \param[in] output_copy_len   Length of the local buffer.
 * \param[out] output           Pointer to user-supplied output buffer.
 * \param[out] output_len       Length of the user-supplied output buffer.
 * \return                      #PSA_SUCCESS, if the buffer was successfully
 *                              copied.
 * \return                      #PSA_ERROR_BUFFER_TOO_SMALL, if the
 *                              user-supplied output buffer is too small to
 *                              hold the contents of the local buffer.
 */
PF_MBEDTLS_STATIC_TESTABLE
pf_psa_status_t pf_psa_crypto_copy_output(const uint8_t *output_copy, size_t output_copy_len,
                                    uint8_t *output, size_t output_len)
{
    if (output_len < output_copy_len) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

#if defined(PF_MBEDTLS_TEST_HOOKS)
    if (pf_psa_output_pre_copy_hook != NULL) {
        pf_psa_output_pre_copy_hook(output, output_len);
    }
#endif

    if (output_copy_len > 0) {
        memcpy(output, output_copy, output_copy_len);
    }

#if defined(PF_MBEDTLS_TEST_HOOKS)
    if (pf_psa_output_post_copy_hook != NULL) {
        pf_psa_output_post_copy_hook(output, output_len);
    }
#endif

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_local_input_alloc(const uint8_t *input, size_t input_len,
                                          pf_psa_crypto_local_input_t *local_input)
{
    pf_psa_status_t status;

    *local_input = PF_PSA_CRYPTO_LOCAL_INPUT_INIT;

    if (input_len == 0) {
        return PF_PSA_SUCCESS;
    }

    local_input->buffer = pf_mbedtls_calloc(input_len, 1);
    if (local_input->buffer == NULL) {
        /* Since we dealt with the zero-length case above, we know that
         * a NULL return value means a failure of allocation. */
        return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    /* From now on, we must free local_input->buffer on error. */

    local_input->length = input_len;

    status = pf_psa_crypto_copy_input(input, input_len,
                                   local_input->buffer, local_input->length);
    if (status != PF_PSA_SUCCESS) {
        goto error;
    }

    return PF_PSA_SUCCESS;

error:
    pf_mbedtls_zeroize_and_free(local_input->buffer, local_input->length);
    local_input->buffer = NULL;
    local_input->length = 0;
    return status;
}

void pf_psa_crypto_local_input_free(pf_psa_crypto_local_input_t *local_input)
{
    pf_mbedtls_zeroize_and_free(local_input->buffer, local_input->length);
    local_input->buffer = NULL;
    local_input->length = 0;
}

pf_psa_status_t pf_psa_crypto_local_output_alloc(uint8_t *output, size_t output_len,
                                           pf_psa_crypto_local_output_t *local_output)
{
    *local_output = PF_PSA_CRYPTO_LOCAL_OUTPUT_INIT;

    if (output_len == 0) {
        return PF_PSA_SUCCESS;
    }
    local_output->buffer = pf_mbedtls_calloc(output_len, 1);
    if (local_output->buffer == NULL) {
        /* Since we dealt with the zero-length case above, we know that
         * a NULL return value means a failure of allocation. */
        return PF_PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    local_output->length = output_len;
    local_output->original = output;

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_crypto_local_output_free(pf_psa_crypto_local_output_t *local_output)
{
    pf_psa_status_t status;

    if (local_output->buffer == NULL) {
        local_output->length = 0;
        return PF_PSA_SUCCESS;
    }
    if (local_output->original == NULL) {
        /* We have an internal copy but nothing to copy back to. */
        return PF_PSA_ERROR_CORRUPTION_DETECTED;
    }

    status = pf_psa_crypto_copy_output(local_output->buffer, local_output->length,
                                    local_output->original, local_output->length);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    pf_mbedtls_zeroize_and_free(local_output->buffer, local_output->length);
    local_output->buffer = NULL;
    local_output->length = 0;

    return PF_PSA_SUCCESS;
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
