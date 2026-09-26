#include "../../../pf_build_config.h"
/*
 *  PSA hashing layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

/* This is needed for MBEDTLS_ERR_XXX macros */
#include "../include/mbedtls/error.h"

#if defined(PF_MBEDTLS_ASN1_WRITE_C)
#include "../include/mbedtls/asn1write.h"
#include "../include/psa/crypto_sizes.h"
#endif

#include "psa_util_internal.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT)

#include "../include/psa/crypto.h"

#if defined(PF_MBEDTLS_MD_LIGHT)
#include "../include/mbedtls/md.h"
#endif
#if defined(PF_MBEDTLS_LMS_C)
#include "../include/mbedtls/lms.h"
#endif
#if defined(PF_MBEDTLS_SSL_TLS_C) && \
    (defined(PF_MBEDTLS_USE_PSA_CRYPTO) || defined(PF_MBEDTLS_SSL_PROTO_TLS1_3))
#include "../include/mbedtls/ssl.h"
#endif
#if defined(PF_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) ||    \
    defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
#include "../include/mbedtls/rsa.h"
#endif
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO) && \
    defined(PF_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#include "../include/mbedtls/ecp.h"
#endif
#if defined(PF_MBEDTLS_PK_C)
#include "../include/mbedtls/pk.h"
#endif
#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
#include "../include/mbedtls/cipher.h"
#endif
#include "../include/mbedtls/entropy.h"

/* PSA_SUCCESS is kept at the top of each error table since
 * it's the most common status when everything functions properly. */
#if defined(PF_MBEDTLS_MD_LIGHT)
const pf_mbedtls_error_pair_t pf_psa_to_md_errors[] =
{
    { PF_PSA_SUCCESS,                     0 },
    { PF_PSA_ERROR_NOT_SUPPORTED,         PF_MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE },
    { PF_PSA_ERROR_INVALID_ARGUMENT,      PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA },
    { PF_PSA_ERROR_INSUFFICIENT_MEMORY,   PF_MBEDTLS_ERR_MD_ALLOC_FAILED }
};
#endif

#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
const pf_mbedtls_error_pair_t pf_psa_to_cipher_errors[] =
{
    { PF_PSA_SUCCESS,                     0 },
    { PF_PSA_ERROR_NOT_SUPPORTED,         PF_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE },
    { PF_PSA_ERROR_INVALID_ARGUMENT,      PF_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA },
    { PF_PSA_ERROR_INSUFFICIENT_MEMORY,   PF_MBEDTLS_ERR_CIPHER_ALLOC_FAILED }
};
#endif

#if defined(PF_MBEDTLS_LMS_C)
const pf_mbedtls_error_pair_t pf_psa_to_lms_errors[] =
{
    { PF_PSA_SUCCESS,                     0 },
    { PF_PSA_ERROR_BUFFER_TOO_SMALL,      PF_MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL },
    { PF_PSA_ERROR_INVALID_ARGUMENT,      PF_MBEDTLS_ERR_LMS_BAD_INPUT_DATA }
};
#endif

#if defined(PF_MBEDTLS_SSL_TLS_C) && \
    (defined(PF_MBEDTLS_USE_PSA_CRYPTO) || defined(PF_MBEDTLS_SSL_PROTO_TLS1_3))
const pf_mbedtls_error_pair_t pf_psa_to_ssl_errors[] =
{
    { PF_PSA_SUCCESS,                     0 },
    { PF_PSA_ERROR_INSUFFICIENT_MEMORY,   PF_MBEDTLS_ERR_SSL_ALLOC_FAILED },
    { PF_PSA_ERROR_NOT_SUPPORTED,         PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE },
    { PF_PSA_ERROR_INVALID_SIGNATURE,     PF_MBEDTLS_ERR_SSL_INVALID_MAC },
    { PF_PSA_ERROR_INVALID_ARGUMENT,      PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA },
    { PF_PSA_ERROR_BAD_STATE,             PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR },
    { PF_PSA_ERROR_BUFFER_TOO_SMALL,      PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL }
};
#endif

#if defined(PF_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) ||    \
    defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
const pf_mbedtls_error_pair_t pf_psa_to_pk_rsa_errors[] =
{
    { PF_PSA_SUCCESS,                     0 },
    { PF_PSA_ERROR_NOT_PERMITTED,         PF_MBEDTLS_ERR_RSA_BAD_INPUT_DATA },
    { PF_PSA_ERROR_INVALID_ARGUMENT,      PF_MBEDTLS_ERR_RSA_BAD_INPUT_DATA },
    { PF_PSA_ERROR_INVALID_HANDLE,        PF_MBEDTLS_ERR_RSA_BAD_INPUT_DATA },
    { PF_PSA_ERROR_BUFFER_TOO_SMALL,      PF_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE },
    { PF_PSA_ERROR_INSUFFICIENT_ENTROPY,  PF_MBEDTLS_ERR_RSA_RNG_FAILED },
    { PF_PSA_ERROR_INVALID_SIGNATURE,     PF_MBEDTLS_ERR_RSA_VERIFY_FAILED },
    { PF_PSA_ERROR_INVALID_PADDING,       PF_MBEDTLS_ERR_RSA_INVALID_PADDING }
};
#endif

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO) && \
    defined(PF_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
const pf_mbedtls_error_pair_t pf_psa_to_pk_ecdsa_errors[] =
{
    { PF_PSA_SUCCESS,                     0 },
    { PF_PSA_ERROR_NOT_PERMITTED,         PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA },
    { PF_PSA_ERROR_INVALID_ARGUMENT,      PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA },
    { PF_PSA_ERROR_INVALID_HANDLE,        PF_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE },
    { PF_PSA_ERROR_BUFFER_TOO_SMALL,      PF_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL },
    { PF_PSA_ERROR_INSUFFICIENT_ENTROPY,  PF_MBEDTLS_ERR_ECP_RANDOM_FAILED },
    { PF_PSA_ERROR_INVALID_SIGNATURE,     PF_MBEDTLS_ERR_ECP_VERIFY_FAILED }
};
#endif

int pf_psa_generic_status_to_mbedtls(pf_psa_status_t status)
{
    switch (status) {
        case PF_PSA_SUCCESS:
            return 0;
        case PF_PSA_ERROR_NOT_SUPPORTED:
            return PF_MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
        case PF_PSA_ERROR_CORRUPTION_DETECTED:
            return PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        case PF_PSA_ERROR_COMMUNICATION_FAILURE:
        case PF_PSA_ERROR_HARDWARE_FAILURE:
            return PF_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        case PF_PSA_ERROR_NOT_PERMITTED:
        default:
            return PF_MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
}

int pf_psa_status_to_mbedtls(pf_psa_status_t status,
                          const pf_mbedtls_error_pair_t *local_translations,
                          size_t local_errors_num,
                          int (*fallback_f)(pf_psa_status_t))
{
    for (size_t i = 0; i < local_errors_num; i++) {
        if (status == local_translations[i].pf_psa_status) {
            return local_translations[i].pf_mbedtls_error;
        }
    }
    return fallback_f(status);
}

#if defined(PF_MBEDTLS_PK_C)
int pf_psa_pk_status_to_mbedtls(pf_psa_status_t status)
{
    switch (status) {
        case PF_PSA_ERROR_INVALID_HANDLE:
            return PF_MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
        case PF_PSA_ERROR_BUFFER_TOO_SMALL:
            return PF_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
        case PF_PSA_ERROR_NOT_SUPPORTED:
            return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        case PF_PSA_ERROR_INVALID_ARGUMENT:
            return PF_MBEDTLS_ERR_PK_INVALID_ALG;
        case PF_PSA_ERROR_NOT_PERMITTED:
            return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
        case PF_PSA_ERROR_INSUFFICIENT_MEMORY:
            return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
        case PF_PSA_ERROR_BAD_STATE:
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        case PF_PSA_ERROR_DATA_CORRUPT:
        case PF_PSA_ERROR_DATA_INVALID:
        case PF_PSA_ERROR_STORAGE_FAILURE:
            return PF_MBEDTLS_ERR_PK_FILE_IO_ERROR;
        default:
            return pf_psa_generic_status_to_mbedtls(status);
    }
}
#endif /* MBEDTLS_PK_C */

/****************************************************************/
/* Key management */
/****************************************************************/

#if defined(PF_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
pf_psa_ecc_family_t pf_mbedtls_ecc_group_to_psa(pf_mbedtls_ecp_group_id grpid,
                                          size_t *bits)
{
    switch (grpid) {
#if defined(PF_MBEDTLS_ECP_HAVE_SECP192R1)
        case PF_MBEDTLS_ECP_DP_SECP192R1:
            *bits = 192;
            return PF_PSA_ECC_FAMILY_SECP_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP224R1)
        case PF_MBEDTLS_ECP_DP_SECP224R1:
            *bits = 224;
            return PF_PSA_ECC_FAMILY_SECP_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP256R1)
        case PF_MBEDTLS_ECP_DP_SECP256R1:
            *bits = 256;
            return PF_PSA_ECC_FAMILY_SECP_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP384R1)
        case PF_MBEDTLS_ECP_DP_SECP384R1:
            *bits = 384;
            return PF_PSA_ECC_FAMILY_SECP_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP521R1)
        case PF_MBEDTLS_ECP_DP_SECP521R1:
            *bits = 521;
            return PF_PSA_ECC_FAMILY_SECP_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP256R1)
        case PF_MBEDTLS_ECP_DP_BP256R1:
            *bits = 256;
            return PF_PSA_ECC_FAMILY_BRAINPOOL_P_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP384R1)
        case PF_MBEDTLS_ECP_DP_BP384R1:
            *bits = 384;
            return PF_PSA_ECC_FAMILY_BRAINPOOL_P_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP512R1)
        case PF_MBEDTLS_ECP_DP_BP512R1:
            *bits = 512;
            return PF_PSA_ECC_FAMILY_BRAINPOOL_P_R1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_CURVE25519)
        case PF_MBEDTLS_ECP_DP_CURVE25519:
            *bits = 255;
            return PF_PSA_ECC_FAMILY_MONTGOMERY;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP192K1)
        case PF_MBEDTLS_ECP_DP_SECP192K1:
            *bits = 192;
            return PF_PSA_ECC_FAMILY_SECP_K1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP224K1)
    /* secp224k1 is not and will not be supported in PSA (#3541). */
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP256K1)
        case PF_MBEDTLS_ECP_DP_SECP256K1:
            *bits = 256;
            return PF_PSA_ECC_FAMILY_SECP_K1;
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_CURVE448)
        case PF_MBEDTLS_ECP_DP_CURVE448:
            *bits = 448;
            return PF_PSA_ECC_FAMILY_MONTGOMERY;
#endif
        default:
            *bits = 0;
            return 0;
    }
}

pf_mbedtls_ecp_group_id pf_mbedtls_ecc_group_from_psa(pf_psa_ecc_family_t family,
                                                size_t bits)
{
    switch (family) {
        case PF_PSA_ECC_FAMILY_SECP_R1:
            switch (bits) {
#if defined(PF_PSA_WANT_ECC_SECP_R1_192)
                case 192:
                    return PF_MBEDTLS_ECP_DP_SECP192R1;
#endif
#if defined(PF_PSA_WANT_ECC_SECP_R1_224)
                case 224:
                    return PF_MBEDTLS_ECP_DP_SECP224R1;
#endif
#if defined(PF_PSA_WANT_ECC_SECP_R1_256)
                case 256:
                    return PF_MBEDTLS_ECP_DP_SECP256R1;
#endif
#if defined(PF_PSA_WANT_ECC_SECP_R1_384)
                case 384:
                    return PF_MBEDTLS_ECP_DP_SECP384R1;
#endif
#if defined(PF_PSA_WANT_ECC_SECP_R1_521)
                case 521:
                    return PF_MBEDTLS_ECP_DP_SECP521R1;
#endif
            }
            break;

        case PF_PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            switch (bits) {
#if defined(PF_PSA_WANT_ECC_BRAINPOOL_P_R1_256)
                case 256:
                    return PF_MBEDTLS_ECP_DP_BP256R1;
#endif
#if defined(PF_PSA_WANT_ECC_BRAINPOOL_P_R1_384)
                case 384:
                    return PF_MBEDTLS_ECP_DP_BP384R1;
#endif
#if defined(PF_PSA_WANT_ECC_BRAINPOOL_P_R1_512)
                case 512:
                    return PF_MBEDTLS_ECP_DP_BP512R1;
#endif
            }
            break;

        case PF_PSA_ECC_FAMILY_MONTGOMERY:
            switch (bits) {
#if defined(PF_PSA_WANT_ECC_MONTGOMERY_255)
                case 255:
                    return PF_MBEDTLS_ECP_DP_CURVE25519;
#endif
#if defined(PF_PSA_WANT_ECC_MONTGOMERY_448)
                case 448:
                    return PF_MBEDTLS_ECP_DP_CURVE448;
#endif
            }
            break;

        case PF_PSA_ECC_FAMILY_SECP_K1:
            switch (bits) {
#if defined(PF_PSA_WANT_ECC_SECP_K1_192)
                case 192:
                    return PF_MBEDTLS_ECP_DP_SECP192K1;
#endif
#if defined(PF_PSA_WANT_ECC_SECP_K1_224)
            /* secp224k1 is not and will not be supported in PSA (#3541). */
#endif
#if defined(PF_PSA_WANT_ECC_SECP_K1_256)
                case 256:
                    return PF_MBEDTLS_ECP_DP_SECP256K1;
#endif
            }
            break;
    }

    return PF_MBEDTLS_ECP_DP_NONE;
}
#endif /* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */

/* Wrapper function allowing the classic API to use the PSA RNG.
 *
 * `mbedtls_psa_get_random(MBEDTLS_PSA_RANDOM_STATE, ...)` calls
 * `psa_generate_random(...)`. The state parameter is ignored since the
 * PSA API doesn't support passing an explicit state.
 */
int pf_mbedtls_psa_get_random(void *p_rng,
                           unsigned char *output,
                           size_t output_size)
{
    /* This function takes a pointer to the RNG state because that's what
     * classic mbedtls functions using an RNG expect. The PSA RNG manages
     * its own state internally and doesn't let the caller access that state.
     * So we just ignore the state parameter, and in practice we'll pass
     * NULL. */
    (void) p_rng;
    pf_psa_status_t status = pf_psa_generate_random(output, output_size);
    if (status == PF_PSA_SUCCESS) {
        return 0;
    } else {
        return PF_MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
}

#endif /* MBEDTLS_PSA_CRYPTO_CLIENT */

#if defined(PF_MBEDTLS_PSA_UTIL_HAVE_ECDSA)

/**
 * \brief  Convert a single raw coordinate to DER ASN.1 format. The output der
 *         buffer is filled backward (i.e. starting from its end).
 *
 * \param raw_buf           Buffer containing the raw coordinate to be
 *                          converted.
 * \param raw_len           Length of raw_buf in bytes. This must be > 0.
 * \param der_buf_start     Pointer to the beginning of the buffer which
 *                          will be filled with the DER converted data.
 * \param der_buf_end       End of the buffer used to store the DER output.
 *
 * \return                  On success, the amount of data (in bytes) written to
 *                          the DER buffer.
 * \return                  MBEDTLS_ERR_ASN1_BUF_TOO_SMALL if the provided der
 *                          buffer is too small to contain all the converted data.
 * \return                  MBEDTLS_ERR_ASN1_INVALID_DATA if the input raw
 *                          coordinate is null (i.e. all zeros).
 *
 * \warning                 Raw and der buffer must not be overlapping.
 */
static int convert_raw_to_der_single_int(const unsigned char *raw_buf, size_t raw_len,
                                         unsigned char *der_buf_start,
                                         unsigned char *der_buf_end)
{
    unsigned char *p = der_buf_end;
    int len;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* ASN.1 DER encoding requires minimal length, so skip leading 0s.
     * Provided input MPIs should not be 0, but as a failsafe measure, still
     * detect that and return error in case. */
    while (*raw_buf == 0x00) {
        ++raw_buf;
        --raw_len;
        if (raw_len == 0) {
            return PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
        }
    }
    len = (int) raw_len;

    /* Copy the raw coordinate to the end of der_buf. */
    if ((p - der_buf_start) < len) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    p -= len;
    memcpy(p, raw_buf, len);

    /* If MSb is 1, ASN.1 requires that we prepend a 0. */
    if (*p & 0x80) {
        if ((p - der_buf_start) < 1) {
            return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        --p;
        *p = 0x00;
        ++len;
    }

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&p, der_buf_start, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(&p, der_buf_start, PF_MBEDTLS_ASN1_INTEGER));

    return len;
}

int pf_mbedtls_ecdsa_raw_to_der(size_t bits, const unsigned char *raw, size_t raw_len,
                             unsigned char *der, size_t der_size, size_t *der_len)
{
    unsigned char r[PF_PSA_BITS_TO_BYTES(PF_PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    unsigned char s[PF_PSA_BITS_TO_BYTES(PF_PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    const size_t coordinate_len = PF_PSA_BITS_TO_BYTES(bits);
    size_t len = 0;
    unsigned char *p = der + der_size;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (bits == 0) {
        return PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    if (raw_len != (2 * coordinate_len)) {
        return PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    if (coordinate_len > sizeof(r)) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    /* Since raw and der buffers might overlap, dump r and s before starting
     * the conversion. */
    memcpy(r, raw, coordinate_len);
    memcpy(s, raw + coordinate_len, coordinate_len);

    /* der buffer will initially be written starting from its end so we pick s
     * first and then r. */
    ret = convert_raw_to_der_single_int(s, coordinate_len, der, p);
    if (ret < 0) {
        return ret;
    }
    p -= ret;
    len += ret;

    ret = convert_raw_to_der_single_int(r, coordinate_len, der, p);
    if (ret < 0) {
        return ret;
    }
    p -= ret;
    len += ret;

    /* Add ASN.1 header (len + tag). */
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&p, der, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(&p, der,
                                                     PF_MBEDTLS_ASN1_CONSTRUCTED |
                                                     PF_MBEDTLS_ASN1_SEQUENCE));

    /* memmove the content of der buffer to its beginnig. */
    memmove(der, p, len);
    *der_len = len;

    return 0;
}

/**
 * \brief Convert a single integer from ASN.1 DER format to raw.
 *
 * \param der               Buffer containing the DER integer value to be
 *                          converted.
 * \param der_len           Length of the der buffer in bytes.
 * \param raw               Output buffer that will be filled with the
 *                          converted data. This should be at least
 *                          coordinate_size bytes and it must be zeroed before
 *                          calling this function.
 * \param coordinate_size   Size (in bytes) of a single coordinate in raw
 *                          format.
 *
 * \return                  On success, the amount of DER data parsed from the
 *                          provided der buffer.
 * \return                  MBEDTLS_ERR_ASN1_UNEXPECTED_TAG if the integer tag
 *                          is missing in the der buffer.
 * \return                  MBEDTLS_ERR_ASN1_LENGTH_MISMATCH if the integer
 *                          is null (i.e. all zeros) or if the output raw buffer
 *                          is too small to contain the converted raw value.
 *
 * \warning                 Der and raw buffers must not be overlapping.
 */
static int convert_der_to_raw_single_int(unsigned char *der, size_t der_len,
                                         unsigned char *raw, size_t coordinate_size)
{
    unsigned char *p = der;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t unpadded_len, padding_len = 0;

    /* Get the length of ASN.1 element (i.e. the integer we need to parse). */
    ret = pf_mbedtls_asn1_get_tag(&p, p + der_len, &unpadded_len,
                               PF_MBEDTLS_ASN1_INTEGER);
    if (ret != 0) {
        return ret;
    }

    /* It's invalid to have:
     * - unpadded_len == 0.
     * - MSb set without a leading 0x00 (leading 0x00 is checked below). */
    if (((unpadded_len == 0) || (*p & 0x80) != 0)) {
        return PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
    }

    /* Skip possible leading zero */
    if (*p == 0x00) {
        p++;
        unpadded_len--;
        /* It is not allowed to have more than 1 leading zero.
         * Ignore the case in which unpadded_len = 0 because that's a 0 encoded
         * in ASN.1 format (i.e. 020100). */
        if ((unpadded_len > 0) && (*p == 0x00)) {
            return PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
        }
    }

    if (unpadded_len > coordinate_size) {
        /* Parsed number is longer than the maximum expected value. */
        return PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    padding_len = coordinate_size - unpadded_len;
    /* raw buffer was already zeroed by the calling function so zero-padding
     * operation is skipped here. */
    memcpy(raw + padding_len, p, unpadded_len);
    p += unpadded_len;

    return (int) (p - der);
}

int pf_mbedtls_ecdsa_der_to_raw(size_t bits, const unsigned char *der, size_t der_len,
                             unsigned char *raw, size_t raw_size, size_t *raw_len)
{
    unsigned char raw_tmp[PF_PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE];
    unsigned char *p = (unsigned char *) der;
    size_t data_len;
    size_t coordinate_size = PF_PSA_BITS_TO_BYTES(bits);
    int ret;

    if (bits == 0) {
        return PF_MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    /* The output raw buffer should be at least twice the size of a raw
     * coordinate in order to store r and s. */
    if (raw_size < coordinate_size * 2) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    if (2 * coordinate_size > sizeof(raw_tmp)) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    /* Check that the provided input DER buffer has the right header. */
    ret = pf_mbedtls_asn1_get_tag(&p, der + der_len, &data_len,
                               PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }

    memset(raw_tmp, 0, 2 * coordinate_size);

    /* Extract r */
    ret = convert_der_to_raw_single_int(p, data_len, raw_tmp, coordinate_size);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    data_len -= ret;

    /* Extract s */
    ret = convert_der_to_raw_single_int(p, data_len, raw_tmp + coordinate_size,
                                        coordinate_size);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    data_len -= ret;

    /* Check that we consumed all the input der data. */
    if ((size_t) (p - der) != der_len) {
        return PF_MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    memcpy(raw, raw_tmp, 2 * coordinate_size);
    *raw_len = 2 * coordinate_size;

    return 0;
}

#endif /* MBEDTLS_PSA_UTIL_HAVE_ECDSA */
