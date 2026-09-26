#include "../../../pf_build_config.h"
/*
 *  Public Key layer for writing key files and structures
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_PK_WRITE_C)

#include "../include/mbedtls/pk.h"
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/oid.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"
#include "pk_internal.h"

#include <string.h>

#if defined(PF_MBEDTLS_ECP_C)
#include "../include/mbedtls/bignum.h"
#include "../include/mbedtls/ecp.h"
#include "../include/mbedtls/platform_util.h"
#endif
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
#include "pk_internal.h"
#endif
#if defined(PF_MBEDTLS_RSA_C) || defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
#include "pkwrite.h"
#endif
#if defined(PF_MBEDTLS_PEM_WRITE_C)
#include "../include/mbedtls/pem.h"
#endif
#if defined(PF_MBEDTLS_RSA_C)
#include "rsa_internal.h"
#endif

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#include "../include/psa/crypto.h"
#include "psa_util_internal.h"
#endif
#include "../include/mbedtls/platform.h"

/* Helpers for properly sizing buffers aimed at holding public keys or
 * key-pairs based on build symbols. */
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
#define PK_MAX_EC_PUBLIC_KEY_SIZE       PF_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH
#define PK_MAX_EC_KEY_PAIR_SIZE         PF_MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH
#elif defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#define PK_MAX_EC_PUBLIC_KEY_SIZE       PF_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH
#define PK_MAX_EC_KEY_PAIR_SIZE         PF_MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH
#else
#define PK_MAX_EC_PUBLIC_KEY_SIZE       PF_MBEDTLS_ECP_MAX_PT_LEN
#define PK_MAX_EC_KEY_PAIR_SIZE         PF_MBEDTLS_ECP_MAX_BYTES
#endif

/******************************************************************************
 * Internal functions for RSA keys.
 ******************************************************************************/
#if defined(PF_MBEDTLS_RSA_C)
static int pk_write_rsa_der(unsigned char **p, unsigned char *buf,
                            const pf_mbedtls_pk_context *pk)
{
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (pf_mbedtls_pk_get_type(pk) == PF_MBEDTLS_PK_OPAQUE) {
        pf_psa_status_t status;
        size_t buf_size = (size_t) (*p - buf);
        size_t key_len = 0;

        status = pf_psa_export_key(pk->priv_id, buf, buf_size, &key_len);
        if (status == PF_PSA_ERROR_BUFFER_TOO_SMALL) {
            return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        } else if (status != PF_PSA_SUCCESS) {
            return PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        }

        /* We wrote to the beginning of the buffer while
         * we were supposed to write to its end. */
        *p -= key_len;
        memmove(*p, buf, key_len);
        pf_mbedtls_platform_zeroize(buf, *p - buf);

        return (int) key_len;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    return pf_mbedtls_rsa_write_key(pf_mbedtls_pk_rsa(*pk), buf, p);
}
#endif /* MBEDTLS_RSA_C */

/******************************************************************************
 * Internal functions for EC keys.
 ******************************************************************************/
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
static int pk_write_ec_pubkey(unsigned char **p, unsigned char *start,
                              const pf_mbedtls_pk_context *pk)
{
    size_t len = 0;
    uint8_t buf[PK_MAX_EC_PUBLIC_KEY_SIZE];

    if (pf_mbedtls_pk_get_type(pk) == PF_MBEDTLS_PK_OPAQUE) {
        if (pf_psa_export_public_key(pk->priv_id, buf, sizeof(buf), &len) != PF_PSA_SUCCESS) {
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        }
    } else {
        len = pk->pub_raw_len;
        memcpy(buf, pk->pub_raw, len);
    }

    if (*p < start || (size_t) (*p - start) < len) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *p -= len;
    memcpy(*p, buf, len);

    return (int) len;
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int pk_write_ec_pubkey(unsigned char **p, unsigned char *start,
                              const pf_mbedtls_pk_context *pk)
{
    size_t len = 0;
    unsigned char buf[PK_MAX_EC_PUBLIC_KEY_SIZE];
    pf_mbedtls_ecp_keypair *ec = pf_mbedtls_pk_ec(*pk);
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (pf_mbedtls_pk_get_type(pk) == PF_MBEDTLS_PK_OPAQUE) {
        if (pf_psa_export_public_key(pk->priv_id, buf, sizeof(buf), &len) != PF_PSA_SUCCESS) {
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        }
        /* Ensure there's enough space in the provided buffer before copying data into it. */
        if (len > (size_t) (*p - start)) {
            return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        *p -= len;
        memcpy(*p, buf, len);
        return (int) len;
    } else
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    {
        if ((ret = pf_mbedtls_ecp_point_write_binary(&ec->grp, &ec->Q,
                                                  PF_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                  &len, buf, sizeof(buf))) != 0) {
            return ret;
        }
    }

    if (*p < start || (size_t) (*p - start) < len) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *p -= len;
    memcpy(*p, buf, len);

    return (int) len;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

/*
 * privateKey  OCTET STRING -- always of length ceil(log2(n)/8)
 */
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
static int pk_write_ec_private(unsigned char **p, unsigned char *start,
                               const pf_mbedtls_pk_context *pk)
{
    size_t byte_length;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tmp[PK_MAX_EC_KEY_PAIR_SIZE];
    pf_psa_status_t status;

    if (pf_mbedtls_pk_get_type(pk) == PF_MBEDTLS_PK_OPAQUE) {
        status = pf_psa_export_key(pk->priv_id, tmp, sizeof(tmp), &byte_length);
        if (status != PF_PSA_SUCCESS) {
            ret = PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
            return ret;
        }
    } else {
        status = pf_psa_export_key(pk->priv_id, tmp, sizeof(tmp), &byte_length);
        if (status != PF_PSA_SUCCESS) {
            ret = PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
            goto exit;
        }
    }

    ret = pf_mbedtls_asn1_write_octet_string(p, start, tmp, byte_length);
exit:
    pf_mbedtls_platform_zeroize(tmp, sizeof(tmp));
    return ret;
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int pk_write_ec_private(unsigned char **p, unsigned char *start,
                               const pf_mbedtls_pk_context *pk)
{
    size_t byte_length;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tmp[PK_MAX_EC_KEY_PAIR_SIZE];

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status;
    if (pf_mbedtls_pk_get_type(pk) == PF_MBEDTLS_PK_OPAQUE) {
        status = pf_psa_export_key(pk->priv_id, tmp, sizeof(tmp), &byte_length);
        if (status != PF_PSA_SUCCESS) {
            ret = PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
            return ret;
        }
    } else
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    {
        pf_mbedtls_ecp_keypair *ec = pf_mbedtls_pk_ec_rw(*pk);
        byte_length = (ec->grp.pbits + 7) / 8;

        ret = pf_mbedtls_ecp_write_key_ext(ec, &byte_length, tmp, sizeof(tmp));
        if (ret != 0) {
            goto exit;
        }
    }
    ret = pf_mbedtls_asn1_write_octet_string(p, start, tmp, byte_length);
exit:
    pf_mbedtls_platform_zeroize(tmp, sizeof(tmp));
    return ret;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

/*
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 * }
 */
static int pk_write_ec_param(unsigned char **p, unsigned char *start,
                             pf_mbedtls_ecp_group_id grp_id)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid;
    size_t oid_len;

    if ((ret = pf_mbedtls_oid_get_oid_by_ec_grp(grp_id, &oid, &oid_len)) != 0) {
        return ret;
    }

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_oid(p, start, oid, oid_len));

    return (int) len;
}

#if defined(PF_MBEDTLS_PK_HAVE_RFC8410_CURVES)
/*
 * RFC8410 section 7
 *
 * OneAsymmetricKey ::= SEQUENCE {
 *    version Version,
 *    privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *    privateKey PrivateKey,
 *    attributes [0] IMPLICIT Attributes OPTIONAL,
 *    ...,
 *    [[2: publicKey [1] IMPLICIT PublicKey OPTIONAL ]],
 *    ...
 * }
 * ...
 * CurvePrivateKey ::= OCTET STRING
 */
static int pk_write_ec_rfc8410_der(unsigned char **p, unsigned char *buf,
                                   const pf_mbedtls_pk_context *pk)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    size_t oid_len = 0;
    const char *oid;
    pf_mbedtls_ecp_group_id grp_id;

    /* privateKey */
    PF_MBEDTLS_ASN1_CHK_ADD(len, pk_write_ec_private(p, buf, pk));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(p, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(p, buf, PF_MBEDTLS_ASN1_OCTET_STRING));

    grp_id = pf_mbedtls_pk_get_ec_group_id(pk);
    /* privateKeyAlgorithm */
    if ((ret = pf_mbedtls_oid_get_oid_by_ec_grp_algid(grp_id, &oid, &oid_len)) != 0) {
        return ret;
    }
    PF_MBEDTLS_ASN1_CHK_ADD(len,
                         pf_mbedtls_asn1_write_algorithm_identifier_ext(p, buf, oid, oid_len, 0, 0));

    /* version */
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_int(p, buf, 0));

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(p, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(p, buf, PF_MBEDTLS_ASN1_CONSTRUCTED |
                                                     PF_MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}
#endif /* MBEDTLS_PK_HAVE_RFC8410_CURVES */

/*
 * RFC 5915, or SEC1 Appendix C.4
 *
 * ECPrivateKey ::= SEQUENCE {
 *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *      privateKey     OCTET STRING,
 *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *      publicKey  [1] BIT STRING OPTIONAL
 *    }
 */
static int pk_write_ec_der(unsigned char **p, unsigned char *buf,
                           const pf_mbedtls_pk_context *pk)
{
    size_t len = 0;
    int ret;
    size_t pub_len = 0, par_len = 0;
    pf_mbedtls_ecp_group_id grp_id;

    /* publicKey */
    PF_MBEDTLS_ASN1_CHK_ADD(pub_len, pk_write_ec_pubkey(p, buf, pk));

    if (*p - buf < 1) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    (*p)--;
    **p = 0;
    pub_len += 1;

    PF_MBEDTLS_ASN1_CHK_ADD(pub_len, pf_mbedtls_asn1_write_len(p, buf, pub_len));
    PF_MBEDTLS_ASN1_CHK_ADD(pub_len, pf_mbedtls_asn1_write_tag(p, buf, PF_MBEDTLS_ASN1_BIT_STRING));

    PF_MBEDTLS_ASN1_CHK_ADD(pub_len, pf_mbedtls_asn1_write_len(p, buf, pub_len));
    PF_MBEDTLS_ASN1_CHK_ADD(pub_len, pf_mbedtls_asn1_write_tag(p, buf,
                                                         PF_MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                         PF_MBEDTLS_ASN1_CONSTRUCTED | 1));
    len += pub_len;

    /* parameters */
    grp_id = pf_mbedtls_pk_get_ec_group_id(pk);
    PF_MBEDTLS_ASN1_CHK_ADD(par_len, pk_write_ec_param(p, buf, grp_id));
    PF_MBEDTLS_ASN1_CHK_ADD(par_len, pf_mbedtls_asn1_write_len(p, buf, par_len));
    PF_MBEDTLS_ASN1_CHK_ADD(par_len, pf_mbedtls_asn1_write_tag(p, buf,
                                                         PF_MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                         PF_MBEDTLS_ASN1_CONSTRUCTED | 0));
    len += par_len;

    /* privateKey */
    PF_MBEDTLS_ASN1_CHK_ADD(len, pk_write_ec_private(p, buf, pk));

    /* version */
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_int(p, buf, 1));

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(p, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(p, buf, PF_MBEDTLS_ASN1_CONSTRUCTED |
                                                     PF_MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

/******************************************************************************
 * Internal functions for Opaque keys.
 ******************************************************************************/
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static int pk_write_opaque_pubkey(unsigned char **p, unsigned char *start,
                                  const pf_mbedtls_pk_context *pk)
{
    size_t buffer_size;
    size_t len = 0;

    if (*p < start) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    buffer_size = (size_t) (*p - start);
    if (pf_psa_export_public_key(pk->priv_id, start, buffer_size,
                              &len) != PF_PSA_SUCCESS) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    *p -= len;
    memmove(*p, start, len);

    return (int) len;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

/******************************************************************************
 * Generic helpers
 ******************************************************************************/

/* Extend the public mbedtls_pk_get_type() by getting key type also in case of
 * opaque keys. */
static pf_mbedtls_pk_type_t pk_get_type_ext(const pf_mbedtls_pk_context *pk)
{
    pf_mbedtls_pk_type_t pk_type = pf_mbedtls_pk_get_type(pk);

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (pk_type == PF_MBEDTLS_PK_OPAQUE) {
        pf_psa_key_attributes_t opaque_attrs = PF_PSA_KEY_ATTRIBUTES_INIT;
        pf_psa_key_type_t opaque_key_type;

        if (pf_psa_get_key_attributes(pk->priv_id, &opaque_attrs) != PF_PSA_SUCCESS) {
            return PF_MBEDTLS_PK_NONE;
        }
        opaque_key_type = pf_psa_get_key_type(&opaque_attrs);
        pf_psa_reset_key_attributes(&opaque_attrs);

        if (PF_PSA_KEY_TYPE_IS_ECC(opaque_key_type)) {
            return PF_MBEDTLS_PK_ECKEY;
        } else if (PF_PSA_KEY_TYPE_IS_RSA(opaque_key_type)) {
            return PF_MBEDTLS_PK_RSA;
        } else {
            return PF_MBEDTLS_PK_NONE;
        }
    } else
#endif
    return pk_type;
}

/******************************************************************************
 * Public functions for writing private/public DER keys.
 ******************************************************************************/
int pf_mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start,
                            const pf_mbedtls_pk_context *key)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

#if defined(PF_MBEDTLS_RSA_C)
    if (pf_mbedtls_pk_get_type(key) == PF_MBEDTLS_PK_RSA) {
        PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_rsa_write_pubkey(pf_mbedtls_pk_rsa(*key), start, p));
    } else
#endif
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (pf_mbedtls_pk_get_type(key) == PF_MBEDTLS_PK_ECKEY) {
        PF_MBEDTLS_ASN1_CHK_ADD(len, pk_write_ec_pubkey(p, start, key));
    } else
#endif
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (pf_mbedtls_pk_get_type(key) == PF_MBEDTLS_PK_OPAQUE) {
        PF_MBEDTLS_ASN1_CHK_ADD(len, pk_write_opaque_pubkey(p, start, key));
    } else
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;

    return (int) len;
}

int pf_mbedtls_pk_write_pubkey_der(const pf_mbedtls_pk_context *key, unsigned char *buf, size_t size)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    int has_par = 1;
    size_t len = 0, par_len = 0, oid_len = 0;
    pf_mbedtls_pk_type_t pk_type;
    const char *oid = NULL;

    if (size == 0) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    c = buf + size;

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_pk_write_pubkey(&c, buf, key));

    if (c - buf < 1) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(&c, buf, PF_MBEDTLS_ASN1_BIT_STRING));

    pk_type = pk_get_type_ext(key);

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (pk_get_type_ext(key) == PF_MBEDTLS_PK_ECKEY) {
        pf_mbedtls_ecp_group_id ec_grp_id = pf_mbedtls_pk_get_ec_group_id(key);
        if (PF_MBEDTLS_PK_IS_RFC8410_GROUP_ID(ec_grp_id)) {
            ret = pf_mbedtls_oid_get_oid_by_ec_grp_algid(ec_grp_id, &oid, &oid_len);
            if (ret != 0) {
                return ret;
            }
            has_par = 0;
        } else {
            PF_MBEDTLS_ASN1_CHK_ADD(par_len, pk_write_ec_param(&c, buf, ec_grp_id));
        }
    }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

    /* At this point oid_len is not null only for EC Montgomery keys. */
    if (oid_len == 0) {
        ret = pf_mbedtls_oid_get_oid_by_pk_alg(pk_type, &oid, &oid_len);
        if (ret != 0) {
            return ret;
        }
    }

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_algorithm_identifier_ext(&c, buf, oid, oid_len,
                                                                          par_len, has_par));

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(&c, buf, PF_MBEDTLS_ASN1_CONSTRUCTED |
                                                     PF_MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int pf_mbedtls_pk_write_key_der(const pf_mbedtls_pk_context *key, unsigned char *buf, size_t size)
{
    unsigned char *c;

    if (size == 0) {
        return PF_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    c = buf + size;

#if defined(PF_MBEDTLS_RSA_C)
    if (pk_get_type_ext(key) == PF_MBEDTLS_PK_RSA) {
        return pk_write_rsa_der(&c, buf, key);
    } else
#endif /* MBEDTLS_RSA_C */
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (pk_get_type_ext(key) == PF_MBEDTLS_PK_ECKEY) {
#if defined(PF_MBEDTLS_PK_HAVE_RFC8410_CURVES)
        if (pf_mbedtls_pk_is_rfc8410(key)) {
            return pk_write_ec_rfc8410_der(&c, buf, key);
        }
#endif /* MBEDTLS_PK_HAVE_RFC8410_CURVES */
        return pk_write_ec_der(&c, buf, key);
    } else
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
    return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}

/******************************************************************************
 * Public functions for wrinting private/public PEM keys.
 ******************************************************************************/
#if defined(PF_MBEDTLS_PEM_WRITE_C)

#define PUB_DER_MAX_BYTES                                                   \
    (PF_MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES > PF_MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES ? \
     PF_MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES : PF_MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES)
#define PRV_DER_MAX_BYTES                                                   \
    (PF_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES > PF_MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES ? \
     PF_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES : PF_MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES)

int pf_mbedtls_pk_write_pubkey_pem(const pf_mbedtls_pk_context *key, unsigned char *buf, size_t size)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *output_buf = NULL;
    output_buf = pf_mbedtls_calloc(1, PUB_DER_MAX_BYTES);
    if (output_buf == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    size_t olen = 0;

    if ((ret = pf_mbedtls_pk_write_pubkey_der(key, output_buf,
                                           PUB_DER_MAX_BYTES)) < 0) {
        goto cleanup;
    }

    if ((ret = pf_mbedtls_pem_write_buffer(PEM_BEGIN_PUBLIC_KEY "\n", PEM_END_PUBLIC_KEY "\n",
                                        output_buf + PUB_DER_MAX_BYTES - ret,
                                        ret, buf, size, &olen)) != 0) {
        goto cleanup;
    }

    ret = 0;
cleanup:
    pf_mbedtls_free(output_buf);
    return ret;
}

int pf_mbedtls_pk_write_key_pem(const pf_mbedtls_pk_context *key, unsigned char *buf, size_t size)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *output_buf = NULL;
    output_buf = pf_mbedtls_calloc(1, PRV_DER_MAX_BYTES);
    if (output_buf == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    const char *begin, *end;
    size_t olen = 0;

    if ((ret = pf_mbedtls_pk_write_key_der(key, output_buf, PRV_DER_MAX_BYTES)) < 0) {
        goto cleanup;
    }

#if defined(PF_MBEDTLS_RSA_C)
    if (pk_get_type_ext(key) == PF_MBEDTLS_PK_RSA) {
        begin = PEM_BEGIN_PRIVATE_KEY_RSA "\n";
        end = PEM_END_PRIVATE_KEY_RSA "\n";
    } else
#endif
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (pk_get_type_ext(key) == PF_MBEDTLS_PK_ECKEY) {
        if (pf_mbedtls_pk_is_rfc8410(key)) {
            begin = PEM_BEGIN_PRIVATE_KEY_PKCS8 "\n";
            end = PEM_END_PRIVATE_KEY_PKCS8 "\n";
        } else {
            begin = PEM_BEGIN_PRIVATE_KEY_EC "\n";
            end = PEM_END_PRIVATE_KEY_EC "\n";
        }
    } else
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
    {
        ret = PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

    if ((ret = pf_mbedtls_pem_write_buffer(begin, end,
                                        output_buf + PRV_DER_MAX_BYTES - ret,
                                        ret, buf, size, &olen)) != 0) {
        goto cleanup;
    }

    ret = 0;
cleanup:
    pf_mbedtls_zeroize_and_free(output_buf, PRV_DER_MAX_BYTES);
    return ret;
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_PK_WRITE_C */
