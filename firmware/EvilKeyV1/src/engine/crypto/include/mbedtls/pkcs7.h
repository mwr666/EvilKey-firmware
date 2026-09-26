/**
 * \file pkcs7.h
 *
 * \brief PKCS #7 generic defines and structures
 *  https://tools.ietf.org/html/rfc2315
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * Note: For the time being, this implementation of the PKCS #7 cryptographic
 * message syntax is a partial implementation of RFC 2315.
 * Differences include:
 *  - The RFC specifies 6 different content types. The only type currently
 *    supported in Mbed TLS is the signed-data content type.
 *  - The only supported PKCS #7 Signed Data syntax version is version 1
 *  - The RFC specifies support for BER. This implementation is limited to
 *    DER only.
 *  - The RFC specifies that multiple digest algorithms can be specified
 *    in the Signed Data type. Only one digest algorithm is supported in Mbed TLS.
 *  - The RFC specifies the Signed Data type can contain multiple X.509 or PKCS #6 extended
 *    certificates. In Mbed TLS, this list can only contain 0 or 1 certificates
 *    and they must be in X.509 format.
 *  - The RFC specifies the Signed Data type can contain
 *    certificate-revocation lists (CRLs). This implementation has no support
 *    for CRLs so it is assumed to be an empty list.
 *  - The RFC allows for SignerInfo structure to optionally contain
 *    unauthenticatedAttributes and authenticatedAttributes. In Mbed TLS it is
 *    assumed these fields are empty.
 *  - The RFC allows for the signed Data type to contain contentInfo. This
 *    implementation assumes the type is DATA and the content is empty.
 *  - The RFC doesn't put any constrain on the hash algorithm to be used, but
 *    this implementation by default rejects weak hash algorithms (i.e. RIPEMD160,
 *    MD5, SHA-1, SHA-224, SHA3-224). In general accepted hash algorithms
 *    are the ones belonging to ::mbedtls_x509_crt_profile_default.
 *    #MBEDTLS_PKCS7_ALLOW_WEAK_SIGNATURES can be enabled to accept all
 *    supported hash algorithms.
 */

#ifndef PF_MBEDTLS_PKCS7_H
#define PF_MBEDTLS_PKCS7_H

#include "private_access.h"

#include "build_info.h"

#include "asn1.h"
#include "x509_crt.h"

/**
 * \name PKCS #7 Module Error codes
 * \{
 */
#define PF_MBEDTLS_ERR_PKCS7_INVALID_FORMAT                   -0x5300  /**< The format is invalid, e.g. different type expected. */
#define PF_MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE              -0x5380  /**< Unavailable feature, e.g. anything other than signed data. */
#define PF_MBEDTLS_ERR_PKCS7_INVALID_VERSION                  -0x5400  /**< The PKCS #7 version element is invalid or cannot be parsed. */
#define PF_MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO             -0x5480  /**< The PKCS #7 content info is invalid or cannot be parsed. */
#define PF_MBEDTLS_ERR_PKCS7_INVALID_ALG                      -0x5500  /**< The algorithm tag or value is invalid or cannot be parsed. */
#define PF_MBEDTLS_ERR_PKCS7_INVALID_CERT                     -0x5580  /**< The certificate tag or value is invalid or cannot be parsed. */
#define PF_MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE                -0x5600  /**< Error parsing the signature */
#define PF_MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO              -0x5680  /**< Error parsing the signer's info */
#define PF_MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA                   -0x5700  /**< Input invalid. */
#define PF_MBEDTLS_ERR_PKCS7_ALLOC_FAILED                     -0x5780  /**< Allocation of memory failed. */
#define PF_MBEDTLS_ERR_PKCS7_VERIFY_FAIL                      -0x5800  /**< Verification Failed */
#define PF_MBEDTLS_ERR_PKCS7_CERT_DATE_INVALID                -0x5880  /**< The PKCS #7 date issued/expired dates are invalid */
/* \} name */

/**
 * \name PKCS #7 Supported Version
 * \{
 */
#define PF_MBEDTLS_PKCS7_SUPPORTED_VERSION                           0x01
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type-length-value structure that allows for ASN.1 using DER.
 */
typedef pf_mbedtls_asn1_buf pf_mbedtls_pkcs7_buf;

/**
 * Container for ASN.1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef pf_mbedtls_asn1_named_data pf_mbedtls_pkcs7_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef pf_mbedtls_asn1_sequence pf_mbedtls_pkcs7_sequence;

/**
 * PKCS #7 types
 */
typedef enum {
    PF_MBEDTLS_PKCS7_NONE=0,
    PF_MBEDTLS_PKCS7_DATA,
    PF_MBEDTLS_PKCS7_SIGNED_DATA,
    PF_MBEDTLS_PKCS7_ENVELOPED_DATA,
    PF_MBEDTLS_PKCS7_SIGNED_AND_ENVELOPED_DATA,
    PF_MBEDTLS_PKCS7_DIGESTED_DATA,
    PF_MBEDTLS_PKCS7_ENCRYPTED_DATA,
}
pf_mbedtls_pkcs7_type;

/**
 * Structure holding PKCS #7 signer info
 */
typedef struct pf_mbedtls_pkcs7_signer_info {
    int PF_MBEDTLS_PRIVATE(version);
    pf_mbedtls_x509_buf PF_MBEDTLS_PRIVATE(serial);
    pf_mbedtls_x509_name PF_MBEDTLS_PRIVATE(issuer);
    pf_mbedtls_x509_buf PF_MBEDTLS_PRIVATE(issuer_raw);
    pf_mbedtls_x509_buf PF_MBEDTLS_PRIVATE(alg_identifier);
    pf_mbedtls_x509_buf PF_MBEDTLS_PRIVATE(sig_alg_identifier);
    pf_mbedtls_x509_buf PF_MBEDTLS_PRIVATE(sig);
    struct pf_mbedtls_pkcs7_signer_info *PF_MBEDTLS_PRIVATE(next);
}
pf_mbedtls_pkcs7_signer_info;

/**
 * Structure holding the signed data section
 */
typedef struct pf_mbedtls_pkcs7_signed_data {
    int PF_MBEDTLS_PRIVATE(version);
    pf_mbedtls_pkcs7_buf PF_MBEDTLS_PRIVATE(digest_alg_identifiers);
    int PF_MBEDTLS_PRIVATE(no_of_certs);
    pf_mbedtls_x509_crt PF_MBEDTLS_PRIVATE(certs);
    int PF_MBEDTLS_PRIVATE(no_of_crls);
    pf_mbedtls_x509_crl PF_MBEDTLS_PRIVATE(crl);
    int PF_MBEDTLS_PRIVATE(no_of_signers);
    pf_mbedtls_pkcs7_signer_info PF_MBEDTLS_PRIVATE(signers);
}
pf_mbedtls_pkcs7_signed_data;

/**
 * Structure holding PKCS #7 structure, only signed data for now
 */
typedef struct pf_mbedtls_pkcs7 {
    pf_mbedtls_pkcs7_buf PF_MBEDTLS_PRIVATE(raw);
    pf_mbedtls_pkcs7_signed_data PF_MBEDTLS_PRIVATE(signed_data);
}
pf_mbedtls_pkcs7;

/**
 * \brief          Initialize mbedtls_pkcs7 structure.
 *
 * \param pkcs7    mbedtls_pkcs7 structure.
 */
void pf_mbedtls_pkcs7_init(pf_mbedtls_pkcs7 *pkcs7);

/**
 * \brief          Parse a single DER formatted PKCS #7 detached signature.
 *
 * \param pkcs7    The mbedtls_pkcs7 structure to be filled by the parser.
 * \param buf      The buffer holding only the DER encoded PKCS #7 content.
 * \param buflen   The size in bytes of \p buf. The size must be exactly the
 *                 length of the DER encoded PKCS #7 content.
 *
 * \note           This function makes an internal copy of the PKCS #7 buffer
 *                 \p buf. In particular, \p buf may be destroyed or reused
 *                 after this call returns.
 * \note           Signatures with internal data are not supported.
 *
 * \return         The \c mbedtls_pkcs7_type of \p buf, if successful.
 * \return         A negative error code on failure.
 */
int pf_mbedtls_pkcs7_parse_der(pf_mbedtls_pkcs7 *pkcs7, const unsigned char *buf,
                            const size_t buflen);

/**
 * \brief          Verification of PKCS #7 signature against a caller-supplied
 *                 certificate.
 *
 *                 For each signer in the PKCS structure, this function computes
 *                 a signature over the supplied data, using the supplied
 *                 certificate and the same digest algorithm as specified by the
 *                 signer. It then compares this signature against the
 *                 signer's signature; verification succeeds if any comparison
 *                 matches.
 *
 *                 This function does not use the certificates held within the
 *                 PKCS #7 structure itself, and does not check that the
 *                 certificate is signed by a trusted certification authority.
 *
 * \param pkcs7    mbedtls_pkcs7 structure containing signature.
 * \param cert     Certificate containing key to verify signature.
 * \param data     Plain data on which signature has to be verified.
 * \param datalen  Length of the data.
 *
 * \note           This function internally calculates the hash on the supplied
 *                 plain data for signature verification.
 *
 * \note           For limitation on the supported hash algorithms, please refer
 *                 to the note at the top of this document.
 *
 * \return         0 if the signature verifies, or a negative error code on failure.
 */
int pf_mbedtls_pkcs7_signed_data_verify(pf_mbedtls_pkcs7 *pkcs7,
                                     const pf_mbedtls_x509_crt *cert,
                                     const unsigned char *data,
                                     size_t datalen);

/**
 * \brief          Verification of PKCS #7 signature against a caller-supplied
 *                 certificate.
 *
 *                 For each signer in the PKCS structure, this function
 *                 validates a signature over the supplied hash, using the
 *                 supplied certificate and the same digest algorithm as
 *                 specified by the signer. Verification succeeds if any
 *                 signature is good.
 *
 *                 This function does not use the certificates held within the
 *                 PKCS #7 structure itself, and does not check that the
 *                 certificate is signed by a trusted certification authority.
 *
 * \param pkcs7    PKCS #7 structure containing signature.
 * \param cert     Certificate containing key to verify signature.
 * \param hash     Hash of the plain data on which signature has to be verified.
 * \param hashlen  Length of the hash.
 *
 * \note           This function is different from mbedtls_pkcs7_signed_data_verify()
 *                 in that it is directly passed the hash of the data.
 *
 * \note           For limitation on the supported hash algorithms, please refer
 *                 to the note at the top of this document.
 *
 * \return         0 if the signature verifies, or a negative error code on failure.
 */
int pf_mbedtls_pkcs7_signed_hash_verify(pf_mbedtls_pkcs7 *pkcs7,
                                     const pf_mbedtls_x509_crt *cert,
                                     const unsigned char *hash, size_t hashlen);

/**
 * \brief          Unallocate all PKCS #7 data and zeroize the memory.
 *                 It doesn't free \p pkcs7 itself. This should be done by the caller.
 *
 * \param pkcs7    mbedtls_pkcs7 structure to free.
 */
void pf_mbedtls_pkcs7_free(pf_mbedtls_pkcs7 *pkcs7);

#ifdef __cplusplus
}
#endif

#endif /* pkcs7.h */
