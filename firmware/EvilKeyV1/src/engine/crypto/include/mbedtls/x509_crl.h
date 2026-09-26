/**
 * \file x509_crl.h
 *
 * \brief X.509 certificate revocation list parsing
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_X509_CRL_H
#define PF_MBEDTLS_X509_CRL_H
#include "private_access.h"

#include "build_info.h"

#include "x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures and functions for parsing CRLs
 * \{
 */

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct pf_mbedtls_x509_crl_entry {
    /** Direct access to the whole entry inside the containing buffer. */
    pf_mbedtls_x509_buf raw;
    /** The serial number of the revoked certificate. */
    pf_mbedtls_x509_buf serial;
    /** The revocation date of this entry. */
    pf_mbedtls_x509_time revocation_date;
    /** Direct access to the list of CRL entry extensions
     * (an ASN.1 constructed sequence).
     *
     * If there are no extensions, `entry_ext.len == 0` and
     * `entry_ext.p == NULL`. */
    pf_mbedtls_x509_buf entry_ext;

    /** Next element in the linked list of entries.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct pf_mbedtls_x509_crl_entry *next;
}
pf_mbedtls_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct pf_mbedtls_x509_crl {
    pf_mbedtls_x509_buf raw;           /**< The raw certificate data (DER). */
    pf_mbedtls_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;            /**< CRL version (1=v1, 2=v2) */
    pf_mbedtls_x509_buf sig_oid;       /**< CRL signature type identifier */

    pf_mbedtls_x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    pf_mbedtls_x509_name issuer;       /**< The parsed issuer data (named information object). */

    pf_mbedtls_x509_time this_update;
    pf_mbedtls_x509_time next_update;

    pf_mbedtls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    pf_mbedtls_x509_buf crl_ext;

    pf_mbedtls_x509_buf PF_MBEDTLS_PRIVATE(sig_oid2);
    pf_mbedtls_x509_buf PF_MBEDTLS_PRIVATE(sig);
    pf_mbedtls_md_type_t PF_MBEDTLS_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    pf_mbedtls_pk_type_t PF_MBEDTLS_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *PF_MBEDTLS_PRIVATE(sig_opts);             /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next element in the linked list of CRL.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct pf_mbedtls_x509_crl *next;
}
pf_mbedtls_x509_crl;

/**
 * \brief          Parse a DER-encoded CRL and append it to the chained list
 *
 * \note           If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int pf_mbedtls_x509_crl_parse_der(pf_mbedtls_x509_crl *chain,
                               const unsigned char *buf, size_t buflen);
/**
 * \brief          Parse one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \note           If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in PEM or DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int pf_mbedtls_x509_crl_parse(pf_mbedtls_x509_crl *chain, const unsigned char *buf, size_t buflen);

#if defined(PF_MBEDTLS_FS_IO)
/**
 * \brief          Load one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \note           If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the CRLs from (in PEM or DER encoding)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int pf_mbedtls_x509_crl_parse_file(pf_mbedtls_x509_crl *chain, const char *path);
#endif /* MBEDTLS_FS_IO */

#if !defined(PF_MBEDTLS_X509_REMOVE_INFO)
/**
 * \brief          Returns an informational string about the CRL.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crl      The X509 CRL to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int pf_mbedtls_x509_crl_info(char *buf, size_t size, const char *prefix,
                          const pf_mbedtls_x509_crl *crl);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

/**
 * \brief          Initialize a CRL (chain)
 *
 * \param crl      CRL chain to initialize
 */
void pf_mbedtls_x509_crl_init(pf_mbedtls_x509_crl *crl);

/**
 * \brief          Unallocate all CRL data
 *
 * \param crl      CRL chain to free
 */
void pf_mbedtls_x509_crl_free(pf_mbedtls_x509_crl *crl);

/** \} name Structures and functions for parsing CRLs */
/** \} addtogroup x509_module */

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_x509_crl.h */
