/**
 * \file compat-2.x.h
 *
 * \brief Compatibility definitions
 *
 * \deprecated Use the new names directly instead
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if defined(PF_MBEDTLS_DEPRECATED_WARNING)
#warning "Including compat-2.x.h is deprecated"
#endif

#ifndef PF_MBEDTLS_COMPAT2X_H
#define PF_MBEDTLS_COMPAT2X_H

/*
 * Macros for renamed functions
 */
#define pf_mbedtls_ctr_drbg_update_ret   pf_mbedtls_ctr_drbg_update
#define pf_mbedtls_hmac_drbg_update_ret  pf_mbedtls_hmac_drbg_update
#define pf_mbedtls_md5_starts_ret        pf_mbedtls_md5_starts
#define pf_mbedtls_md5_update_ret        pf_mbedtls_md5_update
#define pf_mbedtls_md5_finish_ret        pf_mbedtls_md5_finish
#define pf_mbedtls_md5_ret               pf_mbedtls_md5
#define pf_mbedtls_ripemd160_starts_ret  pf_mbedtls_ripemd160_starts
#define pf_mbedtls_ripemd160_update_ret  pf_mbedtls_ripemd160_update
#define pf_mbedtls_ripemd160_finish_ret  pf_mbedtls_ripemd160_finish
#define pf_mbedtls_ripemd160_ret         pf_mbedtls_ripemd160
#define pf_mbedtls_sha1_starts_ret       pf_mbedtls_sha1_starts
#define pf_mbedtls_sha1_update_ret       pf_mbedtls_sha1_update
#define pf_mbedtls_sha1_finish_ret       pf_mbedtls_sha1_finish
#define pf_mbedtls_sha1_ret              pf_mbedtls_sha1
#define pf_mbedtls_sha256_starts_ret     pf_mbedtls_sha256_starts
#define pf_mbedtls_sha256_update_ret     pf_mbedtls_sha256_update
#define pf_mbedtls_sha256_finish_ret     pf_mbedtls_sha256_finish
#define pf_mbedtls_sha256_ret            pf_mbedtls_sha256
#define pf_mbedtls_sha512_starts_ret     pf_mbedtls_sha512_starts
#define pf_mbedtls_sha512_update_ret     pf_mbedtls_sha512_update
#define pf_mbedtls_sha512_finish_ret     pf_mbedtls_sha512_finish
#define pf_mbedtls_sha512_ret            pf_mbedtls_sha512

#endif /* MBEDTLS_COMPAT2X_H */
