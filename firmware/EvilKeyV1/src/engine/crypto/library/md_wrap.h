/**
 * \file md_wrap.h
 *
 * \brief Message digest wrappers.
 *
 * \warning This in an internal header. Do not include directly.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_MD_WRAP_H
#define PF_MBEDTLS_MD_WRAP_H

#include "../include/mbedtls/build_info.h"

#include "../include/mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
struct pf_mbedtls_md_info_t {
    /** Digest identifier */
    pf_mbedtls_md_type_t type;

    /** Output length of the digest function in bytes */
    unsigned char size;

#if defined(PF_MBEDTLS_MD_C)
    /** Block length of the digest function in bytes */
    unsigned char block_size;
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MD_WRAP_H */
