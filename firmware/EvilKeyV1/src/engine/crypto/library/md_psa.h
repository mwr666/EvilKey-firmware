/**
 * Translation between MD and PSA identifiers (algorithms, errors).
 *
 *  Note: this internal module will go away when everything becomes based on
 *  PSA Crypto; it is a helper for the transition period.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_MD_PSA_H
#define PF_MBEDTLS_MD_PSA_H

#include "common.h"

#include "../include/mbedtls/md.h"
#include "../include/psa/crypto.h"

/** Convert PSA status to MD error code.
 *
 * \param status    PSA status.
 *
 * \return          The corresponding MD error code,
 */
int pf_mbedtls_md_error_from_psa(pf_psa_status_t status);

#endif /* MBEDTLS_MD_PSA_H */
