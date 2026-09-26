/**
 * \file mbedtls/config_psa.h
 * \brief PSA crypto configuration options (set of defines)
 *
 *  This set of compile-time options takes settings defined in
 *  include/mbedtls/mbedtls_config.h and include/psa/crypto_config.h and uses
 *  those definitions to define symbols used in the library code.
 *
 *  Users and integrators should not edit this file, please edit
 *  include/mbedtls/mbedtls_config.h for MBEDTLS_XXX settings or
 *  include/psa/crypto_config.h for PSA_WANT_XXX settings.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_MBEDTLS_CONFIG_PSA_H
#define PF_MBEDTLS_CONFIG_PSA_H

#include "../psa/crypto_legacy.h"

#include "../psa/crypto_adjust_config_synonyms.h"

#include "../psa/crypto_adjust_config_dependencies.h"

#include "config_adjust_psa_superset_legacy.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_CONFIG)

/* Require built-in implementations based on PSA requirements */

/* We need this to have a complete list of requirements
 * before we deduce what built-ins are required. */
#include "../psa/crypto_adjust_config_key_pair_types.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_C)
/* If we are implementing PSA crypto ourselves, then we want to enable the
 * required built-ins. Otherwise, PSA features will be provided by the server. */
#include "config_adjust_legacy_from_psa.h"
#endif

#else /* MBEDTLS_PSA_CRYPTO_CONFIG */

/* Infer PSA requirements from Mbed TLS capabilities */

#include "config_adjust_psa_from_legacy.h"

/* Hopefully the file above will have enabled keypair symbols in a consistent
 * way, but including this here fixes them if that wasn't the case. */
#include "../psa/crypto_adjust_config_key_pair_types.h"

#endif /* MBEDTLS_PSA_CRYPTO_CONFIG */

#if defined(PF_PSA_WANT_ALG_JPAKE)
#define PF_PSA_WANT_ALG_SOME_PAKE 1
#endif

#include "../psa/crypto_adjust_auto_enabled.h"

#endif /* MBEDTLS_CONFIG_PSA_H */
