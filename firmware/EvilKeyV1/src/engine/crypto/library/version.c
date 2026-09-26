#include "../../../pf_build_config.h"
/*
 *  Version information
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_VERSION_C)

#include "../include/mbedtls/version.h"
#include <string.h>

unsigned int pf_mbedtls_version_get_number(void)
{
    return PF_MBEDTLS_VERSION_NUMBER;
}

void pf_mbedtls_version_get_string(char *string)
{
    memcpy(string, PF_MBEDTLS_VERSION_STRING,
           sizeof(PF_MBEDTLS_VERSION_STRING));
}

void pf_mbedtls_version_get_string_full(char *string)
{
    memcpy(string, PF_MBEDTLS_VERSION_STRING_FULL,
           sizeof(PF_MBEDTLS_VERSION_STRING_FULL));
}

#endif /* MBEDTLS_VERSION_C */
