#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stddef.h>
#include "../sdk/src/rng/random.h"
#include "../sdk/src/byte_array.h"
/* The existing Pico Keys RNG is initialized before crypto/NVS provisioning.
 * Do not use Arduino random() as a cryptographic entropy source.
 */
int pf_mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data;
    if (!output || !olen) return -1;
    random_fill_buffer(BYTE_ARRAY(output,len));
    *olen=len;
    return 0;
}
