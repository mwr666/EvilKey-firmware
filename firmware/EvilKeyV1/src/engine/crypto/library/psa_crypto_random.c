#include "../../../pf_build_config.h"
/*
 *  PSA crypto random generator.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_C) && !defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

#include "psa_crypto_core.h"
#include "psa_crypto_random.h"
#include "psa_crypto_random_impl.h"
#include "threading_internal.h"

#if defined(PF_MBEDTLS_PSA_INJECT_ENTROPY)
#include "entropy_poll.h"
#endif

#if defined(PF_MBEDTLS_PLATFORM_IS_UNIXLIKE)
/* For getpid(), for fork protection */
#include <unistd.h>
#if defined(PF_MBEDTLS_HAVE_TIME)
#include "../include/mbedtls/platform_time.h"
#else
/* For gettimeofday(), for fork protection without actual entropy */
#include <sys/time.h>
#endif
#endif

void pf_psa_random_internal_init(pf_mbedtls_psa_random_context_t *rng)
{
    /* Set default configuration if
     * mbedtls_psa_crypto_configure_entropy_sources() hasn't been called. */
    if (rng->entropy_init == NULL) {
        rng->entropy_init = pf_mbedtls_entropy_init;
    }
    if (rng->entropy_free == NULL) {
        rng->entropy_free = pf_mbedtls_entropy_free;
    }

    rng->entropy_init(&rng->entropy);
#if defined(PF_MBEDTLS_PSA_INJECT_ENTROPY) && \
    defined(PF_MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
    /* The PSA entropy injection feature depends on using NV seed as an entropy
     * source. Add NV seed as an entropy source for PSA entropy injection. */
    pf_mbedtls_entropy_add_source(&rng->entropy,
                               pf_mbedtls_nv_seed_poll, NULL,
                               PF_MBEDTLS_ENTROPY_BLOCK_SIZE,
                               PF_MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif

    pf_mbedtls_psa_drbg_init(&rng->drbg);
}

void pf_psa_random_internal_free(pf_mbedtls_psa_random_context_t *rng)
{
    pf_mbedtls_psa_drbg_free(&rng->drbg);
    rng->entropy_free(&rng->entropy);
}
pf_psa_status_t pf_psa_random_internal_seed(pf_mbedtls_psa_random_context_t *rng)
{
    const unsigned char drbg_seed[] = "PSA";
    int ret = pf_mbedtls_psa_drbg_seed(&rng->drbg, &rng->entropy,
                                    drbg_seed, sizeof(drbg_seed) - 1);
#if defined(PF_MBEDTLS_PLATFORM_IS_UNIXLIKE)
    rng->pid = getpid();
#endif
    return pf_mbedtls_to_psa_error(ret);
}

#if defined(PF_MBEDTLS_PLATFORM_IS_UNIXLIKE)
static pf_psa_status_t pf_psa_random_internal_reseed_child(
    pf_mbedtls_psa_random_context_t *rng,
    intmax_t pid)
{
    /* Reseeding from actual entropy gives the child a unique RNG state
     * which the parent process cannot predict, and wipes the
     * parent's RNG state from the child.
     *
     * However, in some library configurations, there is no actual
     * entropy source, only a nonvolatile seed (MBEDTLS_ENTROPY_NV_SEED
     * enabled and no actual entropy source enabled). In such a
     * configuration, the reseed operation is deterministic and
     * always injects the same content, so with the DRBG reseed
     * process alone, for example, two child processes forked in
     * close sequence would end up with the same RNG state.

     * To avoid this, we use a personalization string that has a high
     * likelihood of being unique. This way, the child has a unique state.
     * The parent can predict the child's RNG state until the next time
     * it reseeds or generates some random output, but that's
     * unavoidable in the absence of actual entropy.
     */
    struct {
        /* Using the PID mostly guarantees that each child gets a
         * unique state. */
        /* Use intmax_t, not pid_t, because some Unix-like platforms
         * don't define pid_t, or more likely nowadays they define
         * pid_t but only with certain platform macros which might not
         * be the exact ones we use. In practice, this only costs
         * a couple of instructions to pass and compare two words
         * rather than one.
         */
        intmax_t pid;
        /* In case an old child had died and its PID is reused for
         * a new child of the same process, also include the time. */
#if defined(PF_MBEDTLS_HAVE_TIME)
        pf_mbedtls_ms_time_t now;
#else
        struct timeval now;
#endif
    } perso;
    memset(&perso, 0, sizeof(perso));
    perso.pid = pid;
#if defined(PF_MBEDTLS_HAVE_TIME)
    perso.now = pf_mbedtls_ms_time();
#else
    /* We don't have mbedtls_ms_time(), but the platform has getpid().
     * Use gettimeofday(), which is a classic Unix function. Modern POSIX
     * has stopped requiring gettimeofday() (in favor of clock_gettime()),
     * but this is fallback code for restricted configurations, so it's
     * more likely to be used on embedded platforms that only have a subset
     * of Unix APIs and are more likely to have the classic gettimeofday(). */
    if (gettimeofday(&perso.now, NULL) == -1) {
        return PF_PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
#endif
    int ret = pf_mbedtls_psa_drbg_reseed(&rng->drbg,
                                      (unsigned char *) &perso, sizeof(perso));
    return pf_mbedtls_to_psa_error(ret);
}
#endif /* MBEDTLS_PLATFORM_IS_UNIXLIKE */

pf_psa_status_t pf_psa_random_internal_generate(
    pf_mbedtls_psa_random_context_t *rng,
    uint8_t *output, size_t output_size)
{
#if defined(PF_MBEDTLS_PLATFORM_IS_UNIXLIKE)
    intmax_t pid = getpid();
    if (pid != rng->pid) {
        /* This is a (grand...)child of the original process, but
         * we inherited the RNG state from our parent. We must reseed! */
#if defined(PF_MBEDTLS_THREADING_C)
        pf_mbedtls_mutex_lock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */
        pf_psa_status_t status = pf_psa_random_internal_reseed_child(rng, pid);
        if (status == PF_PSA_SUCCESS) {
            rng->pid = pid;
        }
#if defined(PF_MBEDTLS_THREADING_C)
        pf_mbedtls_mutex_unlock(&pf_mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
    }
#endif /* MBEDTLS_PLATFORM_IS_UNIXLIKE */

    while (output_size > 0) {
        size_t request_size =
            (output_size > PF_MBEDTLS_PSA_RANDOM_MAX_REQUEST ?
             PF_MBEDTLS_PSA_RANDOM_MAX_REQUEST :
             output_size);
#if defined(PF_MBEDTLS_CTR_DRBG_C)
        int ret = pf_mbedtls_ctr_drbg_random(&rng->drbg, output, request_size);
#elif defined(PF_MBEDTLS_HMAC_DRBG_C)
        int ret = pf_mbedtls_hmac_drbg_random(&rng->drbg, output, request_size);
#endif /* !MBEDTLS_CTR_DRBG_C && !MBEDTLS_HMAC_DRBG_C */
        if (ret != 0) {
            return pf_mbedtls_to_psa_error(ret);
        }
        output_size -= request_size;
        output += request_size;
    }
    return PF_PSA_SUCCESS;
}

#endif /* MBEDTLS_PSA_CRYPTO_C && !MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
