#include "../../../pf_build_config.h"
/*
 *  Entropy accumulator implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_ENTROPY_C)

#include "../include/mbedtls/entropy.h"
#include "entropy_poll.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"

#include <string.h>

#if defined(PF_MBEDTLS_FS_IO)
#include <stdio.h>
#endif

#include "../include/mbedtls/platform.h"

#define ENTROPY_MAX_LOOP    256     /**< Maximum amount to loop before error */

void pf_mbedtls_entropy_init(pf_mbedtls_entropy_context *ctx)
{
    ctx->source_count = 0;
    memset(ctx->source, 0, sizeof(ctx->source));

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_init(&ctx->mutex);
#endif

    ctx->accumulator_started = 0;
    pf_mbedtls_md_init(&ctx->accumulator);

    /* Reminder: Update ENTROPY_HAVE_STRONG in the test files
     *           when adding more strong entropy sources here. */

#if !defined(PF_MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
#if !defined(PF_MBEDTLS_NO_PLATFORM_ENTROPY)
    pf_mbedtls_entropy_add_source(ctx, pf_mbedtls_platform_entropy_poll, NULL,
                               PF_MBEDTLS_ENTROPY_MIN_PLATFORM,
                               PF_MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif
#if defined(PF_MBEDTLS_ENTROPY_HARDWARE_ALT)
    pf_mbedtls_entropy_add_source(ctx, pf_mbedtls_hardware_poll, NULL,
                               PF_MBEDTLS_ENTROPY_MIN_HARDWARE,
                               PF_MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif
#if defined(PF_MBEDTLS_ENTROPY_NV_SEED)
    pf_mbedtls_entropy_add_source(ctx, pf_mbedtls_nv_seed_poll, NULL,
                               PF_MBEDTLS_ENTROPY_BLOCK_SIZE,
                               PF_MBEDTLS_ENTROPY_SOURCE_STRONG);
    ctx->initial_entropy_run = 0;
#endif
#endif /* MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES */
}

void pf_mbedtls_entropy_free(pf_mbedtls_entropy_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* If the context was already free, don't call free() again.
     * This is important for mutexes which don't allow double-free. */
    if (ctx->accumulator_started == -1) {
        return;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_free(&ctx->mutex);
#endif
    pf_mbedtls_md_free(&ctx->accumulator);
#if defined(PF_MBEDTLS_ENTROPY_NV_SEED)
    ctx->initial_entropy_run = 0;
#endif
    ctx->source_count = 0;
    pf_mbedtls_platform_zeroize(ctx->source, sizeof(ctx->source));
    ctx->accumulator_started = -1;
}

int pf_mbedtls_entropy_add_source(pf_mbedtls_entropy_context *ctx,
                               pf_mbedtls_entropy_f_source_ptr f_source, void *p_source,
                               size_t threshold, int strong)
{
    int idx, ret = 0;

#if defined(PF_MBEDTLS_THREADING_C)
    if ((ret = pf_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    idx = ctx->source_count;
    if (idx >= PF_MBEDTLS_ENTROPY_MAX_SOURCES) {
        ret = PF_MBEDTLS_ERR_ENTROPY_MAX_SOURCES;
        goto exit;
    }

    ctx->source[idx].f_source  = f_source;
    ctx->source[idx].p_source  = p_source;
    ctx->source[idx].threshold = threshold;
    ctx->source[idx].strong    = strong;

    ctx->source_count++;

exit:
#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return PF_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

/*
 * Entropy accumulator update
 */
static int entropy_update(pf_mbedtls_entropy_context *ctx, unsigned char source_id,
                          const unsigned char *data, size_t len)
{
    unsigned char header[2];
    unsigned char tmp[PF_MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = len;
    const unsigned char *p = data;
    int ret = 0;

    if (use_len > PF_MBEDTLS_ENTROPY_BLOCK_SIZE) {
        if ((ret = pf_mbedtls_md(pf_mbedtls_md_info_from_type(PF_MBEDTLS_ENTROPY_MD),
                              data, len, tmp)) != 0) {
            goto cleanup;
        }
        p = tmp;
        use_len = PF_MBEDTLS_ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = use_len & 0xFF;

    /*
     * Start the accumulator if this has not already happened. Note that
     * it is sufficient to start the accumulator here only because all calls to
     * gather entropy eventually execute this code.
     */
    if (ctx->accumulator_started == 0) {
        ret = pf_mbedtls_md_setup(&ctx->accumulator,
                               pf_mbedtls_md_info_from_type(PF_MBEDTLS_ENTROPY_MD), 0);
        if (ret != 0) {
            goto cleanup;
        }
        ret = pf_mbedtls_md_starts(&ctx->accumulator);
        if (ret != 0) {
            goto cleanup;
        }
        ctx->accumulator_started = 1;
    }
    if ((ret = pf_mbedtls_md_update(&ctx->accumulator, header, 2)) != 0) {
        goto cleanup;
    }
    ret = pf_mbedtls_md_update(&ctx->accumulator, p, use_len);

cleanup:
    pf_mbedtls_platform_zeroize(tmp, sizeof(tmp));

    return ret;
}

int pf_mbedtls_entropy_update_manual(pf_mbedtls_entropy_context *ctx,
                                  const unsigned char *data, size_t len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(PF_MBEDTLS_THREADING_C)
    if ((ret = pf_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    ret = entropy_update(ctx, PF_MBEDTLS_ENTROPY_SOURCE_MANUAL, data, len);

#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return PF_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

/*
 * Run through the different sources to add entropy to our accumulator
 */
static int entropy_gather_internal(pf_mbedtls_entropy_context *ctx)
{
    int ret = PF_MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    int i;
    int have_one_strong = 0;
    unsigned char buf[PF_MBEDTLS_ENTROPY_MAX_GATHER];
    size_t olen;

    if (ctx->source_count == 0) {
        return PF_MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED;
    }

    /*
     * Run through our entropy sources
     */
    for (i = 0; i < ctx->source_count; i++) {
        if (ctx->source[i].strong == PF_MBEDTLS_ENTROPY_SOURCE_STRONG) {
            have_one_strong = 1;
        }

        olen = 0;
        if ((ret = ctx->source[i].f_source(ctx->source[i].p_source,
                                           buf, PF_MBEDTLS_ENTROPY_MAX_GATHER, &olen)) != 0) {
            goto cleanup;
        }

        /*
         * Add if we actually gathered something
         */
        if (olen > 0) {
            if ((ret = entropy_update(ctx, (unsigned char) i,
                                      buf, olen)) != 0) {
                return ret;
            }
            ctx->source[i].size += olen;
        }
    }

    if (have_one_strong == 0) {
        ret = PF_MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE;
    }

cleanup:
    pf_mbedtls_platform_zeroize(buf, sizeof(buf));

    return ret;
}

/*
 * Thread-safe wrapper for entropy_gather_internal()
 */
int pf_mbedtls_entropy_gather(pf_mbedtls_entropy_context *ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(PF_MBEDTLS_THREADING_C)
    if ((ret = pf_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    ret = entropy_gather_internal(ctx);

#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return PF_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

int pf_mbedtls_entropy_func(void *data, unsigned char *output, size_t len)
{
    int ret, count = 0, i, thresholds_reached;
    size_t strong_size;
    pf_mbedtls_entropy_context *ctx = (pf_mbedtls_entropy_context *) data;
    unsigned char buf[PF_MBEDTLS_ENTROPY_BLOCK_SIZE];

    if (len > PF_MBEDTLS_ENTROPY_BLOCK_SIZE) {
        return PF_MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

#if defined(PF_MBEDTLS_ENTROPY_NV_SEED)
    /* Update the NV entropy seed before generating any entropy for outside
     * use.
     */
    if (ctx->initial_entropy_run == 0) {
        ctx->initial_entropy_run = 1;
        if ((ret = pf_mbedtls_entropy_update_nv_seed(ctx)) != 0) {
            return ret;
        }
    }
#endif

#if defined(PF_MBEDTLS_THREADING_C)
    if ((ret = pf_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    /*
     * Always gather extra entropy before a call
     */
    do {
        if (count++ > ENTROPY_MAX_LOOP) {
            ret = PF_MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
            goto exit;
        }

        if ((ret = entropy_gather_internal(ctx)) != 0) {
            goto exit;
        }

        thresholds_reached = 1;
        strong_size = 0;
        for (i = 0; i < ctx->source_count; i++) {
            if (ctx->source[i].size < ctx->source[i].threshold) {
                thresholds_reached = 0;
            }
            if (ctx->source[i].strong == PF_MBEDTLS_ENTROPY_SOURCE_STRONG) {
                strong_size += ctx->source[i].size;
            }
        }
    } while (!thresholds_reached || strong_size < PF_MBEDTLS_ENTROPY_BLOCK_SIZE);

    memset(buf, 0, PF_MBEDTLS_ENTROPY_BLOCK_SIZE);

    /*
     * Note that at this stage it is assumed that the accumulator was started
     * in a previous call to entropy_update(). If this is not guaranteed, the
     * code below will fail.
     */
    if ((ret = pf_mbedtls_md_finish(&ctx->accumulator, buf)) != 0) {
        goto exit;
    }

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    pf_mbedtls_md_free(&ctx->accumulator);
    pf_mbedtls_md_init(&ctx->accumulator);
    ret = pf_mbedtls_md_setup(&ctx->accumulator,
                           pf_mbedtls_md_info_from_type(PF_MBEDTLS_ENTROPY_MD), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = pf_mbedtls_md_starts(&ctx->accumulator);
    if (ret != 0) {
        goto exit;
    }
    if ((ret = pf_mbedtls_md_update(&ctx->accumulator, buf,
                                 PF_MBEDTLS_ENTROPY_BLOCK_SIZE)) != 0) {
        goto exit;
    }

    /*
     * Perform second hashing on entropy
     */
    if ((ret = pf_mbedtls_md(pf_mbedtls_md_info_from_type(PF_MBEDTLS_ENTROPY_MD),
                          buf, PF_MBEDTLS_ENTROPY_BLOCK_SIZE, buf)) != 0) {
        goto exit;
    }

    for (i = 0; i < ctx->source_count; i++) {
        ctx->source[i].size = 0;
    }

    memcpy(output, buf, len);

    ret = 0;

exit:
    pf_mbedtls_platform_zeroize(buf, sizeof(buf));

#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return PF_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

#if defined(PF_MBEDTLS_ENTROPY_NV_SEED)
int pf_mbedtls_entropy_update_nv_seed(pf_mbedtls_entropy_context *ctx)
{
    int ret = PF_MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    unsigned char buf[PF_MBEDTLS_ENTROPY_BLOCK_SIZE];

    /* Read new seed  and write it to NV */
    if ((ret = pf_mbedtls_entropy_func(ctx, buf, PF_MBEDTLS_ENTROPY_BLOCK_SIZE)) != 0) {
        return ret;
    }

    if (pf_mbedtls_nv_seed_write(buf, PF_MBEDTLS_ENTROPY_BLOCK_SIZE) < 0) {
        return PF_MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    }

    /* Manually update the remaining stream with a separator value to diverge */
    memset(buf, 0, PF_MBEDTLS_ENTROPY_BLOCK_SIZE);
    ret = pf_mbedtls_entropy_update_manual(ctx, buf, PF_MBEDTLS_ENTROPY_BLOCK_SIZE);

    return ret;
}
#endif /* MBEDTLS_ENTROPY_NV_SEED */

#if defined(PF_MBEDTLS_FS_IO)
int pf_mbedtls_entropy_write_seed_file(pf_mbedtls_entropy_context *ctx, const char *path)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    FILE *f = NULL;
    unsigned char buf[PF_MBEDTLS_ENTROPY_BLOCK_SIZE];

    if ((ret = pf_mbedtls_entropy_func(ctx, buf, PF_MBEDTLS_ENTROPY_BLOCK_SIZE)) != 0) {
        ret = PF_MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        goto exit;
    }

    if ((f = fopen(path, "wb")) == NULL) {
        ret = PF_MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
        goto exit;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    pf_mbedtls_setbuf(f, NULL);

    if (fwrite(buf, 1, PF_MBEDTLS_ENTROPY_BLOCK_SIZE, f) != PF_MBEDTLS_ENTROPY_BLOCK_SIZE) {
        ret = PF_MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
        goto exit;
    }

    ret = 0;

exit:
    pf_mbedtls_platform_zeroize(buf, sizeof(buf));

    if (f != NULL) {
        fclose(f);
    }

    return ret;
}

int pf_mbedtls_entropy_update_seed_file(pf_mbedtls_entropy_context *ctx, const char *path)
{
    int ret = 0;
    FILE *f;
    size_t n;
    unsigned char buf[PF_MBEDTLS_ENTROPY_MAX_SEED_SIZE];

    if ((f = fopen(path, "rb")) == NULL) {
        return PF_MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    pf_mbedtls_setbuf(f, NULL);

    fseek(f, 0, SEEK_END);
    n = (size_t) ftell(f);
    fseek(f, 0, SEEK_SET);

    if (n > PF_MBEDTLS_ENTROPY_MAX_SEED_SIZE) {
        n = PF_MBEDTLS_ENTROPY_MAX_SEED_SIZE;
    }

    if (fread(buf, 1, n, f) != n) {
        ret = PF_MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    } else {
        ret = pf_mbedtls_entropy_update_manual(ctx, buf, n);
    }

    fclose(f);

    pf_mbedtls_platform_zeroize(buf, sizeof(buf));

    if (ret != 0) {
        return ret;
    }

    return pf_mbedtls_entropy_write_seed_file(ctx, path);
}
#endif /* MBEDTLS_FS_IO */

#if defined(PF_MBEDTLS_SELF_TEST)
/*
 * Dummy source function
 */
static int entropy_dummy_source(void *data, unsigned char *output,
                                size_t len, size_t *olen)
{
    ((void) data);

    memset(output, 0x2a, len);
    *olen = len;

    return 0;
}

#if defined(PF_MBEDTLS_ENTROPY_HARDWARE_ALT)

static int pf_mbedtls_entropy_source_self_test_gather(unsigned char *buf, size_t buf_len)
{
    int ret = 0;
    size_t entropy_len = 0;
    size_t olen = 0;
    size_t attempts = buf_len;

    while (attempts > 0 && entropy_len < buf_len) {
        if ((ret = pf_mbedtls_hardware_poll(NULL, buf + entropy_len,
                                         buf_len - entropy_len, &olen)) != 0) {
            return ret;
        }

        entropy_len += olen;
        attempts--;
    }

    if (entropy_len < buf_len) {
        ret = 1;
    }

    return ret;
}


static int pf_mbedtls_entropy_source_self_test_check_bits(const unsigned char *buf,
                                                       size_t buf_len)
{
    unsigned char set = 0xFF;
    unsigned char unset = 0x00;
    size_t i;

    for (i = 0; i < buf_len; i++) {
        set &= buf[i];
        unset |= buf[i];
    }

    return set == 0xFF || unset == 0x00;
}

/*
 * A test to ensure that the entropy sources are functioning correctly
 * and there is no obvious failure. The test performs the following checks:
 *  - The entropy source is not providing only 0s (all bits unset) or 1s (all
 *    bits set).
 *  - The entropy source is not providing values in a pattern. Because the
 *    hardware could be providing data in an arbitrary length, this check polls
 *    the hardware entropy source twice and compares the result to ensure they
 *    are not equal.
 *  - The error code returned by the entropy source is not an error.
 */
int pf_mbedtls_entropy_source_self_test(int verbose)
{
    int ret = 0;
    unsigned char buf0[2 * sizeof(unsigned long long int)];
    unsigned char buf1[2 * sizeof(unsigned long long int)];

    if (verbose != 0) {
        pf_mbedtls_printf("  ENTROPY_BIAS test: ");
    }

    memset(buf0, 0x00, sizeof(buf0));
    memset(buf1, 0x00, sizeof(buf1));

    if ((ret = pf_mbedtls_entropy_source_self_test_gather(buf0, sizeof(buf0))) != 0) {
        goto cleanup;
    }
    if ((ret = pf_mbedtls_entropy_source_self_test_gather(buf1, sizeof(buf1))) != 0) {
        goto cleanup;
    }

    /* Make sure that the returned values are not all 0 or 1 */
    if ((ret = pf_mbedtls_entropy_source_self_test_check_bits(buf0, sizeof(buf0))) != 0) {
        goto cleanup;
    }
    if ((ret = pf_mbedtls_entropy_source_self_test_check_bits(buf1, sizeof(buf1))) != 0) {
        goto cleanup;
    }

    /* Make sure that the entropy source is not returning values in a
     * pattern */
    ret = memcmp(buf0, buf1, sizeof(buf0)) == 0;

cleanup:
    if (verbose != 0) {
        if (ret != 0) {
            pf_mbedtls_printf("failed\n");
        } else {
            pf_mbedtls_printf("passed\n");
        }

        pf_mbedtls_printf("\n");
    }

    return ret != 0;
}

#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */

/*
 * The actual entropy quality is hard to test, but we can at least
 * test that the functions don't cause errors and write the correct
 * amount of data to buffers.
 */
int pf_mbedtls_entropy_self_test(int verbose)
{
    int ret = 1;
    pf_mbedtls_entropy_context ctx;
    unsigned char buf[PF_MBEDTLS_ENTROPY_BLOCK_SIZE] = { 0 };
    unsigned char acc[PF_MBEDTLS_ENTROPY_BLOCK_SIZE] = { 0 };
    size_t i, j;

    if (verbose != 0) {
        pf_mbedtls_printf("  ENTROPY test: ");
    }

    pf_mbedtls_entropy_init(&ctx);

    /* First do a gather to make sure we have default sources */
    if ((ret = pf_mbedtls_entropy_gather(&ctx)) != 0) {
        goto cleanup;
    }

    ret = pf_mbedtls_entropy_add_source(&ctx, entropy_dummy_source, NULL, 16,
                                     PF_MBEDTLS_ENTROPY_SOURCE_WEAK);
    if (ret != 0) {
        goto cleanup;
    }

    if ((ret = pf_mbedtls_entropy_update_manual(&ctx, buf, sizeof(buf))) != 0) {
        goto cleanup;
    }

    /*
     * To test that mbedtls_entropy_func writes correct number of bytes:
     * - use the whole buffer and rely on ASan to detect overruns
     * - collect entropy 8 times and OR the result in an accumulator:
     *   any byte should then be 0 with probably 2^(-64), so requiring
     *   each of the 32 or 64 bytes to be non-zero has a false failure rate
     *   of at most 2^(-58) which is acceptable.
     */
    for (i = 0; i < 8; i++) {
        if ((ret = pf_mbedtls_entropy_func(&ctx, buf, sizeof(buf))) != 0) {
            goto cleanup;
        }

        for (j = 0; j < sizeof(buf); j++) {
            acc[j] |= buf[j];
        }
    }

    for (j = 0; j < sizeof(buf); j++) {
        if (acc[j] == 0) {
            ret = 1;
            goto cleanup;
        }
    }

#if defined(PF_MBEDTLS_ENTROPY_HARDWARE_ALT)
    if ((ret = pf_mbedtls_entropy_source_self_test(0)) != 0) {
        goto cleanup;
    }
#endif

cleanup:
    pf_mbedtls_entropy_free(&ctx);

    if (verbose != 0) {
        if (ret != 0) {
            pf_mbedtls_printf("failed\n");
        } else {
            pf_mbedtls_printf("passed\n");
        }

        pf_mbedtls_printf("\n");
    }

    return ret != 0;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_ENTROPY_C */
