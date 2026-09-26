#include "../../../pf_build_config.h"
/*
 *  PSA ITS simulator over stdio files.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_PSA_ITS_FILE_C)

#include "../include/mbedtls/platform.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#include "psa_crypto_its.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(PF_PSA_ITS_STORAGE_PREFIX)
#define PF_PSA_ITS_STORAGE_PREFIX ""
#endif

#define PF_PSA_ITS_STORAGE_FILENAME_PATTERN "%08x%08x"
#define PF_PSA_ITS_STORAGE_SUFFIX ".psa_its"
#define PF_PSA_ITS_STORAGE_FILENAME_LENGTH         \
    (sizeof(PF_PSA_ITS_STORAGE_PREFIX) - 1 +    /*prefix without terminating 0*/ \
     16 +  /*UID (64-bit number in hex)*/                               \
     sizeof(PF_PSA_ITS_STORAGE_SUFFIX) - 1 +    /*suffix without terminating 0*/ \
     1 /*terminating null byte*/)
#define PF_PSA_ITS_STORAGE_TEMP \
    PF_PSA_ITS_STORAGE_PREFIX "tempfile" PF_PSA_ITS_STORAGE_SUFFIX

/* The maximum value of psa_storage_info_t.size */
#define PF_PSA_ITS_MAX_SIZE 0xffffffff

#define PF_PSA_ITS_MAGIC_STRING "PSA\0ITS\0"
#define PF_PSA_ITS_MAGIC_LENGTH 8

/* As rename fails on Windows if the new filepath already exists,
 * use MoveFileExA with the MOVEFILE_REPLACE_EXISTING flag instead.
 * Returns 0 on success, nonzero on failure. */
#if defined(_WIN32)
#define rename_replace_existing(oldpath, newpath) \
    (!MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING))
#else
#define rename_replace_existing(oldpath, newpath) rename(oldpath, newpath)
#endif

typedef struct {
    uint8_t magic[PF_PSA_ITS_MAGIC_LENGTH];
    uint8_t size[sizeof(uint32_t)];
    uint8_t flags[sizeof(pf_psa_storage_create_flags_t)];
} pf_psa_its_file_header_t;

static void pf_psa_its_fill_filename(pf_psa_storage_uid_t uid, char *filename)
{
    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    pf_mbedtls_snprintf(filename, PF_PSA_ITS_STORAGE_FILENAME_LENGTH,
                     "%s" PF_PSA_ITS_STORAGE_FILENAME_PATTERN "%s",
                     PF_PSA_ITS_STORAGE_PREFIX,
                     (unsigned) (uid >> 32),
                     (unsigned) (uid & 0xffffffff),
                     PF_PSA_ITS_STORAGE_SUFFIX);
}

static pf_psa_status_t pf_psa_its_read_file(pf_psa_storage_uid_t uid,
                                      struct pf_psa_storage_info_t *p_info,
                                      FILE **p_stream)
{
    char filename[PF_PSA_ITS_STORAGE_FILENAME_LENGTH];
    pf_psa_its_file_header_t header;
    size_t n;

    *p_stream = NULL;
    pf_psa_its_fill_filename(uid, filename);
    *p_stream = fopen(filename, "rb");
    if (*p_stream == NULL) {
        return PF_PSA_ERROR_DOES_NOT_EXIST;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    pf_mbedtls_setbuf(*p_stream, NULL);

    n = fread(&header, 1, sizeof(header), *p_stream);
    if (n != sizeof(header)) {
        return PF_PSA_ERROR_DATA_CORRUPT;
    }
    if (memcmp(header.magic, PF_PSA_ITS_MAGIC_STRING,
               PF_PSA_ITS_MAGIC_LENGTH) != 0) {
        return PF_PSA_ERROR_DATA_CORRUPT;
    }

    p_info->size  = PF_MBEDTLS_GET_UINT32_LE(header.size, 0);
    p_info->flags = PF_MBEDTLS_GET_UINT32_LE(header.flags, 0);

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_psa_its_get_info(pf_psa_storage_uid_t uid,
                              struct pf_psa_storage_info_t *p_info)
{
    pf_psa_status_t status;
    FILE *stream = NULL;
    status = pf_psa_its_read_file(uid, p_info, &stream);
    if (stream != NULL) {
        fclose(stream);
    }
    return status;
}

pf_psa_status_t pf_psa_its_get(pf_psa_storage_uid_t uid,
                         uint32_t data_offset,
                         uint32_t data_length,
                         void *p_data,
                         size_t *p_data_length)
{
    pf_psa_status_t status;
    FILE *stream = NULL;
    size_t n;
    struct pf_psa_storage_info_t info;

    status = pf_psa_its_read_file(uid, &info, &stream);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }
    status = PF_PSA_ERROR_INVALID_ARGUMENT;
    if (data_offset + data_length < data_offset) {
        goto exit;
    }
#if SIZE_MAX < 0xffffffff
    if (data_offset + data_length > SIZE_MAX) {
        goto exit;
    }
#endif
    if (data_offset + data_length > info.size) {
        goto exit;
    }

    status = PF_PSA_ERROR_STORAGE_FAILURE;
#if LONG_MAX < 0xffffffff
    while (data_offset > LONG_MAX) {
        if (fseek(stream, LONG_MAX, SEEK_CUR) != 0) {
            goto exit;
        }
        data_offset -= LONG_MAX;
    }
#endif
    if (fseek(stream, data_offset, SEEK_CUR) != 0) {
        goto exit;
    }
    n = fread(p_data, 1, data_length, stream);
    if (n != data_length) {
        goto exit;
    }
    status = PF_PSA_SUCCESS;
    if (p_data_length != NULL) {
        *p_data_length = n;
    }

exit:
    if (stream != NULL) {
        fclose(stream);
    }
    return status;
}

pf_psa_status_t pf_psa_its_set(pf_psa_storage_uid_t uid,
                         uint32_t data_length,
                         const void *p_data,
                         pf_psa_storage_create_flags_t create_flags)
{
    if (uid == 0) {
        return PF_PSA_ERROR_INVALID_HANDLE;
    }

    pf_psa_status_t status = PF_PSA_ERROR_STORAGE_FAILURE;
    char filename[PF_PSA_ITS_STORAGE_FILENAME_LENGTH];
    FILE *stream = NULL;
    pf_psa_its_file_header_t header;
    size_t n;

    memcpy(header.magic, PF_PSA_ITS_MAGIC_STRING, PF_PSA_ITS_MAGIC_LENGTH);
    PF_MBEDTLS_PUT_UINT32_LE(data_length, header.size, 0);
    PF_MBEDTLS_PUT_UINT32_LE(create_flags, header.flags, 0);

    pf_psa_its_fill_filename(uid, filename);
    stream = fopen(PF_PSA_ITS_STORAGE_TEMP, "wb");

    if (stream == NULL) {
        goto exit;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    pf_mbedtls_setbuf(stream, NULL);

    status = PF_PSA_ERROR_INSUFFICIENT_STORAGE;
    n = fwrite(&header, 1, sizeof(header), stream);
    if (n != sizeof(header)) {
        goto exit;
    }
    if (data_length != 0) {
        n = fwrite(p_data, 1, data_length, stream);
        if (n != data_length) {
            goto exit;
        }
    }
    status = PF_PSA_SUCCESS;

exit:
    if (stream != NULL) {
        int ret = fclose(stream);
        if (status == PF_PSA_SUCCESS && ret != 0) {
            status = PF_PSA_ERROR_INSUFFICIENT_STORAGE;
        }
    }
    if (status == PF_PSA_SUCCESS) {
        if (rename_replace_existing(PF_PSA_ITS_STORAGE_TEMP, filename) != 0) {
            status = PF_PSA_ERROR_STORAGE_FAILURE;
        }
    }
    /* The temporary file may still exist, but only in failure cases where
     * we're already reporting an error. So there's nothing we can do on
     * failure. If the function succeeded, and in some error cases, the
     * temporary file doesn't exist and so remove() is expected to fail.
     * Thus we just ignore the return status of remove(). */
    (void) remove(PF_PSA_ITS_STORAGE_TEMP);
    return status;
}

pf_psa_status_t pf_psa_its_remove(pf_psa_storage_uid_t uid)
{
    char filename[PF_PSA_ITS_STORAGE_FILENAME_LENGTH];
    FILE *stream;
    pf_psa_its_fill_filename(uid, filename);
    stream = fopen(filename, "rb");
    if (stream == NULL) {
        return PF_PSA_ERROR_DOES_NOT_EXIST;
    }
    fclose(stream);
    if (remove(filename) != 0) {
        return PF_PSA_ERROR_STORAGE_FAILURE;
    }
    return PF_PSA_SUCCESS;
}

#endif /* MBEDTLS_PSA_ITS_FILE_C */
