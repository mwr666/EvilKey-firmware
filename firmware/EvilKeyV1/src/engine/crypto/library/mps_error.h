/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * \file mps_error.h
 *
 * \brief Error codes used by MPS
 */

#ifndef PF_MBEDTLS_MPS_ERROR_H
#define PF_MBEDTLS_MPS_ERROR_H


/* TODO: The error code allocation needs to be revisited:
 *
 * - Should we make (some of) the MPS Reader error codes public?
 *   If so, we need to adjust MBEDTLS_MPS_READER_MAKE_ERROR() to hit
 *   a gap in the Mbed TLS public error space.
 *   If not, we have to make sure we don't forward those errors
 *   at the level of the public API -- no risk at the moment as
 *   long as MPS is an experimental component not accessible from
 *   public API.
 */

/**
 * \name SECTION:       MPS general error codes
 *
 * \{
 */

#ifndef PF_MBEDTLS_MPS_ERR_BASE
#define PF_MBEDTLS_MPS_ERR_BASE (0)
#endif

#define PF_MBEDTLS_MPS_MAKE_ERROR(code) \
    (-(PF_MBEDTLS_MPS_ERR_BASE | (code)))

#define PF_MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED  PF_MBEDTLS_MPS_MAKE_ERROR(0x1)
#define PF_MBEDTLS_ERR_MPS_INTERNAL_ERROR        PF_MBEDTLS_MPS_MAKE_ERROR(0x2)

/* \} name SECTION: MPS general error codes */

/**
 * \name SECTION:       MPS Reader error codes
 *
 * \{
 */

#ifndef PF_MBEDTLS_MPS_READER_ERR_BASE
#define PF_MBEDTLS_MPS_READER_ERR_BASE (1 << 8)
#endif

#define PF_MBEDTLS_MPS_READER_MAKE_ERROR(code) \
    (-(PF_MBEDTLS_MPS_READER_ERR_BASE | (code)))

/*! An attempt to reclaim the data buffer from a reader failed because
 *  the user hasn't yet read and committed all of it. */
#define PF_MBEDTLS_ERR_MPS_READER_DATA_LEFT             PF_MBEDTLS_MPS_READER_MAKE_ERROR(0x1)

/*! An invalid argument was passed to the reader. */
#define PF_MBEDTLS_ERR_MPS_READER_INVALID_ARG           PF_MBEDTLS_MPS_READER_MAKE_ERROR(0x2)

/*! An attempt to move a reader to consuming mode through mbedtls_mps_reader_feed()
 *  after pausing failed because the provided data is not sufficient to serve the
 *  read requests that led to the pausing. */
#define PF_MBEDTLS_ERR_MPS_READER_NEED_MORE             PF_MBEDTLS_MPS_READER_MAKE_ERROR(0x3)

/*! A get request failed because not enough data is available in the reader. */
#define PF_MBEDTLS_ERR_MPS_READER_OUT_OF_DATA           PF_MBEDTLS_MPS_READER_MAKE_ERROR(0x4)

/*!< A get request after pausing and reactivating the reader failed because
 *   the request is not in line with the request made prior to pausing. The user
 *   must not change it's 'strategy' after pausing and reactivating a reader. */
#define PF_MBEDTLS_ERR_MPS_READER_INCONSISTENT_REQUESTS PF_MBEDTLS_MPS_READER_MAKE_ERROR(0x5)

/*! An attempt to reclaim the data buffer from a reader failed because the reader
 *  has no accumulator it can use to backup the data that hasn't been processed. */
#define PF_MBEDTLS_ERR_MPS_READER_NEED_ACCUMULATOR      PF_MBEDTLS_MPS_READER_MAKE_ERROR(0x6)

/*! An attempt to reclaim the data buffer from a reader failed because the
 *  accumulator passed to the reader is not large enough to hold both the
 *  data that hasn't been processed and the excess of the last read-request. */
#define PF_MBEDTLS_ERR_MPS_READER_ACCUMULATOR_TOO_SMALL PF_MBEDTLS_MPS_READER_MAKE_ERROR(0x7)

/* \} name SECTION: MPS Reader error codes */

#endif /* MBEDTLS_MPS_ERROR_H */
