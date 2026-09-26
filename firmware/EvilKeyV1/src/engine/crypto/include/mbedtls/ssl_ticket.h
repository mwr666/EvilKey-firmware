/**
 * \file ssl_ticket.h
 *
 * \brief TLS server ticket callbacks implementation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_SSL_TICKET_H
#define PF_MBEDTLS_SSL_TICKET_H
#include "private_access.h"

#include "build_info.h"

/*
 * This implementation of the session ticket callbacks includes key
 * management, rotating the keys periodically in order to preserve forward
 * secrecy, when MBEDTLS_HAVE_TIME is defined.
 */

#include "ssl.h"
#include "cipher.h"

#if defined(PF_MBEDTLS_HAVE_TIME)
#include "platform_time.h"
#endif

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#include "../psa/crypto.h"
#endif

#if defined(PF_MBEDTLS_THREADING_C)
#include "threading.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PF_MBEDTLS_SSL_TICKET_MAX_KEY_BYTES 32          /*!< Max supported key length in bytes */
#define PF_MBEDTLS_SSL_TICKET_KEY_NAME_BYTES 4          /*!< key name length in bytes */

/**
 * \brief   Information for session ticket protection
 */
typedef struct pf_mbedtls_ssl_ticket_key {
    unsigned char PF_MBEDTLS_PRIVATE(name)[PF_MBEDTLS_SSL_TICKET_KEY_NAME_BYTES];
    /*!< random key identifier              */
#if defined(PF_MBEDTLS_HAVE_TIME)
    pf_mbedtls_time_t PF_MBEDTLS_PRIVATE(generation_time); /*!< key generation timestamp (seconds) */
#endif
    /*! Lifetime of the key in seconds. This is also the lifetime of the
     *  tickets created under that key.
     */
    uint32_t PF_MBEDTLS_PRIVATE(lifetime);
#if !defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_mbedtls_cipher_context_t PF_MBEDTLS_PRIVATE(ctx);   /*!< context for auth enc/decryption    */
#else
    pf_mbedtls_svc_key_id_t PF_MBEDTLS_PRIVATE(key);       /*!< key used for auth enc/decryption   */
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);            /*!< algorithm of auth enc/decryption   */
    pf_psa_key_type_t PF_MBEDTLS_PRIVATE(key_type);        /*!< key type                           */
    size_t PF_MBEDTLS_PRIVATE(key_bits);                /*!< key length in bits                 */
#endif
}
pf_mbedtls_ssl_ticket_key;

/**
 * \brief   Context for session ticket handling functions
 */
typedef struct pf_mbedtls_ssl_ticket_context {
    pf_mbedtls_ssl_ticket_key PF_MBEDTLS_PRIVATE(keys)[2]; /*!< ticket protection keys             */
    unsigned char PF_MBEDTLS_PRIVATE(active);           /*!< index of the currently active key  */

    uint32_t PF_MBEDTLS_PRIVATE(ticket_lifetime);       /*!< lifetime of tickets in seconds     */

    /** Callback for getting (pseudo-)random numbers                        */
    int(*PF_MBEDTLS_PRIVATE(f_rng))(void *, unsigned char *, size_t);
    void *PF_MBEDTLS_PRIVATE(p_rng);                    /*!< context for the RNG function       */

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_threading_mutex_t PF_MBEDTLS_PRIVATE(mutex);
#endif
}
pf_mbedtls_ssl_ticket_context;

/**
 * \brief           Initialize a ticket context.
 *                  (Just make it ready for mbedtls_ssl_ticket_setup()
 *                  or mbedtls_ssl_ticket_free().)
 *
 * \param ctx       Context to be initialized
 */
void pf_mbedtls_ssl_ticket_init(pf_mbedtls_ssl_ticket_context *ctx);

/**
 * \brief           Prepare context to be actually used
 *
 * \param ctx       Context to be set up
 * \param f_rng     RNG callback function (mandatory)
 * \param p_rng     RNG callback context.
 *                  Note that the RNG callback must remain valid
 *                  until the ticket context is freed.
 * \param cipher    AEAD cipher to use for ticket protection.
 *                  Recommended value: MBEDTLS_CIPHER_AES_256_GCM.
 * \param lifetime  Tickets lifetime in seconds
 *                  Recommended value: 86400 (one day).
 *
 * \note            It is highly recommended to select a cipher that is at
 *                  least as strong as the strongest ciphersuite
 *                  supported. Usually that means a 256-bit key.
 *
 * \note            It is recommended to pick a reasonable lifetime so as not
 *                  to negate the benefits of forward secrecy.
 *
 * \note            The TLS 1.3 specification states that ticket lifetime must
 *                  be smaller than seven days. If ticket lifetime has been
 *                  set to a value greater than seven days in this module then
 *                  if the TLS 1.3 is configured to send tickets after the
 *                  handshake it will fail the connection when trying to send
 *                  the first ticket.
 *
 * \return          0 if successful,
 *                  or a specific MBEDTLS_ERR_XXX error code
 */
int pf_mbedtls_ssl_ticket_setup(pf_mbedtls_ssl_ticket_context *ctx,
                             pf_mbedtls_f_rng_t *f_rng, void *p_rng,
                             pf_mbedtls_cipher_type_t cipher,
                             uint32_t lifetime);

/**
 * \brief           Rotate session ticket encryption key to new specified key.
 *                  Provides for external control of session ticket encryption
 *                  key rotation, e.g. for synchronization between different
 *                  machines.  If this function is not used, or if not called
 *                  before ticket lifetime expires, then a new session ticket
 *                  encryption key is generated internally in order to avoid
 *                  unbounded session ticket encryption key lifetimes.
 *
 * \param ctx       Context to be set up
 * \param name      Session ticket encryption key name
 * \param nlength   Session ticket encryption key name length in bytes
 * \param k         Session ticket encryption key
 * \param klength   Session ticket encryption key length in bytes
 * \param lifetime  Tickets lifetime in seconds
 *                  Recommended value: 86400 (one day).
 *
 * \note            \c name and \c k are recommended to be cryptographically
 *                  random data.
 *
 * \note            \c nlength must match sizeof( ctx->name )
 *
 * \note            \c klength must be sufficient for use by cipher specified
 *                  to \c mbedtls_ssl_ticket_setup
 *
 * \note            It is recommended to pick a reasonable lifetime so as not
 *                  to negate the benefits of forward secrecy.
 *
 * \note            The TLS 1.3 specification states that ticket lifetime must
 *                  be smaller than seven days. If ticket lifetime has been
 *                  set to a value greater than seven days in this module then
 *                  if the TLS 1.3 is configured to send tickets after the
 *                  handshake it will fail the connection when trying to send
 *                  the first ticket.
 *
 * \return          0 if successful,
 *                  or a specific MBEDTLS_ERR_XXX error code
 */
int pf_mbedtls_ssl_ticket_rotate(pf_mbedtls_ssl_ticket_context *ctx,
                              const unsigned char *name, size_t nlength,
                              const unsigned char *k, size_t klength,
                              uint32_t lifetime);

/**
 * \brief           Implementation of the ticket write callback
 *
 * \note            See \c mbedtls_ssl_ticket_write_t for description
 */
pf_mbedtls_ssl_ticket_write_t pf_mbedtls_ssl_ticket_write;

/**
 * \brief           Implementation of the ticket parse callback
 *
 * \note            See \c mbedtls_ssl_ticket_parse_t for description
 */
pf_mbedtls_ssl_ticket_parse_t pf_mbedtls_ssl_ticket_parse;

/**
 * \brief           Free a context's content and zeroize it.
 *
 * \param ctx       Context to be cleaned up
 */
void pf_mbedtls_ssl_ticket_free(pf_mbedtls_ssl_ticket_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ssl_ticket.h */
