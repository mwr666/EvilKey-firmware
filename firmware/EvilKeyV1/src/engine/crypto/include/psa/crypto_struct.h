/**
 * \file psa/crypto_struct.h
 *
 * \brief PSA cryptography module: Mbed TLS structured type implementations
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of some data structures with
 * implementation-specific definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, it is expected that the front-end and the back-end
 * would have different versions of this file.
 *
 * <h3>Design notes about multipart operation structures</h3>
 *
 * For multipart operations without driver delegation support, each multipart
 * operation structure contains a `psa_algorithm_t alg` field which indicates
 * which specific algorithm the structure is for. When the structure is not in
 * use, `alg` is 0. Most of the structure consists of a union which is
 * discriminated by `alg`.
 *
 * For multipart operations with driver delegation support, each multipart
 * operation structure contains an `unsigned int id` field indicating which
 * driver got assigned to do the operation. When the structure is not in use,
 * 'id' is 0. The structure contains also a driver context which is the union
 * of the contexts of all drivers able to handle the type of multipart
 * operation.
 *
 * Note that when `alg` or `id` is 0, the content of other fields is undefined.
 * In particular, it is not guaranteed that a freshly-initialized structure
 * is all-zero: we initialize structures to something like `{0, 0}`, which
 * is only guaranteed to initializes the first member of the union;
 * GCC and Clang initialize the whole structure to 0 (at the time of writing),
 * but MSVC and CompCert don't.
 *
 * In Mbed TLS, multipart operation structures live independently from
 * the key. This allows Mbed TLS to free the key objects when destroying
 * a key slot. If a multipart operation needs to remember the key after
 * the setup function returns, the operation structure needs to contain a
 * copy of the key.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_PSA_CRYPTO_STRUCT_H
#define PF_PSA_CRYPTO_STRUCT_H
#include "../mbedtls/private_access.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Include the build-time configuration information header. Here, we do not
 * include `"mbedtls/build_info.h"` directly but `"psa/build_info.h"`, which
 * is basically just an alias to it. This is to ease the maintenance of the
 * TF-PSA-Crypto repository which has a different build system and
 * configuration.
 */
#include "build_info.h"

/* Include the context definition for the compiled-in drivers for the primitive
 * algorithms. */
#include "crypto_driver_contexts_primitives.h"

struct pf_psa_hash_operation_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_driver_wrappers.h.
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. the driver context is not active, in use). */
    unsigned int PF_MBEDTLS_PRIVATE(id);
    pf_psa_driver_hash_context_t PF_MBEDTLS_PRIVATE(ctx);
#endif
};
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
#define PF_PSA_HASH_OPERATION_INIT { 0 }
#else
#define PF_PSA_HASH_OPERATION_INIT { 0, { 0 } }
#endif
static inline struct pf_psa_hash_operation_s pf_psa_hash_operation_init(void)
{
    const struct pf_psa_hash_operation_s v = PF_PSA_HASH_OPERATION_INIT;
    return v;
}

struct pf_psa_cipher_operation_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int PF_MBEDTLS_PRIVATE(id);

    unsigned int PF_MBEDTLS_PRIVATE(iv_required) : 1;
    unsigned int PF_MBEDTLS_PRIVATE(iv_set) : 1;

    uint8_t PF_MBEDTLS_PRIVATE(default_iv_length);

    pf_psa_driver_cipher_context_t PF_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
#define PF_PSA_CIPHER_OPERATION_INIT { 0 }
#else
#define PF_PSA_CIPHER_OPERATION_INIT { 0, 0, 0, 0, { 0 } }
#endif
static inline struct pf_psa_cipher_operation_s pf_psa_cipher_operation_init(void)
{
    const struct pf_psa_cipher_operation_s v = PF_PSA_CIPHER_OPERATION_INIT;
    return v;
}

/* Include the context definition for the compiled-in drivers for the composite
 * algorithms. */
#include "crypto_driver_contexts_composites.h"

struct pf_psa_mac_operation_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int PF_MBEDTLS_PRIVATE(id);
    uint8_t PF_MBEDTLS_PRIVATE(mac_size);
    unsigned int PF_MBEDTLS_PRIVATE(is_sign) : 1;
    pf_psa_driver_mac_context_t PF_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
#define PF_PSA_MAC_OPERATION_INIT { 0 }
#else
#define PF_PSA_MAC_OPERATION_INIT { 0, 0, 0, { 0 } }
#endif
static inline struct pf_psa_mac_operation_s pf_psa_mac_operation_init(void)
{
    const struct pf_psa_mac_operation_s v = PF_PSA_MAC_OPERATION_INIT;
    return v;
}

struct pf_psa_aead_operation_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int PF_MBEDTLS_PRIVATE(id);

    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);
    pf_psa_key_type_t PF_MBEDTLS_PRIVATE(key_type);

    size_t PF_MBEDTLS_PRIVATE(ad_remaining);
    size_t PF_MBEDTLS_PRIVATE(body_remaining);

    unsigned int PF_MBEDTLS_PRIVATE(nonce_set) : 1;
    unsigned int PF_MBEDTLS_PRIVATE(lengths_set) : 1;
    unsigned int PF_MBEDTLS_PRIVATE(ad_started) : 1;
    unsigned int PF_MBEDTLS_PRIVATE(body_started) : 1;
    unsigned int PF_MBEDTLS_PRIVATE(is_encrypt) : 1;

    pf_psa_driver_aead_context_t PF_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
#define PF_PSA_AEAD_OPERATION_INIT { 0 }
#else
#define PF_PSA_AEAD_OPERATION_INIT { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, { 0 } }
#endif
static inline struct pf_psa_aead_operation_s pf_psa_aead_operation_init(void)
{
    const struct pf_psa_aead_operation_s v = PF_PSA_AEAD_OPERATION_INIT;
    return v;
}

/* Include the context definition for the compiled-in drivers for the key
 * derivation algorithms. */
#include "crypto_driver_contexts_key_derivation.h"

struct pf_psa_key_derivation_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_mbedtls_psa_client_handle_t handle;
#else
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);
    unsigned int PF_MBEDTLS_PRIVATE(can_output_key) : 1;
    size_t PF_MBEDTLS_PRIVATE(capacity);
    pf_psa_driver_key_derivation_context_t PF_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
#define PF_PSA_KEY_DERIVATION_OPERATION_INIT { 0 }
#else
/* This only zeroes out the first byte in the union, the rest is unspecified. */
#define PF_PSA_KEY_DERIVATION_OPERATION_INIT { 0, 0, 0, { 0 } }
#endif
static inline struct pf_psa_key_derivation_s pf_psa_key_derivation_operation_init(
    void)
{
    const struct pf_psa_key_derivation_s v = PF_PSA_KEY_DERIVATION_OPERATION_INIT;
    return v;
}

struct pf_psa_custom_key_parameters_s {
    /* Future versions may add other fields in this structure. */
    uint32_t flags;
};

/** The default production parameters for key generation or key derivation.
 *
 * Calling psa_generate_key_custom() or psa_key_derivation_output_key_custom()
 * with `custom=PSA_CUSTOM_KEY_PARAMETERS_INIT` and `custom_data_length=0` is
 * equivalent to calling psa_generate_key() or psa_key_derivation_output_key()
 * respectively.
 */
#define PF_PSA_CUSTOM_KEY_PARAMETERS_INIT { 0 }

#ifndef __cplusplus
/* Omitted when compiling in C++, because one of the parameters is a
 * pointer to a struct with a flexible array member, and that is not
 * standard C++.
 * https://github.com/Mbed-TLS/mbedtls/issues/9020
 */
/* This is a deprecated variant of `struct psa_custom_key_parameters_s`.
 * It has exactly the same layout, plus an extra field which is a flexible
 * array member. Thus a `const struct psa_key_production_parameters_s *`
 * can be passed to any function that reads a
 * `const struct psa_custom_key_parameters_s *`.
 */
struct pf_psa_key_production_parameters_s {
    uint32_t flags;
    uint8_t data[];
};

/** The default production parameters for key generation or key derivation.
 *
 * Calling psa_generate_key_ext() or psa_key_derivation_output_key_ext()
 * with `params=PSA_KEY_PRODUCTION_PARAMETERS_INIT` and
 * `params_data_length == 0` is equivalent to
 * calling psa_generate_key() or psa_key_derivation_output_key()
 * respectively.
 */
#define PF_PSA_KEY_PRODUCTION_PARAMETERS_INIT { 0 }
#endif /* !__cplusplus */

struct pf_psa_key_policy_s {
    pf_psa_key_usage_t PF_MBEDTLS_PRIVATE(usage);
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg2);
};
typedef struct pf_psa_key_policy_s pf_psa_key_policy_t;

#define PF_PSA_KEY_POLICY_INIT { 0, 0, 0 }
static inline struct pf_psa_key_policy_s pf_psa_key_policy_init(void)
{
    const struct pf_psa_key_policy_s v = PF_PSA_KEY_POLICY_INIT;
    return v;
}

/* The type used internally for key sizes.
 * Public interfaces use size_t, but internally we use a smaller type. */
typedef uint16_t pf_psa_key_bits_t;
/* The maximum value of the type used to represent bit-sizes.
 * This is used to mark an invalid key size. */
#define PF_PSA_KEY_BITS_TOO_LARGE          ((pf_psa_key_bits_t) -1)
/* The maximum size of a key in bits.
 * Currently defined as the maximum that can be represented, rounded down
 * to a whole number of bytes.
 * This is an uncast value so that it can be used in preprocessor
 * conditionals. */
#define PF_PSA_MAX_KEY_BITS 0xfff8

struct pf_psa_key_attributes_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
    pf_psa_key_slot_number_t PF_MBEDTLS_PRIVATE(slot_number);
    int PF_MBEDTLS_PRIVATE(has_slot_number);
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    pf_psa_key_type_t PF_MBEDTLS_PRIVATE(type);
    pf_psa_key_bits_t PF_MBEDTLS_PRIVATE(bits);
    pf_psa_key_lifetime_t PF_MBEDTLS_PRIVATE(lifetime);
    pf_psa_key_policy_t PF_MBEDTLS_PRIVATE(policy);
    /* This type has a different layout in the client view wrt the
     * service view of the key id, i.e. in service view usually is
     * expected to have MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER defined
     * thus adding an owner field to the standard psa_key_id_t. For
     * implementations with client/service separation, this means the
     * object will be marshalled through a transport channel and
     * interpreted differently at each side of the transport. Placing
     * it at the end of structures allows to interpret the structure
     * at the client without reorganizing the memory layout of the
     * struct
     */
    pf_mbedtls_svc_key_id_t PF_MBEDTLS_PRIVATE(id);
};

#if defined(PF_MBEDTLS_PSA_CRYPTO_SE_C)
#define PF_PSA_KEY_ATTRIBUTES_MAYBE_SLOT_NUMBER 0, 0,
#else
#define PF_PSA_KEY_ATTRIBUTES_MAYBE_SLOT_NUMBER
#endif
#define PF_PSA_KEY_ATTRIBUTES_INIT { PF_PSA_KEY_ATTRIBUTES_MAYBE_SLOT_NUMBER \
                                      PF_PSA_KEY_TYPE_NONE, 0,            \
                                      PF_PSA_KEY_LIFETIME_VOLATILE,       \
                                      PF_PSA_KEY_POLICY_INIT,             \
                                      PF_MBEDTLS_SVC_KEY_ID_INIT }

static inline struct pf_psa_key_attributes_s pf_psa_key_attributes_init(void)
{
    const struct pf_psa_key_attributes_s v = PF_PSA_KEY_ATTRIBUTES_INIT;
    return v;
}

static inline void pf_psa_set_key_id(pf_psa_key_attributes_t *attributes,
                                  pf_mbedtls_svc_key_id_t key)
{
    pf_psa_key_lifetime_t lifetime = attributes->PF_MBEDTLS_PRIVATE(lifetime);

    attributes->PF_MBEDTLS_PRIVATE(id) = key;

    if (PF_PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        attributes->PF_MBEDTLS_PRIVATE(lifetime) =
            PF_PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                PF_PSA_KEY_LIFETIME_PERSISTENT,
                PF_PSA_KEY_LIFETIME_GET_LOCATION(lifetime));
    }
}

static inline pf_mbedtls_svc_key_id_t pf_psa_get_key_id(
    const pf_psa_key_attributes_t *attributes)
{
    return attributes->PF_MBEDTLS_PRIVATE(id);
}

#ifdef PF_MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
static inline void pf_mbedtls_set_key_owner_id(pf_psa_key_attributes_t *attributes,
                                            pf_mbedtls_key_owner_id_t owner)
{
    attributes->PF_MBEDTLS_PRIVATE(id).PF_MBEDTLS_PRIVATE(owner) = owner;
}
#endif

static inline void pf_psa_set_key_lifetime(pf_psa_key_attributes_t *attributes,
                                        pf_psa_key_lifetime_t lifetime)
{
    attributes->PF_MBEDTLS_PRIVATE(lifetime) = lifetime;
    if (PF_PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
#ifdef PF_MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
        attributes->PF_MBEDTLS_PRIVATE(id).PF_MBEDTLS_PRIVATE(key_id) = 0;
#else
        attributes->PF_MBEDTLS_PRIVATE(id) = 0;
#endif
    }
}

static inline pf_psa_key_lifetime_t pf_psa_get_key_lifetime(
    const pf_psa_key_attributes_t *attributes)
{
    return attributes->PF_MBEDTLS_PRIVATE(lifetime);
}

static inline void pf_psa_extend_key_usage_flags(pf_psa_key_usage_t *usage_flags)
{
    if (*usage_flags & PF_PSA_KEY_USAGE_SIGN_HASH) {
        *usage_flags |= PF_PSA_KEY_USAGE_SIGN_MESSAGE;
    }

    if (*usage_flags & PF_PSA_KEY_USAGE_VERIFY_HASH) {
        *usage_flags |= PF_PSA_KEY_USAGE_VERIFY_MESSAGE;
    }
}

static inline void pf_psa_set_key_usage_flags(pf_psa_key_attributes_t *attributes,
                                           pf_psa_key_usage_t usage_flags)
{
    pf_psa_extend_key_usage_flags(&usage_flags);
    attributes->PF_MBEDTLS_PRIVATE(policy).PF_MBEDTLS_PRIVATE(usage) = usage_flags;
}

static inline pf_psa_key_usage_t pf_psa_get_key_usage_flags(
    const pf_psa_key_attributes_t *attributes)
{
    return attributes->PF_MBEDTLS_PRIVATE(policy).PF_MBEDTLS_PRIVATE(usage);
}

static inline void pf_psa_set_key_algorithm(pf_psa_key_attributes_t *attributes,
                                         pf_psa_algorithm_t alg)
{
    attributes->PF_MBEDTLS_PRIVATE(policy).PF_MBEDTLS_PRIVATE(alg) = alg;
}

static inline pf_psa_algorithm_t pf_psa_get_key_algorithm(
    const pf_psa_key_attributes_t *attributes)
{
    return attributes->PF_MBEDTLS_PRIVATE(policy).PF_MBEDTLS_PRIVATE(alg);
}

static inline void pf_psa_set_key_type(pf_psa_key_attributes_t *attributes,
                                    pf_psa_key_type_t type)
{
    attributes->PF_MBEDTLS_PRIVATE(type) = type;
}

static inline pf_psa_key_type_t pf_psa_get_key_type(
    const pf_psa_key_attributes_t *attributes)
{
    return attributes->PF_MBEDTLS_PRIVATE(type);
}

static inline void pf_psa_set_key_bits(pf_psa_key_attributes_t *attributes,
                                    size_t bits)
{
    if (bits > PF_PSA_MAX_KEY_BITS) {
        attributes->PF_MBEDTLS_PRIVATE(bits) = PF_PSA_KEY_BITS_TOO_LARGE;
    } else {
        attributes->PF_MBEDTLS_PRIVATE(bits) = (pf_psa_key_bits_t) bits;
    }
}

static inline size_t pf_psa_get_key_bits(
    const pf_psa_key_attributes_t *attributes)
{
    return attributes->PF_MBEDTLS_PRIVATE(bits);
}

/**
 * \brief The context for PSA interruptible hash signing.
 */
struct pf_psa_sign_hash_interruptible_operation_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int PF_MBEDTLS_PRIVATE(id);

    pf_psa_driver_sign_hash_interruptible_context_t PF_MBEDTLS_PRIVATE(ctx);

    unsigned int PF_MBEDTLS_PRIVATE(error_occurred) : 1;

    uint32_t PF_MBEDTLS_PRIVATE(num_ops);
#endif
};

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
#define PF_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
#else
#define PF_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0, { 0 }, 0, 0 }
#endif

static inline struct pf_psa_sign_hash_interruptible_operation_s
pf_psa_sign_hash_interruptible_operation_init(void)
{
    const struct pf_psa_sign_hash_interruptible_operation_s v =
        PF_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT;

    return v;
}

/**
 * \brief The context for PSA interruptible hash verification.
 */
struct pf_psa_verify_hash_interruptible_operation_s {
#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int PF_MBEDTLS_PRIVATE(id);

    pf_psa_driver_verify_hash_interruptible_context_t PF_MBEDTLS_PRIVATE(ctx);

    unsigned int PF_MBEDTLS_PRIVATE(error_occurred) : 1;

    uint32_t PF_MBEDTLS_PRIVATE(num_ops);
#endif
};

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(PF_MBEDTLS_PSA_CRYPTO_C)
#define PF_PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
#else
#define PF_PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT { 0, { 0 }, 0, 0 }
#endif

static inline struct pf_psa_verify_hash_interruptible_operation_s
pf_psa_verify_hash_interruptible_operation_init(void)
{
    const struct pf_psa_verify_hash_interruptible_operation_s v =
        PF_PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT;

    return v;
}

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_STRUCT_H */
