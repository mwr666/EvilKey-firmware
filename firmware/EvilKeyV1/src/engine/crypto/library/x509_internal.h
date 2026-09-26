/**
 * \file x509.h
 *
 * \brief Internal part of the public "x509.h".
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_X509_INTERNAL_H
#define PF_MBEDTLS_X509_INTERNAL_H
#include "../include/mbedtls/private_access.h"

#include "../include/mbedtls/build_info.h"

#include "../include/mbedtls/x509.h"
#include "../include/mbedtls/x509_crt.h"
#include "../include/mbedtls/asn1.h"
#include "pk_internal.h"

#if defined(PF_MBEDTLS_RSA_C)
#include "../include/mbedtls/rsa.h"
#endif

int pf_mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          pf_mbedtls_x509_name *cur);
int pf_mbedtls_x509_get_alg_null(unsigned char **p, const unsigned char *end,
                              pf_mbedtls_x509_buf *alg);
int pf_mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end,
                         pf_mbedtls_x509_buf *alg, pf_mbedtls_x509_buf *params);
#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT)
int pf_mbedtls_x509_get_rsassa_pss_params(const pf_mbedtls_x509_buf *params,
                                       pf_mbedtls_md_type_t *md_alg, pf_mbedtls_md_type_t *mgf_md,
                                       int *salt_len);
#endif
int pf_mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, pf_mbedtls_x509_buf *sig);
int pf_mbedtls_x509_get_sig_alg(const pf_mbedtls_x509_buf *sig_oid, const pf_mbedtls_x509_buf *sig_params,
                             pf_mbedtls_md_type_t *md_alg, pf_mbedtls_pk_type_t *pk_alg,
                             void **sig_opts);
int pf_mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,
                          pf_mbedtls_x509_time *t);
int pf_mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            pf_mbedtls_x509_buf *serial);
int pf_mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         pf_mbedtls_x509_buf *ext, int tag);
#if !defined(PF_MBEDTLS_X509_REMOVE_INFO)
int pf_mbedtls_x509_sig_alg_gets(char *buf, size_t size, const pf_mbedtls_x509_buf *sig_oid,
                              pf_mbedtls_pk_type_t pk_alg, pf_mbedtls_md_type_t md_alg,
                              const void *sig_opts);
#endif
int pf_mbedtls_x509_key_size_helper(char *buf, size_t buf_size, const char *name);
int pf_mbedtls_x509_set_extension(pf_mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val,
                               size_t val_len);
int pf_mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  pf_mbedtls_asn1_named_data *first);
int pf_mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             pf_mbedtls_asn1_named_data *first);
int pf_mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size,
                           pf_mbedtls_pk_type_t pk_alg);
int pf_mbedtls_x509_get_ns_cert_type(unsigned char **p,
                                  const unsigned char *end,
                                  unsigned char *ns_cert_type);
int pf_mbedtls_x509_get_key_usage(unsigned char **p,
                               const unsigned char *end,
                               unsigned int *key_usage);
int pf_mbedtls_x509_get_subject_alt_name(unsigned char **p,
                                      const unsigned char *end,
                                      pf_mbedtls_x509_sequence *subject_alt_name);
int pf_mbedtls_x509_get_subject_alt_name_ext(unsigned char **p,
                                          const unsigned char *end,
                                          pf_mbedtls_x509_sequence *subject_alt_name);
int pf_mbedtls_x509_info_subject_alt_name(char **buf, size_t *size,
                                       const pf_mbedtls_x509_sequence
                                       *subject_alt_name,
                                       const char *prefix);
int pf_mbedtls_x509_info_cert_type(char **buf, size_t *size,
                                unsigned char ns_cert_type);
int pf_mbedtls_x509_info_key_usage(char **buf, size_t *size,
                                unsigned int key_usage);

int pf_mbedtls_x509_write_set_san_common(pf_mbedtls_asn1_named_data **extensions,
                                      const pf_mbedtls_x509_san_list *san_list);

/*
 * Check md_alg against profile
 * Return 0 if md_alg is acceptable for this profile, -1 otherwise
 */
int pf_mbedtls_x509_profile_check_md_alg(const pf_mbedtls_x509_crt_profile *profile,
                                      pf_mbedtls_md_type_t md_alg);

/*
 * Check pk_alg against profile
 * Return 0 if pk_alg is acceptable for this profile, -1 otherwise
 */
int pf_mbedtls_x509_profile_check_pk_alg(const pf_mbedtls_x509_crt_profile *profile,
                                      pf_mbedtls_pk_type_t pk_alg);

#endif /* MBEDTLS_X509_INTERNAL_H */
