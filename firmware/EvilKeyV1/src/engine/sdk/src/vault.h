/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _PICOKEYS_VAULT_H_
#define _PICOKEYS_VAULT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto_utils.h"
#include "fs/file.h"

#define PICOKEYS_VAULT_KEY_SIZE 32u
#define PICOKEYS_VAULT_X448_BYTES 56u
#define PICOKEYS_VAULT_BLOB_NONCE_SIZE 12u
#define PICOKEYS_VAULT_BLOB_TAG_SIZE 16u
#define PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY 1u
#define PICOKEYS_VAULT_ALGORITHM_AESGCM 2u
#define PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY_AESGCM 3u
#define PICOKEYS_VAULT_ALGORITHM_AESGCM_CHACHAPOLY 4u
#define PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES 32u
#define PICOKEYS_VAULT_ENROLL_WINDOW_MS 60000u
#define PICOKEYS_VAULT_ENROLL_HOLD_MS 10000u
#define PICOKEYS_VAULT_ENROLLMENT_PROTOCOL 2u
#define PICOKEYS_VAULT_ENROLL_CERT_MAX 1900u
#define PICOKEYS_VAULT_ENROLL_PLAIN_MAX (PICOKEYS_VAULT_KEY_SIZE + 1u + 64u)
#define PICOKEYS_VAULT_ENROLL_MIN_PACKET_LEN (2u + PICOKEYS_VAULT_X448_BYTES + PICOKEYS_VAULT_KEY_SIZE + 16u)

extern int picokeys_vault_hash_kvault(const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE]);
extern int picokeys_vault_layer_key(const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE], const uint8_t credential_hash[PICOKEYS_VAULT_KEY_SIZE], uint8_t algorithm, uint8_t layer, uint8_t out[PICOKEYS_VAULT_KEY_SIZE]);
extern int picokeys_vault_encrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, uint8_t *output, uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE]);
extern int picokeys_vault_decrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, const uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE], uint8_t *output);
extern bool picokeys_vault_enrollment_button_ready(void);
extern int picokeys_vault_enrollment_start(uint8_t public_key[PICOKEYS_VAULT_X448_BYTES], uint8_t challenge[PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES]);
extern void picokeys_vault_enrollment_clear(void);
extern void picokeys_vault_enrollment_reset(void);
extern int picokeys_vault_enrollment_decode(const uint8_t *packet, size_t packet_len, uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len);
extern bool picokeys_vault_algorithm_valid(uint8_t algorithm);
extern size_t picokeys_vault_algorithm_layers(uint8_t algorithm);
extern uint8_t picokeys_vault_algorithm_layer(uint8_t algorithm, size_t layer);

#endif // _PICOKEYS_VAULT_H_
