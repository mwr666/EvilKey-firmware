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

#ifndef _VAULT_CONTAINER_H_
#define _VAULT_CONTAINER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../byte_array.h"
#include "file.h"
#include "object_container_store.h"
#include "../vault.h"

#define PICOKEYS_VAULT_RECORD_FORMAT PIN_KDF_V2
#define PICOKEYS_VAULT_RECORD_SIZE (1u + PIN_KDF_SIZE(PICOKEYS_VAULT_KEY_SIZE))
#define PICOKEYS_VAULT_OBJECT_WRAP 0x0001u
#define PICOKEYS_VAULT_OBJECT_LABEL 0x0002u
#define PICOKEYS_VAULT_POLICY_ID 0x0300u
#define PICOKEYS_VAULT_LABEL_MAX 64u

extern int picokeys_vault_init(const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_t *legacy_file, file_t *legacy_label_file);
extern bool picokeys_vault_wrap_available(uint8_t app_id);
extern int picokeys_vault_set_kvault(const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], const uint8_t encryption_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t app_id);
extern int picokeys_vault_get_kvault(uint8_t app_id, const uint8_t encryption_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]);
extern int picokeys_vault_get_label(byte_buffer_t *label);
extern int picokeys_vault_set_label(const_byte_array_t label);
extern int picokeys_vault_delete_kvault(uint8_t app_id);

#endif // _VAULT_CONTAINER_H_
