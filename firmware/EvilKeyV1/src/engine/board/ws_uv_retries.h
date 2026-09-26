/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Sole caller is the serialized FIDO command worker. No auto-erasure on errors. */
int ws_uv_retries_get(void); /* 0..8, -1 on persistent-store failure */
bool ws_uv_retries_reserve(void); /* Persist attempt BEFORE verifying PIN */
bool ws_uv_retries_reset(void); /* Only following successful PIN verification */
