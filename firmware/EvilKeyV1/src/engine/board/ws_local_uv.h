/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
bool pf_local_uv_ready(void);
int pf_local_uv_verify(uint8_t permissions); /* Actual PIN check; never a touch-only UV shortcut. */
/* R13: verify a PIN already collected on-device for the narrow Settings
 * READ ONLY -> READ/WRITE transition. This grants no FIDO UV/token/session. */
int pf_local_uv_verify_supplied_pin(const char *pin,size_t length);
int ws_board_get_pin(char *out,size_t capacity,size_t *length,unsigned retries,uint8_t permissions);
bool ws_board_pin_pending(void);
void ws_board_pin_abort(void);
void ws_board_pin_feedback(int ctap_error);
#ifdef __cplusplus
}
#endif
