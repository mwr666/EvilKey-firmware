/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WS_MANAGER_DRIVE_READ_ID  UINT64_C(0x50464d3200000001)
#define WS_MANAGER_DRIVE_WRITE_ID UINT64_C(0x50464d3200000002)
#define WS_MANAGER_DRIVE_API_VERSION 1U
#define WS_MANAGER_DRIVE_WIRE_SIZE 8U

/* Non-secret persistent preferences for the optional microSD USB MSC interface.
 * mdrive_v1 controls whether MSC is enumerated after boot. mdrive_ro1 controls
 * host write protection. Both live in wsdev/pf_manager, separate from FIDO keys,
 * credentials and PIN state. The default write-protection setting is OFF so a
 * fresh card can receive EvilKeyManager.exe without another card reader. */
void ws_manager_drive_state_init(void);
bool ws_manager_drive_enabled(void);
bool ws_manager_drive_read_only(void);
bool ws_manager_drive_storage_ok(void);
bool ws_manager_drive_set_enabled(bool enabled);
bool ws_manager_drive_set_read_only(bool read_only);

/* Authenticated Manager API record: "PFM2", version 1, flags bit0=read-only,
 * two zero reserved bytes. No key material or filesystem contents are exposed. */
void ws_manager_drive_encode(uint8_t out[WS_MANAGER_DRIVE_WIRE_SIZE]);
bool ws_manager_drive_decode(const uint8_t *data,size_t len,bool *read_only);

#ifdef __cplusplus
}
#endif
