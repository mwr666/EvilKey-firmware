#include "../../../../pf_build_config.h"
/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

#include <stdio.h>
#include "../../../sdk/src/picokeys.h"
#include "../../../sdk/src/serial.h"
#include "fido.h"
#include "../../../sdk/src/apdu.h"
#include "version.h"
#include "files.h"
#include "../../../sdk/src/tlv.h"
#include "management.h"

bool is_gpg = true;

static int man_process_apdu(void);
static int man_unload(void);

const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};
static int man_select(app_t *a, uint8_t force) {
    a->process_apdu = man_process_apdu;
    a->unload = man_unload;
    sprintf((char *) res_APDU, "%d.%d.0", PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR);
    res_APDU_size = (uint16_t)strlen((char *) res_APDU);
    apdu.ne = res_APDU_size;
    if (force) {
        scan_all();
#ifdef ENABLE_OTP_APP
        init_otp();
#endif
    }
    is_gpg = false;
    return PICOKEYS_OK;
}

INITIALIZER ( man_ctor ) {
    register_app(man_select, man_aid);
}

static int man_unload(void) {
    return PICOKEYS_OK;
}

bool cap_supported(uint16_t cap) {
    /* PF_PROFILE_PATCH_023: compile-time FIDO-only capabilities win over stale EF_DEV_CONF.
     * The old stored record is not erased or modified. */
    return (cap & PF_PROFILE_CAPABILITIES) != 0;
}

static uint8_t _openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};
static uint8_t _piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x8,
};

int man_get_config(void) {
    /* A complete bounded management read-info response; no unsupported applets. */
    const size_t n = pf_profile_build_management_info(res_APDU, 64, pico_serial.id);
    if (n == 0) {
        res_APDU_size = 0;
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    res_APDU_size = (uint16_t)n;
    return PICOKEYS_OK;
}

static int cmd_read_config(void) {
    if (man_get_config() != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}

static int cmd_write_config(void) {
    /* USB/application capabilities are configured in code, not by this read-only adapter. */
    return SW_INS_NOT_SUPPORTED();
}

extern int cbor_reset(void);
static int cmd_factory_reset(void) {
    cbor_reset();
    return SW_OK();
}

#define INS_READ_CONFIG             0x1D
#define INS_WRITE_CONFIG            0x1C
#define INS_RESET                   0x1E    // Reset device

static const cmd_t cmds[] = {
    { INS_READ_CONFIG, cmd_read_config },
    { INS_WRITE_CONFIG, cmd_write_config },
    { INS_RESET, cmd_factory_reset },
    { 0x00, 0x0 }
};

static int man_process_apdu(void) {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
