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

#include "../../../sdk/src/picokeys.h"
#include "../../../crypto/include/mbedtls/ecp.h"
#include "../../../crypto/include/mbedtls/ecdh.h"
#include "../../../crypto/include/mbedtls/sha256.h"
#include "../../../crypto/include/mbedtls/hkdf.h"
#include "../../../crypto/include/mbedtls/constant_time.h"
#include "../../../cbor/src/cbor.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "../../../sdk/src/usb/hid/ctap_hid.h"
#include "fido.h"
#include "files.h"
#include "../../../sdk/src/rng/random.h"
#include "../../../sdk/src/crypto_utils.h"
#include "../../../sdk/src/apdu.h"
#include "object_authorization.h"

uint32_t usage_timer = 0, initial_usage_time_limit = 0;
uint32_t max_usage_time_period  = 600 * 1000;
bool needs_power_cycle = false;
static pf_mbedtls_ecdh_context hkey;
static bool hkey_init = false;
#define PIN_LEGACY_DATA_LEN 34
#define PIN_DATA_LEN 35
#define PIN_RETRY_COMMIT_TIMEOUT_MS 500

static bool minpin_record_has_header(const file_t *ef) {
    return file_has_data(ef) && file_get_size(ef) >= 2;
}

static int minpin_read_length(const file_t *ef, uint8_t *min_pin) {
    if (!min_pin) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *min_pin = 4;
    if (!ef || !ef->data) {
        return PICOKEYS_OK;
    }
    return file_read_at(ef, 0, BYTE_ARRAY(min_pin, sizeof(*min_pin)));
}

static bool minpin_force_change_pending(const file_t *ef) {
    if (!ef || !ef->data) {
        return false;
    }

    uint8_t pending = 0;
    if (file_read_at(ef, 1, BYTE_ARRAY(&pending, sizeof(pending))) != PICOKEYS_OK) {
        return true;
    }
    return pending != 0;
}

static bool load_pin_data(const file_t *ef, uint8_t pin_data[PIN_DATA_LEN], uint16_t *pin_data_len) {
    uint32_t stored_len = file_get_size(ef);
    const uint8_t *data = file_get_data(ef);

    if (!data || (stored_len != PIN_LEGACY_DATA_LEN && stored_len != PIN_DATA_LEN)) {
        return false;
    }
    uint16_t len = (uint16_t)stored_len;

    memset(pin_data, 0, PIN_DATA_LEN);
    memcpy(pin_data, data, len);
    *pin_data_len = len;
    return true;
}

static bool persist_pin_retry_counter(file_t *ef, const uint8_t *pin_data, uint16_t pin_data_len) {
    if (file_put_data(ef, CONST_BYTE_ARRAY(pin_data, pin_data_len)) != PICOKEYS_OK) {
        return false;
    }
    // Do not trust the decremented RAM copy until core0 has drained the flash queue.
    if (!flash_commit_sync(PIN_RETRY_COMMIT_TIMEOUT_MS) || file_get_size(ef) != pin_data_len || !file_get_data(ef)) {
        return false;
    }
    return file_get_data(ef)[0] == pin_data[0];
}

static bool pin_power_cycle_locked(void) {
    return needs_power_cycle || (ef_pin && file_has_data(ef_pin) && (*file_get_data(ef_pin) & PIN_RETRY_POWER_CYCLE) != 0);
}

static int beginUsingPinUvAuthToken(bool userIsPresent) {
    paut.user_present = userIsPresent;
    paut.user_verified = true;
    initial_usage_time_limit = board_millis();
    usage_timer = board_millis();
    paut.in_use = true;
    fido_object_authorization_session_invalidate();
    return 0;
}

void clearUserPresentFlag(void) {
    if (paut.in_use == true && paut.user_present) {
        paut.user_present = false;
        fido_object_authorization_session_invalidate();
    }
}

void clearUserVerifiedFlag(void) {
    if (paut.in_use == true && paut.user_verified) {
        paut.user_verified = false;
        fido_object_authorization_session_invalidate();
    }
}

void clearPinUvAuthTokenPermissionsExceptLbw(void) {
    if (paut.in_use == true && paut.permissions != CTAP_PERMISSION_LBW) {
        paut.permissions = CTAP_PERMISSION_LBW;
        fido_object_authorization_session_invalidate();
    }
}

static void stopUsingPinUvAuthToken(void) {
    bool token_active = paut.in_use || paut.permissions != 0 || paut.has_rp_id || paut.user_present || paut.user_verified;

    paut.permissions = 0;
    usage_timer = 0;
    paut.in_use = false;
    memset(paut.rp_id_hash, 0, sizeof(paut.rp_id_hash));
    paut.has_rp_id = false;
    initial_usage_time_limit = 0;
    paut.user_present = paut.user_verified = false;
    user_present_time_limit = 0;
    if (token_active) {
        fido_object_authorization_session_invalidate();
    }
}

bool getUserPresentFlagValue(void) {
    if (paut.in_use != true) {
        paut.user_present = false;
    }
    return paut.user_present;
}

bool getUserVerifiedFlagValue(void) {
    if (paut.in_use != true) {
        paut.user_verified = false;
    }
    return paut.user_verified;
}

static int regenerate(void) {
    pf_mbedtls_ecdh_context tmp;
    pf_mbedtls_ecdh_init(&tmp);

    int ret = pf_mbedtls_ecdh_setup(&tmp, PF_MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        pf_mbedtls_ecdh_free(&tmp);
        return ret;
    }
    ret = pf_mbedtls_ecdh_gen_public(&tmp.ctx.mbed_ecdh.grp, &tmp.ctx.mbed_ecdh.d, &tmp.ctx.mbed_ecdh.Q, random_fill_iterator, NULL);
    if (ret != 0) {
        pf_mbedtls_ecdh_free(&tmp);
        return ret;
    }
    ret = pf_mbedtls_mpi_lset(&tmp.ctx.mbed_ecdh.Qp.Z, 1);
    if (ret != 0) {
        pf_mbedtls_ecdh_free(&tmp);
        return ret;
    }

    if (hkey_init == true) {
        pf_mbedtls_ecdh_free(&hkey);
    }
    hkey = tmp;
    hkey_init = true;
    return 0;
}

static int kdf(uint8_t protocol, const pf_mbedtls_mpi *z, uint8_t *sharedSecret) {
    int ret = 0;
    uint8_t buf[32];
    ret = pf_mbedtls_mpi_write_binary(z, buf, sizeof(buf));
    if (ret != 0) {
        return ret;
    }
    if (protocol == 1) {
        return pf_mbedtls_md(pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256), buf, sizeof(buf), sharedSecret);
    }
    else if (protocol == 2) {
        const pf_mbedtls_md_info_t *md_info = pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256);
        ret = pf_mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *) "CTAP2 HMAC key", 14, sharedSecret, 32);
        if (ret != 0) {
            return ret;
        }
        return pf_mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *) "CTAP2 AES key", 13, sharedSecret + 32, 32);
    }
    return -1;
}

int ecdh(uint8_t protocol, const pf_mbedtls_ecp_point *Q, uint8_t *sharedSecret) {
    pf_mbedtls_mpi z;
    pf_mbedtls_mpi_init(&z);
    int ret = pf_mbedtls_ecdh_compute_shared(&hkey.ctx.mbed_ecdh.grp, &z, Q, &hkey.ctx.mbed_ecdh.d, random_fill_iterator, NULL);
    if (ret == 0) ret = kdf(protocol, &z, sharedSecret);
    pf_mbedtls_mpi_free(&z);
    return ret;
}

static void resetAuthToken(bool persistent) {
    uint16_t fid = EF_AUTHTOKEN;
    if (persistent) {
        fid = EF_PAUTHTOKEN;
    }
    file_t *ef = file_search_by_fid(fid, NULL, SPECIFY_EF);
    uint8_t t[32];
    random_fill_buffer(BYTE_ARRAY(t, sizeof(t)));
    file_put_data(ef, CONST_BYTE_ARRAY(t, sizeof(t)));
    flash_commit();
}

int resetPinUvAuthToken(void) {
    resetAuthToken(false);
    paut.permissions = 0;
    paut.data = file_get_data(ef_authtoken);
    paut.len = file_get_size(ef_authtoken);
    fido_object_authorization_session_invalidate();
    return 0;
}

int resetPersistentPinUvAuthToken(void) {
    resetAuthToken(true);
    file_t *ef_pauthtoken = file_search_by_fid(EF_PAUTHTOKEN, NULL, SPECIFY_EF);
    ppaut.permissions = 0;
    ppaut.data = file_get_data(ef_pauthtoken);
    ppaut.len = file_get_size(ef_pauthtoken);
    fido_object_authorization_session_invalidate();
    return 0;
}

int encrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_encrypt(CONST_BYTE_ARRAY(key, 32), NULL, PICOKEYS_AES_MODE_CBC, BYTE_ARRAY(out, in_len));
    }
    else if (protocol == 2) {
        random_fill_buffer(BYTE_ARRAY(out, IV_SIZE));
        memcpy(out + IV_SIZE, in, in_len);
        return aes_encrypt(CONST_BYTE_ARRAY(key + 32, 32), out, PICOKEYS_AES_MODE_CBC, BYTE_ARRAY(out + IV_SIZE, in_len));
    }

    return -1;
}

int decrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_decrypt(CONST_BYTE_ARRAY(key, 32), NULL, PICOKEYS_AES_MODE_CBC, BYTE_ARRAY(out, in_len));
    }
    else if (protocol == 2) {
        memcpy(out, in + IV_SIZE, in_len - IV_SIZE);
        return aes_decrypt(CONST_BYTE_ARRAY(key + 32, 32), in, PICOKEYS_AES_MODE_CBC, BYTE_ARRAY(out, in_len - IV_SIZE));
    }

    return -1;
}

int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, uint16_t len, uint8_t *sign) {
    uint8_t hmac[32];
    //if (paut.in_use == false)
    //    return -2;
    int ret = pf_mbedtls_md_hmac(pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0) {
        return ret;
    }
    if (protocol == 1) {
        return pf_mbedtls_ct_memcmp(sign, hmac, 16);
    }
    else if (protocol == 2) {
        return pf_mbedtls_ct_memcmp(sign, hmac, 32);
    }
    return -1;
}

int verify_hmac_secret(uint8_t protocol, const uint8_t *key, const uint8_t *data, uint16_t len, const uint8_t *sign, uint16_t sign_len) {
    uint8_t hmac[32];
    uint16_t expected_len;
    if (protocol == 1) {
        expected_len = 16;
    }
    else if (protocol == 2) {
        expected_len = 32;
    }
    else {
        return -1;
    }
    if (sign_len != expected_len) {
        return -1;
    }
    int ret = pf_mbedtls_md_hmac(pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0) {
        return ret;
    }
    return pf_mbedtls_ct_memcmp(sign, hmac, expected_len);
}

static int initialize(void) {
    regenerate();
    return resetPinUvAuthToken();
}

void pin_uv_auth_token_tick(void) {
    uint32_t now = board_millis();
    if (usage_timer == 0) {
        return;
    }
    if (paut.in_use == true && (usage_timer + max_usage_time_period <= now || initial_usage_time_limit == 0 || initial_usage_time_limit + TRANSPORT_TIME_LIMIT <= now)) {
        stopUsingPinUvAuthToken();
        return;
    }
    if (user_present_time_limit == 0 || user_present_time_limit + TRANSPORT_TIME_LIMIT <= now) {
        clearUserPresentFlag();
    }
}

static int check_keydev_encrypted(const uint8_t pin_token[32]) {
    if (file_get_data(ef_keydev) && *file_get_data(ef_keydev) == 0x01) {
        uint8_t tmp_keydev[61];
        tmp_keydev[0] = 0x03; // Change format to encrypted
        int ret = encrypt_with_aad(pin_token, CONST_BYTE_ARRAY(file_get_data(ef_keydev) + 1, 32), 2, tmp_keydev + 1);
        if (ret != PICOKEYS_OK) {
            pf_mbedtls_platform_zeroize(tmp_keydev, sizeof(tmp_keydev));
            return ret;
        }
        file_put_data(ef_keydev, CONST_BYTE_ARRAY(tmp_keydev, sizeof(tmp_keydev)));
        pf_mbedtls_platform_zeroize(tmp_keydev, sizeof(tmp_keydev));
        flash_commit();
        keydev_unlocked = true;
    }
    return PICOKEYS_OK;
}

static bool pin_policy_pass(const uint8_t *pin, size_t pin_len) {
    file_t *ef_pin_complexity_policy = file_search_by_fid(EF_PIN_COMPLEXITY_POLICY, NULL, SPECIFY_EF);
    if (!file_has_data(ef_pin_complexity_policy)) {
        return true;
    }
    uint16_t policy = get_uint16_be(file_get_data(ef_pin_complexity_policy));
    if (policy == 0) {
        return true;
    }
    bool has_upper = false, has_lower = false, has_digit = false, has_symbol = false;
    for (size_t i = 0; i < pin_len; i++) {
        if (pin[i] >= 'A' && pin[i] <= 'Z') {
            has_upper = true;
        }
        else if (pin[i] >= 'a' && pin[i] <= 'z') {
            has_lower = true;
        }
        else if (pin[i] >= '0' && pin[i] <= '9') {
            has_digit = true;
        }
        else {
            has_symbol = true;
        }
    }
    if (policy & PIN_POLICY_UPPER && !has_upper) {
        return false;
    }
    if (policy & PIN_POLICY_LOWER && !has_lower) {
        return false;
    }
    if (policy & PIN_POLICY_DIGIT && !has_digit) {
        return false;
    }
    if (policy & PIN_POLICY_SYMBOL && !has_symbol) {
        return false;
    }
    return true;
}

static uint16_t pin_codepoint_len(const uint8_t *pin, size_t pin_len) {
    uint16_t count = 0;

    for (size_t i = 0; i < pin_len; i++) {
        if ((pin[i] & 0xC0) != 0x80) {
            count++;
        }
    }
    return count;
}


#include "../../../board/ws_local_uv.h"
#include "../../../board/ws_pinpad.h"
#include "../../../board/ws_uv_retries.h"
#include "../../../sdk/src/button.h" /* Shared SDK cancellation flag; do not redeclare locally. */
static int pf_local_uv_token(uint8_t,uint64_t,int64_t,int64_t,int64_t,
    const CborByteString *,const CborByteString *,const CborCharString *,uint8_t [48],uint16_t *);

uint8_t new_pin_mismatches = 0;

int cbor_client_pin(const uint8_t *data, size_t len) {
    size_t resp_size = 0;
    uint64_t subcommand = 0x0, pinUvAuthProtocol = 0, permissions = 0;
    bool protocol_present=false, permissions_present=false;
    int64_t kty = 0, alg = 0, crv = 0;
    CborParser parser;
    CborEncoder encoder, mapEncoder;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = { 0 }, newPinEnc = { 0 }, pinHashEnc = { 0 }, kax = { 0 }, kay = { 0 };
    CborCharString rpId = { 0 };
    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    uint8_t keydev[32] = {0};
    if (hkey_init == false) {
        initialize();
    }
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        /* Retry queries may omit protocol (key 1). */
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
            protocol_present=true;
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x03) {
            CBOR_CHECK(COSE_read_key(&_f1, &kty, &alg, &crv, &kax, &kay));
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x05) {
            CBOR_FIELD_GET_BYTES(newPinEnc, 1);
        }
        else if (val_u == 0x06) {
            CBOR_FIELD_GET_BYTES(pinHashEnc, 1);
        }
        else if (val_u == 0x09) {
            CBOR_FIELD_GET_UINT(permissions, 1);
            permissions_present=true;
        }
        else if (val_u == 0x0A) {
            CBOR_FIELD_GET_TEXT(rpId, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    if (subcommand == 0 || (!protocol_present && subcommand != 1 && subcommand != 7)) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    if (protocol_present && pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    if (subcommand == 0x0) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    else if (subcommand == 0x1) { //getPINRetries
        bool power_cycle_locked = pin_power_cycle_locked();
        uint8_t retries = file_has_data(ef_pin) ? *file_get_data(ef_pin) & PIN_RETRY_COUNT_MASK : MAX_PIN_RETRIES;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, power_cycle_locked ? 2 : 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, retries));
        if (power_cycle_locked) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, true));
        }
    }
#if FIDO_V1_LOCAL_UV
    else if (subcommand == 0x7) { /* getUVRetries */
        int n=ws_uv_retries_get();
        if(n<0) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
        if(file_has_data(ef_pin) && (*file_get_data(ef_pin)&PIN_RETRY_COUNT_MASK)==0) n=0;
        CBOR_CHECK(cbor_encoder_create_map(&encoder,&mapEncoder,1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder,0x05));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder,(uint64_t)n));
    }
    else if (subcommand == 0x6) { /* getPinUvAuthTokenUsingUvWithPermissions */
        if(!permissions_present || !kax.present || !kay.present) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if(pinHashEnc.present || newPinEnc.present || pinUvAuthParam.present) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t wrapped[48]={0}; uint16_t wrapped_len=0;
        int uv_error=pf_local_uv_token((uint8_t)pinUvAuthProtocol,permissions,kty,alg,crv,
            &kax,&kay,&rpId,wrapped,&wrapped_len);
        if(uv_error) { CBOR_ERROR(uv_error); }
        /* Fixed-size response always fits the CTAP buffer. */
        CborError encode_error=cbor_encoder_create_map(&encoder,&mapEncoder,1);
        if(encode_error==CborNoError) encode_error=cbor_encode_uint(&mapEncoder,0x02);
        if(encode_error==CborNoError) encode_error=cbor_encode_byte_string(&mapEncoder,wrapped,wrapped_len);
        pf_mbedtls_platform_zeroize(wrapped,sizeof(wrapped));
        CBOR_CHECK(encode_error);
    }
#endif
    else if (subcommand == 0x2) { //getKeyAgreement
        if (pinUvAuthProtocol == 1 || pinUvAuthProtocol == 2) {
            CborEncoder mapEncoder2;
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));

            CBOR_CHECK(COSE_key_shared(&hkey, &mapEncoder, &mapEncoder2));
        }
        else {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
    }
    else if (subcommand == 0x3) { //setPIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 ||
            newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        if ((pinUvAuthProtocol == 1 && (newPinEnc.len < 64 || (newPinEnc.len % 16) != 0)) ||
            (pinUvAuthProtocol == 2 &&
             (newPinEnc.len < 64 + IV_SIZE || ((newPinEnc.len - IV_SIZE) % 16) != 0))) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (verify((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, pinUvAuthParam.data) != 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint16_t new_pin_plain_len = pinUvAuthProtocol == 1 ? (uint16_t)newPinEnc.len : (uint16_t)(newPinEnc.len - IV_SIZE);
        uint8_t paddedNewPin[256 + IV_SIZE] = { 0 };
        if (new_pin_plain_len > sizeof(paddedNewPin)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, paddedNewPin);
        pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (new_pin_plain_len > 64 || paddedNewPin[63] != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        uint16_t pin_byte_len = 0;
        while (pin_byte_len < sizeof(paddedNewPin) && paddedNewPin[pin_byte_len] != 0) {
            pin_byte_len++;
        }
        uint16_t pin_codepoints = pin_codepoint_len(paddedNewPin, pin_byte_len);
        uint8_t minPin = 4;
        file_t *ef_minpin = file_search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (minpin_read_length(ef_minpin, &minPin) != PICOKEYS_OK) {
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        if (pin_codepoints < minPin) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if (!pin_policy_pass(paddedNewPin, pin_byte_len)) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        uint8_t hsh[35], dhash[32];
        hsh[0] = MAX_PIN_RETRIES;
        hsh[1] = (uint8_t)pin_codepoints;
        hsh[2] = 1; // New format indicator
        pf_mbedtls_md(pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256), paddedNewPin, pin_byte_len, dhash);
        pf_mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
        pin_derive_verifier(CONST_BYTE_ARRAY(dhash, 16), hsh + 3);
        file_put_data(ef_pin, CONST_BYTE_ARRAY(hsh, sizeof(hsh)));
        flash_commit();

        pin_derive_session(CONST_BYTE_ARRAY(dhash, 16), session_pin);
        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEYS_OK) {
            CBOR_ERROR(ret);
        }
        pf_mbedtls_platform_zeroize(hsh, sizeof(hsh));
        pf_mbedtls_platform_zeroize(dhash, sizeof(dhash));
        new_pin_mismatches = 0;
#if FIDO_V1_LOCAL_UV
        if (!ws_uv_retries_reset()) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
#endif
        needs_power_cycle = false;

        goto err; //No return
    }
    else if (subcommand == 0x4) { //changePIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 ||
            newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0 ||
            pinHashEnc.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (!file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if ((*file_get_data(ef_pin) & PIN_RETRY_COUNT_MASK) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        if (needs_power_cycle) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        if ((pinUvAuthProtocol == 1 && ((newPinEnc.len < 64 || (newPinEnc.len % 16) != 0) || pinHashEnc.len != 16)) ||
            (pinUvAuthProtocol == 2 &&
             ((newPinEnc.len < 64 + IV_SIZE || ((newPinEnc.len - IV_SIZE) % 16) != 0) || pinHashEnc.len != 16 + IV_SIZE))) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if ((pinUvAuthProtocol == 1 && newPinEnc.len > 256) ||
            (pinUvAuthProtocol == 2 && newPinEnc.len > 256 + IV_SIZE)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t tmp[256 + IV_SIZE + 32];
        memcpy(tmp, newPinEnc.data, newPinEnc.len);
        memcpy(tmp + newPinEnc.len, pinHashEnc.data, pinHashEnc.len);
        if (verify((uint8_t)pinUvAuthProtocol, sharedSecret, tmp, (uint16_t)(newPinEnc.len + pinHashEnc.len), pinUvAuthParam.data) != 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t pin_data[PIN_DATA_LEN];
        uint16_t pin_data_len = 0;
        if (!load_pin_data(ef_pin, pin_data, &pin_data_len)) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        if ((pin_data[0] & PIN_RETRY_COUNT_MASK) == 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        pin_data[0] = (uint8_t)((pin_data[0] & PIN_RETRY_POWER_CYCLE) | ((pin_data[0] & PIN_RETRY_COUNT_MASK) - 1));
        if (!persist_pin_retry_counter(ef_pin, pin_data, pin_data_len)) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        uint8_t retries = pin_data[0] & PIN_RETRY_COUNT_MASK;
        bool power_cycle_locked = (pin_data[0] & PIN_RETRY_POWER_CYCLE) != 0;
        uint8_t paddedNewPin[256 + IV_SIZE] = { 0 };
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pinHashEnc.data, (uint16_t)pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t dhash[32], off = 3;
        if (pin_data_len == PIN_LEGACY_DATA_LEN) {
            off = 2;
            double_hash_pin(CONST_BYTE_ARRAY(paddedNewPin, 16), dhash);
        }
        else {
            pin_derive_verifier(CONST_BYTE_ARRAY(paddedNewPin, 16), dhash);
        }

        if (pf_mbedtls_ct_memcmp(dhash, pin_data + off, 32) != 0) {
            regenerate();
            resetPinUvAuthToken();
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (power_cycle_locked || ++new_pin_mismatches >= 3) {
                if (!power_cycle_locked) {
                    pin_data[0] |= PIN_RETRY_POWER_CYCLE;
                    if (!persist_pin_retry_counter(ef_pin, pin_data, pin_data_len)) {
                        CBOR_ERROR(CTAP2_ERR_PROCESSING);
                    }
                }
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
        }
        if (needs_power_cycle) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            pf_mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
            pf_mbedtls_platform_zeroize(dhash, sizeof(dhash));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        if (off == 2) {
            // Upgrade pin file to new format
            pin_data[2] = 1;      // New format indicator
            pin_derive_verifier(CONST_BYTE_ARRAY(paddedNewPin, 16), pin_data + 3);

            hash_multi(CONST_BYTE_ARRAY(paddedNewPin, 16), session_pin);
            ret = load_keydev(keydev);
            if (ret != PICOKEYS_OK) {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
            encrypt_keydev_f1(keydev);
        }
        pin_derive_session(CONST_BYTE_ARRAY(paddedNewPin, 16), session_pin);
        pin_data[0] = MAX_PIN_RETRIES;
        file_put_data(ef_pin, CONST_BYTE_ARRAY(pin_data, sizeof(pin_data)));
        flash_commit();

        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEYS_OK) {
            CBOR_ERROR(ret);
        }

        new_pin_mismatches = 0;
#if FIDO_V1_LOCAL_UV
        if (!ws_uv_retries_reset()) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
#endif
        uint16_t new_pin_plain_len = pinUvAuthProtocol == 1 ? (uint16_t)newPinEnc.len : (uint16_t)(newPinEnc.len - IV_SIZE);
        if (new_pin_plain_len > sizeof(paddedNewPin)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, paddedNewPin);
        pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (new_pin_plain_len > 64 || paddedNewPin[63] != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        uint16_t pin_byte_len = 0;
        while (pin_byte_len < sizeof(paddedNewPin) && paddedNewPin[pin_byte_len] != 0) {
            pin_byte_len++;
        }
        uint16_t pin_codepoints = pin_codepoint_len(paddedNewPin, pin_byte_len);
        uint8_t minPin = 4;
        file_t *ef_minpin = file_search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (minpin_read_length(ef_minpin, &minPin) != PICOKEYS_OK) {
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        if (pin_codepoints < minPin) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if (!pin_policy_pass(paddedNewPin, pin_byte_len)) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        // New PIN is valid and verified
        ret = load_keydev(keydev);
        if (ret != PICOKEYS_OK) {
            CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
        }
        encrypt_keydev_f1(keydev);

        pf_mbedtls_md(pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256), paddedNewPin, pin_byte_len, dhash);
        pin_derive_session(CONST_BYTE_ARRAY(dhash, 16), session_pin);
        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEYS_OK) {
            CBOR_ERROR(ret);
        }
        flash_commit();

        pin_data[0] = MAX_PIN_RETRIES;
        pin_data[1] = (uint8_t)pin_codepoints;
        pin_data[2] = 1; // New format indicator
        pin_derive_verifier(CONST_BYTE_ARRAY(dhash, 16), pin_data + 3);

        if (minpin_record_has_header(ef_minpin) && file_get_data(ef_minpin)[1] == 1 && pf_mbedtls_ct_memcmp(pin_data + 3, file_get_data(ef_pin) + 3, 32) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        file_put_data(ef_pin, CONST_BYTE_ARRAY(pin_data, sizeof(pin_data)));

        pf_mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
        pf_mbedtls_platform_zeroize(dhash, sizeof(dhash));
        if (minpin_record_has_header(ef_minpin) && file_get_data(ef_minpin)[1] == 1) {
            uint8_t *tmpf = (uint8_t *) calloc(1, file_get_size(ef_minpin));
            memcpy(tmpf, file_get_data(ef_minpin), file_get_size(ef_minpin));
            tmpf[1] = 0;
            file_put_data(ef_minpin, CONST_BYTE_ARRAY(tmpf, file_get_size(ef_minpin)));
            free(tmpf);
        }
        flash_commit();
        resetPinUvAuthToken();
        resetPersistentPinUvAuthToken();
        needs_power_cycle = false;
        goto err; // No return
    }
    else if (subcommand == 0x9 || subcommand == 0x5) { //getPinUvAuthTokenUsingPinWithPermissions
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 || alg == 0 ||
            pinHashEnc.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (subcommand == 0x5 && (permissions != 0 || rpId.present == true)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (subcommand == 0x9) {
            if (permissions == 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if ((permissions & CTAP_PERMISSION_BE)) { // Not supported yet
                CBOR_ERROR(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
            }
            if ((permissions & CTAP_PERMISSION_PCMR) && permissions != CTAP_PERMISSION_PCMR) {
                CBOR_ERROR(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
            }
        }
        if (!file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if ((*file_get_data(ef_pin) & PIN_RETRY_COUNT_MASK) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        if (pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t pin_data[PIN_DATA_LEN];
        uint16_t pin_data_len = 0;
        if (!load_pin_data(ef_pin, pin_data, &pin_data_len)) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        if ((pin_data[0] & PIN_RETRY_COUNT_MASK) == 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        pin_data[0] = (uint8_t)((pin_data[0] & PIN_RETRY_POWER_CYCLE) | ((pin_data[0] & PIN_RETRY_COUNT_MASK) - 1));
        if (!persist_pin_retry_counter(ef_pin, pin_data, pin_data_len)) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        uint8_t retries = pin_data[0] & PIN_RETRY_COUNT_MASK;
        bool power_cycle_locked = (pin_data[0] & PIN_RETRY_POWER_CYCLE) != 0;
        uint8_t paddedNewPin[64], poff = ((uint8_t)pinUvAuthProtocol - 1) * IV_SIZE;
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pinHashEnc.data, (uint16_t)pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t dhash[32], off = 3;
        if (pin_data_len == PIN_LEGACY_DATA_LEN) {
            off = 2;
            double_hash_pin(CONST_BYTE_ARRAY(paddedNewPin, 16), dhash);
        }
        else {
            pin_derive_verifier(CONST_BYTE_ARRAY(paddedNewPin, 16), dhash);
        }
        if (pf_mbedtls_ct_memcmp(dhash, pin_data + off, 32) != 0) {
            regenerate();
            resetPinUvAuthToken();
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            pf_mbedtls_platform_zeroize(dhash, sizeof(dhash));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (power_cycle_locked || ++new_pin_mismatches >= 3) {
                if (!power_cycle_locked) {
                    pin_data[0] |= PIN_RETRY_POWER_CYCLE;
                    if (!persist_pin_retry_counter(ef_pin, pin_data, pin_data_len)) {
                        CBOR_ERROR(CTAP2_ERR_PROCESSING);
                    }
                }
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
        }
        if (needs_power_cycle) {
            pf_mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            pf_mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
            pf_mbedtls_platform_zeroize(dhash, sizeof(dhash));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        pf_mbedtls_platform_zeroize(dhash, sizeof(dhash));

        if (off == 2) {
            // Upgrade pin file to new format
            pin_data[2] = 1;      // New format indicator
            pin_derive_verifier(CONST_BYTE_ARRAY(paddedNewPin, 16), pin_data + 3);
            hash_multi(CONST_BYTE_ARRAY(paddedNewPin, 16), session_pin);
            ret = load_keydev(keydev);
            if (ret != PICOKEYS_OK) {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
            encrypt_keydev_f1(keydev);
        }

        pin_derive_session(CONST_BYTE_ARRAY(paddedNewPin, 16), session_pin);
        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEYS_OK) {
            CBOR_ERROR(ret);
        }

        pin_data[0] = MAX_PIN_RETRIES;
        new_pin_mismatches = 0;
#if FIDO_V1_LOCAL_UV
        if (!ws_uv_retries_reset()) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
#endif

        file_put_data(ef_pin, CONST_BYTE_ARRAY(pin_data, sizeof(pin_data)));
        pf_mbedtls_platform_zeroize(pin_data, sizeof(pin_data));

        flash_commit();
        file_t *ef_minpin = file_search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (minpin_force_change_pending(ef_minpin)) {
            if (subcommand == 0x09 && permissions == CTAP_PERMISSION_ACFG && rpId.present == false) {
                CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
        }
        uint8_t pinUvAuthToken_enc[32 + IV_SIZE], *pdata = NULL;
        if (permissions & CTAP_PERMISSION_PCMR) {
            ppaut.permissions = CTAP_PERMISSION_PCMR;
            pdata = ppaut.data;
        }
        else {
            resetPinUvAuthToken();
            beginUsingPinUvAuthToken(false);
            if (subcommand == 0x05) {
                permissions = CTAP_PERMISSION_MC | CTAP_PERMISSION_GA;
            }
            paut.permissions = (uint8_t)permissions;
            if (rpId.present == true) {
                pf_mbedtls_sha256((uint8_t *) rpId.data, rpId.len, paut.rp_id_hash, 0);
                paut.has_rp_id = true;
            }
            else {
                paut.has_rp_id = false;
            }
            pdata = paut.data;
        }
        encrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pdata, 32, pinUvAuthToken_enc);
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pinUvAuthToken_enc, 32 + poff));
        needs_power_cycle = false;
    }
    else {
        CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(newPinEnc);
    CBOR_FREE_BYTE_STRING(pinHashEnc);
    CBOR_FREE_BYTE_STRING(kax);
    CBOR_FREE_BYTE_STRING(kay);
    CBOR_FREE_BYTE_STRING(rpId);
    pf_mbedtls_platform_zeroize(keydev, sizeof(keydev));
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}

/* PF_LOCAL_UV_024 -- compiled in cbor_client_pin.c to reuse the real PIN verifier.
 * No second PIN, no automatic approval, no plaintext PIN sent over USB.
 * Numeric UI uses the existing format-1 FIDO PIN and device-key wrapping.
 * Host ClientPIN is deliberately retained for provisioning and compatibility.
 */
extern bool has_keydev_dec;
extern uint8_t keydev_dec[32];

#include "../../../board/local_uv_binding.h"

static void pf_uv_forget_working_secrets(void) {
    pf_mbedtls_platform_zeroize(session_pin,32);
    pf_mbedtls_platform_zeroize(keydev_dec,32);
    has_keydev_dec=false;
    keydev_unlocked=false;
    stopUsingPinUvAuthToken();
    fido_object_authorization_session_invalidate();
}

bool pf_local_uv_ready(void) {
#if FIDO_V1_LOCAL_UV
    /* R16_RW_PIN_INIT_FIX: Settings can run before the host sends CTAPHID_INIT.
     * At that point ef_pin may still be NULL even though file_scan_flash() has
     * already restored a valid PIN record. Resolve EF_PIN directly instead of
     * treating the lazy global pointer as proof that no PIN is configured.
     * R15 legacy/current record handling remains unchanged. */
    file_t *pin=pf_local_uv_pin_file();
    if(!pin || !file_has_data(pin) || !file_get_data(pin)) return false;
    uint32_t n=file_get_size(pin);
    if(n==PIN_LEGACY_DATA_LEN) return true;
    return n==PIN_DATA_LEN && file_get_data(pin)[2]==1;
#else
    return false;
#endif
}

static int pf_uv_unlock_and_migrate_pin(uint8_t stored[PIN_DATA_LEN],uint16_t stored_len,
                                        const uint8_t h[32],uint8_t key[32]) {
#if !FIDO_V1_LOCAL_UV
    (void)stored;(void)stored_len;(void)h;(void)key;
    return CTAP2_ERR_NOT_ALLOWED;
#else
    const bool legacy=stored_len==PIN_LEGACY_DATA_LEN;
    if(legacy) {
        /* Reproduce upstream ClientPIN's legacy-key migration before switching
         * to the current session KDF. This preserves credentials created before
         * the 35-byte PIN record was introduced. */
        hash_multi(CONST_BYTE_ARRAY(h,16),session_pin);
        if(load_keydev(key)!=PICOKEYS_OK) return CTAP2_ERR_PROCESSING;
        if(encrypt_keydev_f1(key)!=PICOKEYS_OK) return CTAP2_ERR_PROCESSING;
    }
    pin_derive_session(CONST_BYTE_ARRAY(h,16),session_pin);
    if(check_keydev_encrypted(session_pin)!=PICOKEYS_OK || load_keydev(key)!=PICOKEYS_OK)
        return CTAP2_ERR_PROCESSING;
    if(legacy) {
        uint8_t upgraded[PIN_DATA_LEN]={0};
        upgraded[0]=MAX_PIN_RETRIES;
        upgraded[1]=stored[1];
        upgraded[2]=1;
        pin_derive_verifier(CONST_BYTE_ARRAY(h,16),upgraded+3);
        if(file_put_data(ef_pin,CONST_BYTE_ARRAY(upgraded,sizeof(upgraded)))!=PICOKEYS_OK) {
            pf_mbedtls_platform_zeroize(upgraded,sizeof(upgraded));
            return CTAP2_ERR_PROCESSING;
        }
        flash_commit();
        memcpy(stored,upgraded,sizeof(upgraded));
        pf_mbedtls_platform_zeroize(upgraded,sizeof(upgraded));
        new_pin_mismatches=0;
        needs_power_cycle=false;
    }
    return CTAP2_OK;
#endif
}

int pf_local_uv_verify(uint8_t permissions) {
#if !FIDO_V1_LOCAL_UV
    (void)permissions;
    return CTAP2_ERR_NOT_ALLOWED;
#else
    uint8_t stored[PIN_DATA_LEN]={0}, h[32]={0}, verifier[32]={0}, key[32]={0};
    uint16_t stored_len=0;
    char pin[WS_PIN_MAX_BYTES+1]={0};
    size_t length=0;
    int result=CTAP2_ERR_PROCESSING;
    /* Never let an earlier successful operation substitute for a new PIN check. */
    pf_uv_forget_working_secrets();
    if(!pf_local_uv_ready()) { result=CTAP2_ERR_NOT_ALLOWED;goto done; }
    if(!load_pin_data(ef_pin,stored,&stored_len)) goto done;
    /* Exhausting ClientPIN disables ALL user verification, as required by CTAP. */
    if((stored[0]&PIN_RETRY_COUNT_MASK)==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    if(minpin_force_change_pending(file_search_by_fid(EF_MINPINLEN,NULL,SPECIFY_EF))) {
        result=CTAP2_ERR_PIN_POLICY_VIOLATION;goto done;
    }
    int budget=ws_uv_retries_get();
    if(budget<0) goto done;
    if(budget==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    int input=ws_board_get_pin(pin,sizeof(pin),&length,(unsigned)budget,permissions);
    if(input) {
        result=input==1?CTAP2_ERR_KEEPALIVE_CANCEL:input==2?CTAP2_ERR_USER_ACTION_TIMEOUT:CTAP2_ERR_PROCESSING;
        goto done;
    }
    if(cancel_button) { result=CTAP2_ERR_KEEPALIVE_CANCEL;goto done; }
    if(length<4 || length>WS_PIN_MAX_BYTES) goto done;
    for(size_t i=0;i<length;++i) if(pin[i]<'0' || pin[i]>'9') goto done;
    /* Commit BEFORE comparing, so an ordinary power cycle cannot refund a guess. */
    if(!ws_uv_retries_reserve()) goto done;
    if(pf_mbedtls_sha256((const uint8_t *)pin,length,h,0)!=0) goto done;
    pf_mbedtls_platform_zeroize(pin,sizeof(pin));
    uint8_t off=stored_len==PIN_LEGACY_DATA_LEN?2U:3U;
    if(off==2U) double_hash_pin(CONST_BYTE_ARRAY(h,16),verifier);
    else pin_derive_verifier(CONST_BYTE_ARRAY(h,16),verifier);
    if(pf_mbedtls_ct_memcmp(verifier,stored+off,32)!=0) {
        result=budget==1?CTAP2_ERR_UV_BLOCKED:CTAP2_ERR_UV_INVALID;goto done;
    }
    if(!pf_local_uv_bind_keydev_file()) { result=CTAP2_ERR_PROCESSING;goto done; }
    /* Loading the real key is essential; a cosmetic UV flag would not unlock
     * PIN-wrapped resident credentials. Do not fall back to an unwrapped key. */
    result=pf_uv_unlock_and_migrate_pin(stored,stored_len,h,key);
    if(result!=CTAP2_OK) goto done;
    if(cancel_button) { result=CTAP2_ERR_KEEPALIVE_CANCEL;goto done; }
    if(!ws_uv_retries_reset()) goto done;
    result=CTAP2_OK;
done:
    pf_mbedtls_platform_zeroize(pin,sizeof(pin));
    pf_mbedtls_platform_zeroize(stored,sizeof(stored));
    pf_mbedtls_platform_zeroize(h,sizeof(h));
    pf_mbedtls_platform_zeroize(verifier,sizeof(verifier));
    pf_mbedtls_platform_zeroize(key,sizeof(key));
    if(result!=CTAP2_OK) pf_uv_forget_working_secrets();
    ws_board_pin_feedback(result);
    return result;
#endif
}


/* R13 narrow local policy check for Settings READ ONLY -> READ/WRITE.
 * The PIN is collected by the existing on-device pinpad. We reuse the same
 * stored verifier, retry budget and wrapped-device-key validation as normal
 * local UV, but ALWAYS tear down the working PIN/session state before return.
 * Success therefore authorizes exactly one local configuration transition and
 * never creates/reuses a CTAP pinUvAuthToken or user-verification session. */
int pf_local_uv_verify_supplied_pin(const char *pin,size_t length) {
#if !FIDO_V1_LOCAL_UV
    (void)pin;(void)length;
    return CTAP2_ERR_NOT_ALLOWED;
#else
    uint8_t stored[PIN_DATA_LEN]={0}, h[32]={0}, verifier[32]={0}, key[32]={0};
    uint16_t stored_len=0;
    int result=CTAP2_ERR_PROCESSING;
    int budget=-1;
    pf_uv_forget_working_secrets();
    if(!pin || !pf_local_uv_ready()) { result=CTAP2_ERR_NOT_ALLOWED;goto done; }
    if(!load_pin_data(ef_pin,stored,&stored_len)) goto done;
    if((stored[0]&PIN_RETRY_COUNT_MASK)==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    if(minpin_force_change_pending(file_search_by_fid(EF_MINPINLEN,NULL,SPECIFY_EF))) {
        result=CTAP2_ERR_PIN_POLICY_VIOLATION;goto done;
    }
    budget=ws_uv_retries_get();
    if(budget<0) goto done;
    if(budget==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    if(length<4 || length>WS_PIN_MAX_BYTES) { result=CTAP2_ERR_UV_INVALID;goto done; }
    for(size_t i=0;i<length;++i) {
        if(pin[i]<'0' || pin[i]>'9') { result=CTAP2_ERR_UV_INVALID;goto done; }
    }
    /* Match the normal local-UV anti-rollback rule: consume the attempt before
     * comparing, so a power loss cannot refund a wrong PIN guess. */
    if(!ws_uv_retries_reserve()) goto done;
    if(pf_mbedtls_sha256((const uint8_t *)pin,length,h,0)!=0) goto done;
    uint8_t off=stored_len==PIN_LEGACY_DATA_LEN?2U:3U;
    if(off==2U) double_hash_pin(CONST_BYTE_ARRAY(h,16),verifier);
    else pin_derive_verifier(CONST_BYTE_ARRAY(h,16),verifier);
    if(pf_mbedtls_ct_memcmp(verifier,stored+off,32)!=0) {
        result=budget==1?CTAP2_ERR_UV_BLOCKED:CTAP2_ERR_UV_INVALID;goto done;
    }
    if(!pf_local_uv_bind_keydev_file()) { result=CTAP2_ERR_PROCESSING;goto done; }
    /* Validate the same wrapped device key as the normal FIDO verifier. The
     * resulting session/key material is deliberately destroyed below. */
    result=pf_uv_unlock_and_migrate_pin(stored,stored_len,h,key);
    if(result!=CTAP2_OK) goto done;
    if(!ws_uv_retries_reset()) goto done;
    result=CTAP2_OK;
done:
    pf_mbedtls_platform_zeroize(stored,sizeof(stored));
    pf_mbedtls_platform_zeroize(h,sizeof(h));
    pf_mbedtls_platform_zeroize(verifier,sizeof(verifier));
    pf_mbedtls_platform_zeroize(key,sizeof(key));
    /* Unlike pf_local_uv_verify(), Settings authentication never leaves a UV
     * session alive, even after a correct PIN. */
    pf_uv_forget_working_secrets();
    return result;
#endif
}

static int pf_local_uv_token(uint8_t protocol,uint64_t permissions,
                            int64_t kty,int64_t alg,int64_t crv,
                            const CborByteString *x,const CborByteString *y,
                            const CborCharString *rp,uint8_t out[48],uint16_t *out_len) {
#if !FIDO_V1_LOCAL_UV
    (void)protocol;(void)permissions;(void)kty;(void)alg;(void)crv;
    (void)x;(void)y;(void)rp;(void)out;(void)out_len;
    return CTAP2_ERR_INVALID_SUBCOMMAND;
#else
    *out_len=0;
    pf_mbedtls_platform_zeroize(out,48);
    const uint64_t supported=CTAP_PERMISSION_MC|CTAP_PERMISSION_GA|CTAP_PERMISSION_CM|
        CTAP_PERMISSION_LBW|CTAP_PERMISSION_ACFG|CTAP_PERMISSION_PCMR;
    if(!x->present || !y->present) return CTAP2_ERR_MISSING_PARAMETER;
    if((protocol!=1 && protocol!=2) || kty!=2 || alg!=-25 || crv!=1 ||
       x->len!=32 || y->len!=32 || !x->data || !y->data) return CTAP1_ERR_INVALID_PARAMETER;
    if(!permissions) return CTAP1_ERR_INVALID_PARAMETER;
    if((permissions & ~supported) ||
       ((permissions&CTAP_PERMISSION_PCMR) && permissions!=CTAP_PERMISSION_PCMR))
        return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
    if((permissions&(CTAP_PERMISSION_MC|CTAP_PERMISSION_GA)) && !rp->present)
        return CTAP2_ERR_MISSING_PARAMETER;
    if(rp->present && (!rp->data || !rp->len || rp->len>1024)) return CTAP1_ERR_INVALID_PARAMETER;
    if(!hkey_init) return CTAP2_ERR_PROCESSING;
    if(pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X,x->data,x->len)!=0 ||
       pf_mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y,y->data,y->len)!=0 ||
       pf_mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z,1)!=0 ||
       pf_mbedtls_ecp_check_pubkey(&hkey.ctx.mbed_ecdh.grp,&hkey.ctx.mbed_ecdh.Qp)!=0)
        return CTAP1_ERR_INVALID_PARAMETER;
    uint8_t shared[64]={0};
    int result=ecdh(protocol,&hkey.ctx.mbed_ecdh.Qp,shared);
    if(result) { result=CTAP1_ERR_INVALID_PARAMETER;goto done; }
    result=pf_local_uv_verify((uint8_t)permissions);
    if(result) goto done;
    if(cancel_button) { result=CTAP2_ERR_KEEPALIVE_CANCEL;goto done; }
    const uint8_t *token=NULL;
    if(permissions==CTAP_PERMISSION_PCMR) {
        if(!ppaut.data || ppaut.len!=32) { result=CTAP2_ERR_PROCESSING;goto done; }
        ppaut.permissions=CTAP_PERMISSION_PCMR;
        token=ppaut.data;
    } else {
        if(resetPinUvAuthToken()!=0 || !paut.data || paut.len!=32) {
            result=CTAP2_ERR_PROCESSING;goto done;
        }
        beginUsingPinUvAuthToken(true);
        /* Entry plus explicit OK supplies UP, not just UV. It is bound to the
         * token's permissions/RP and consumed by the normal CTAP command path. */
        user_present_time_limit=board_millis();
        paut.permissions=(uint8_t)permissions;
        paut.has_rp_id=rp->present;
        if(rp->present && pf_mbedtls_sha256((const uint8_t *)rp->data,rp->len,paut.rp_id_hash,0)!=0) {
            result=CTAP2_ERR_PROCESSING;goto done;
        }
        token=paut.data;
    }
    if(encrypt(protocol,shared,token,32,out)!=0) { result=CTAP2_ERR_PROCESSING;goto done; }
    *out_len=protocol==1?32:48;
    result=CTAP2_OK;
done:
    pf_mbedtls_platform_zeroize(shared,sizeof(shared));
    if(result) {
        pf_mbedtls_platform_zeroize(out,48);
        pf_uv_forget_working_secrets();
        ppaut.permissions=0;
    }
    return result;
#endif
}
