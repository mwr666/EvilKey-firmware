/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Replacement for pico-keys-sdk/src/otp/otp_esp32.c in the DEVELOPMENT build.
 * NOT a secure storage backend. Secrets are saved in plaintext NVS.
 * This file intentionally contains no eFuse write/burn/protect operations.
 */
#include "sdkconfig.h"
#include "otp_platform.h"
#include "byte_array.h"
#include "random.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/platform_util.h"
#include "esp_err.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdlib.h>
#include <string.h>

#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_FLASH_ENC_ENABLED) || \
    defined(CONFIG_NVS_ENCRYPTION)
#error "The ws_v1 development backend forbids automatic security provisioning"
#endif

static const char *TAG="ws_dev_keys";
static struct {
    uint32_t magic;
    uint32_t version;
    uint8_t key1[32];
    uint8_t key2[32];
} store;

static _Noreturn void fail(const char *reason)
{
    ESP_LOGE(TAG,"%s. Storage was NOT erased. Stop and investigate.",reason);
    abort();
}

bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey)
{
    if(bootkey) *bootkey=0xFF;
    return esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN);
}

bool otp_platform_is_secure_boot_locked(void)
{
    return false; /* This profile cannot enable or provision secure lock. */
}

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock)
{
    (void)bootkey;
    (void)secure_lock;
    ESP_LOGE(TAG,"Secure Boot/Secure Lock rejected by development profile");
    return ESP_ERR_NOT_SUPPORTED;
}

void otp_platform_init(const uint8_t **key1_out,const uint8_t **key2_out)
{
    if(!key1_out || !key2_out) fail("Invalid OTP output pointers");
    if(otp_platform_is_secure_boot_enabled(NULL)) {
        fail("This development build is not intended for an already secure-boot device");
    }
    esp_err_t err=nvs_flash_init_partition("wsdev");
    if(err!=ESP_OK) fail("Cannot initialize wsdev NVS partition");
    nvs_handle_t h;
    if(nvs_open_from_partition("wsdev","pico_fido",NVS_READWRITE,&h)!=ESP_OK) {
        fail("Cannot open development keystore");
    }
    size_t length=sizeof(store);
    err=nvs_get_blob(h,"keys_v1",&store,&length);
    if(err==ESP_ERR_NVS_NOT_FOUND) {
        memset(&store,0,sizeof(store));
        store.magic=0x57534431U; /* WSD1 */
        store.version=1;
        random_fill_buffer(BYTE_ARRAY(store.key1,sizeof(store.key1)));
        mbedtls_ecdsa_context key;
        mbedtls_ecdsa_init(&key);
        int rc=mbedtls_ecdsa_genkey(&key,MBEDTLS_ECP_DP_SECP256K1,
                                  random_fill_iterator,NULL);
        size_t used=0;
        if(rc==0) rc=mbedtls_ecp_write_key_ext(&key,&used,store.key2,sizeof(store.key2));
        mbedtls_ecdsa_free(&key);
        if(rc!=0 || used!=sizeof(store.key2)) {
            mbedtls_platform_zeroize(&store,sizeof(store));
            nvs_close(h);
            fail("Cannot generate development key");
        }
        err=nvs_set_blob(h,"keys_v1",&store,sizeof(store));
        if(err==ESP_OK) err=nvs_commit(h);
        if(err!=ESP_OK) {
            mbedtls_platform_zeroize(&store,sizeof(store));
            nvs_close(h);
            fail("Cannot persist development keys");
        }
        ESP_LOGW(TAG,"New DEVELOPMENT keys saved in unencrypted NVS; eFuses unchanged");
    } else if(err!=ESP_OK || length!=sizeof(store) ||
              store.magic!=0x57534431U || store.version!=1U) {
        mbedtls_platform_zeroize(&store,sizeof(store));
        nvs_close(h);
        fail("Development key record invalid");
    }
    nvs_close(h);
    *key1_out=store.key1;
    *key2_out=store.key2;
}
