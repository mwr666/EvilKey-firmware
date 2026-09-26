/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include "sdkconfig.h"
#include "esp_arduino_version.h"
#include "../FidoConfig.h"
#include "pf_firmware_version.h" /* PF_FIRMWARE_VERSION_FIX_R2 */
#include "pf_device_profile.h"
#if !defined(ARDUINO_ARCH_ESP32) || !defined(CONFIG_IDF_TARGET_ESP32S3)
#error "Select ESP32S3 Dev Module (ESP32-S3 only)"
#endif
#if ESP_ARDUINO_VERSION != ESP_ARDUINO_VERSION_VAL(3, 3, 11) && \
    ESP_ARDUINO_VERSION != ESP_ARDUINO_VERSION_VAL(3, 3, 12)
#error "This port supports esp32 by Espressif Systems 3.3.11 or 3.3.12 only"
#endif
#if !defined(ARDUINO_USB_MODE) || ARDUINO_USB_MODE != 0
#error "Tools > USB Mode must be USB-OTG (TinyUSB), not Hardware CDC/JTAG"
#endif
#if ARDUINO_USB_CDC_ON_BOOT || ARDUINO_USB_MSC_ON_BOOT || ARDUINO_USB_DFU_ON_BOOT
#error "Disable menu USB CDC/MSC/DFU on boot; firmware registers FIDO and optional Manager Drive itself"
#endif
#if !CONFIG_TINYUSB_ENABLED || !CONFIG_TINYUSB_HID_ENABLED
#error "The selected Arduino core must provide native TinyUSB HID"
#endif
#if (FIDO_V1_MANAGER_DRIVE || FIDO_V1_USB_TOOL) && !CONFIG_TINYUSB_MSC_ENABLED
#error "Manager Drive and USB Tool STORAGE require TinyUSB MSC support in the selected Arduino-ESP32 core"
#endif
#if FIDO_V1_MANAGER_DRIVE != 0 && FIDO_V1_MANAGER_DRIVE != 1
#error "FIDO_V1_MANAGER_DRIVE must be 0 or 1"
#endif
#if FIDO_V1_MANAGER_DRIVE_DEFAULT != 0 && FIDO_V1_MANAGER_DRIVE_DEFAULT != 1
#error "FIDO_V1_MANAGER_DRIVE_DEFAULT must be 0 or 1"
#endif
#if FIDO_V1_MANAGER_DRIVE_DEFAULT && !FIDO_V1_MANAGER_DRIVE
#error "Manager Drive cannot default ON when the feature is disabled"
#endif
#if FIDO_V1_MANAGER_DRIVE_SD_HZ < 4000000UL || FIDO_V1_MANAGER_DRIVE_SD_HZ > 25000000UL
#error "FIDO_V1_MANAGER_DRIVE_SD_HZ must be 4..25 MHz"
#endif
#if FIDO_V1_MANAGER_DRIVE_VID <= 0 || FIDO_V1_MANAGER_DRIVE_VID >= 0xFFFF || \
    FIDO_V1_MANAGER_DRIVE_PID <= 0 || FIDO_V1_MANAGER_DRIVE_PID >= 0xFFFF
#error "Manager Drive VID/PID must be nonzero 16-bit identifiers other than FFFF"
#endif
#if FIDO_V1_USB_TOOL != 0 && FIDO_V1_USB_TOOL != 1
#error "FIDO_V1_USB_TOOL must be 0 or 1"
#endif
#if FIDO_V1_USB_TOOL_DEFAULT != 0 && FIDO_V1_USB_TOOL_DEFAULT != 1
#error "FIDO_V1_USB_TOOL_DEFAULT must be 0 or 1"
#endif
#if FIDO_V1_USB_TOOL_DEFAULT && !FIDO_V1_USB_TOOL
#error "USB Tool cannot default ON when the feature is disabled"
#endif
#if FIDO_V1_USB_TOOL_LAYOUT_DEFAULT < 0 || FIDO_V1_USB_TOOL_LAYOUT_DEFAULT > 4
#error "FIDO_V1_USB_TOOL_LAYOUT_DEFAULT must be 0..4"
#endif
#ifdef __cplusplus
static_assert(sizeof(FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT)>1 && sizeof(FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT)<=20,
              "USB Tool language code must be 1..19 ASCII characters");
#endif
#if FIDO_V1_USB_TOOL_SD_HZ < 4000000UL || FIDO_V1_USB_TOOL_SD_HZ > 25000000UL
#error "FIDO_V1_USB_TOOL_SD_HZ must be 4..25 MHz"
#endif
#if FIDO_V1_USB_TOOL_MAX_PAYLOAD < 1024U || FIDO_V1_USB_TOOL_MAX_PAYLOAD > (256U * 1024U)
#error "FIDO_V1_USB_TOOL_MAX_PAYLOAD must be 1..256 KiB"
#endif
#if FIDO_V1_USB_TOOL_VID <= 0 || FIDO_V1_USB_TOOL_VID >= 0xFFFF || \
    FIDO_V1_USB_TOOL_PID <= 0 || FIDO_V1_USB_TOOL_PID >= 0xFFFF
#error "USB Tool VID/PID must be nonzero 16-bit identifiers other than FFFF"
#endif
#ifdef __cplusplus
static_assert(sizeof(FIDO_V1_USB_TOOL_PRODUCT) > 1 && sizeof(FIDO_V1_USB_TOOL_PRODUCT) <= 32,
              "USB Tool product must be 1..31 ASCII characters");
static_assert(sizeof(FIDO_V1_USB_TOOL_MANUFACTURER) > 1 && sizeof(FIDO_V1_USB_TOOL_MANUFACTURER) <= 32,
              "USB Tool manufacturer must be 1..31 ASCII characters");
#endif
#ifdef __cplusplus
static_assert(sizeof(FIDO_V1_MANAGER_DRIVE_PRODUCT) > 1 &&
              sizeof(FIDO_V1_MANAGER_DRIVE_PRODUCT) <= 32,
              "Manager Drive USB product must be 1..31 ASCII characters");
static_assert(sizeof(FIDO_V1_MANAGER_DRIVE_MANUFACTURER) > 1 &&
              sizeof(FIDO_V1_MANAGER_DRIVE_MANUFACTURER) <= 32,
              "Manager Drive manufacturer must be 1..31 ASCII characters");
#endif
#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_FLASH_ENC_ENABLED) || \
    defined(CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT) || defined(CONFIG_NVS_ENCRYPTION)
#error "DEVELOPMENT ONLY: provisioning and encrypted-NVS builds are not supported"
#endif
#if FIDO_V1_BRIGHTNESS < 8 || FIDO_V1_BRIGHTNESS > 255
#error "FIDO_V1_BRIGHTNESS must be 8..255 in the manager build"
#endif
#if FIDO_V1_DIM_AFTER_SECONDS < 0 || FIDO_V1_DIM_AFTER_SECONDS > 3600
#error "FIDO_V1_DIM_AFTER_SECONDS must be 0..3600"
#endif
#if FIDO_V1_TOUCH_CONFIRM && !FIDO_V1_DISPLAY
#error "Touch approval requires a working display"
#endif
#ifndef ESP_PLATFORM
#define ESP_PLATFORM 1
#endif
#ifndef CONFIG_TINYUSB_TASK_PRIORITY
#define CONFIG_TINYUSB_TASK_PRIORITY 5
#endif
#define USB_ITF_HID 1
#define DEBUG_APDU 0
#define FORCE_BUTTON_WAIT 1
/* All private Mbed TLS identifiers/macros are prefixed during preparation.
 * Do NOT mix these types with the core's system Mbed TLS ABI.
 */
#define PF_MBEDTLS_CONFIG_FILE 1
#define PF_MBEDTLS_ECP_DP_ED25519_ENABLED 1
#define PF_MBEDTLS_ECP_DP_ED448_ENABLED 1
#define PF_MBEDTLS_EDDSA_C 1
#define PF_MBEDTLS_SHA3_C 1
#if FIDO_V1_DISPLAY
#define CONFIG_WS_V1_DISPLAY 1
#endif
#if FIDO_V1_TOUCH_CONFIRM
#define CONFIG_WS_V1_TOUCH_CONFIRM 1
#endif
#define CONFIG_WS_V1_BRIGHTNESS FIDO_V1_BRIGHTNESS
#define CONFIG_WS_V1_DIM_AFTER_SECONDS FIDO_V1_DIM_AFTER_SECONDS

#if FIDO_V1_LOCAL_UV && (!FIDO_V1_DISPLAY || !FIDO_V1_TOUCH_CONFIRM)
#error "On-device PIN requires display and touch confirmation"
#endif
#if FIDO_V1_LOCAL_UV != 0 && FIDO_V1_LOCAL_UV != 1
#error "FIDO_V1_LOCAL_UV must be 0 or 1"
#endif
#if FIDO_V1_BOOT_CONFIRM_FALLBACK != 0 && FIDO_V1_BOOT_CONFIRM_FALLBACK != 1
#error "FIDO_V1_BOOT_CONFIRM_FALLBACK must be 0 or 1"
#endif
#if FIDO_V1_UV_TIMEOUT_SECONDS < 15 || FIDO_V1_UV_TIMEOUT_SECONDS > 120
#error "FIDO_V1_UV_TIMEOUT_SECONDS must be 15..120"
#endif

#if FIDO_V1_DIM_BRIGHTNESS < 1 || FIDO_V1_DIM_BRIGHTNESS > 32 || FIDO_V1_DIM_BRIGHTNESS > FIDO_V1_BRIGHTNESS
#error "FIDO_V1_DIM_BRIGHTNESS must be 1..32 and not exceed full brightness"
#endif
#if FIDO_V1_DIM_AFTER_SECONDS != 0 && FIDO_V1_DIM_AFTER_SECONDS < 5
#error "Idle dim interval must be 0 or 5..3600 seconds"
#endif
#if FIDO_V1_OFF_AFTER_DIM_SECONDS < 0 || FIDO_V1_OFF_AFTER_DIM_SECONDS > 3600 || (FIDO_V1_OFF_AFTER_DIM_SECONDS > 0 && FIDO_V1_OFF_AFTER_DIM_SECONDS < 5)
#error "Display-off interval must be 0 or 5..3600 seconds"
#endif
