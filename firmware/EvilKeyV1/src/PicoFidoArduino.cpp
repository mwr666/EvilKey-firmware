/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "pf_build_config.h"
#if !__has_include("engine_ready.h")
#error "Run prepare_arduino.py from the package root before Verify/Upload"
#endif
#include "engine_ready.h"
#ifndef PF_LOCAL_UV_PATCH
#error "Regenerate the 0.2.4 engine; do not copy an older src/engine tree"
#endif
#if !defined(PF_DEVICE_PROFILE_PATCH) || PF_DEVICE_PROFILE_PATCH != 1
#error "Apply the 0.2.3 profile patch to generated engine sources (see README)"
#endif
#include "PicoFidoArduino.h"
#include "pf_engine_api.h"
#include <Arduino.h>
#include <USB.h>
#include "esp32-hal-tinyusb.h"
#if FIDO_V1_USB_TOOL
#include "UsbTool.h"
#include "engine/board/ws_usb_tool_state.h"
#endif
#if FIDO_V1_MANAGER_DRIVE || FIDO_V1_USB_TOOL
#include "PfUsbMsc.h"
#include <SPI.h>
#include <SD.h>
#include <new>
#include "engine/board/ws_pins.h"
#endif
#if FIDO_V1_MANAGER_DRIVE
#include "engine/board/ws_manager_drive_state.h"
#endif
#include "esp_partition.h"
#include "esp_flash_encrypt.h"
#include "esp_secure_boot.h"
#include "esp_ota_ops.h"
#include "esp_attr.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_mac.h"
#include <cstring>
#include <cstdio>

// USBHID.h is intentionally not included: Pico owns the HID callbacks.
PicoFidoArduinoClass PicoFidoArduino;
static const char *TAG = "pf_arduino";
static const uint8_t fido_report_descriptor[] = {
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
    0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0
};
static const uint8_t air_mouse_report_descriptor[] = {
    TUD_HID_REPORT_DESC_MOUSE()
};
static constexpr uint32_t PF_AIR_MOUSE_BOOT_MAGIC=0xE71A0320UL;
RTC_NOINIT_ATTR static uint32_t s_air_mouse_boot_token;
RTC_NOINIT_ATTR static uint32_t s_air_mouse_boot_token_check;
static bool s_air_mouse_role;

extern "C" bool pf_air_mouse_role(void) { return s_air_mouse_role; }

extern "C" bool pf_air_mouse_report(uint8_t buttons,int8_t x,int8_t y,int8_t wheel) {
    if(!s_air_mouse_role || !tud_hid_ready())return false;
    return tud_hid_mouse_report(0,buttons,x,y,wheel,0);
}

extern "C" void pf_air_mouse_restart_into(void) {
    s_air_mouse_boot_token=PF_AIR_MOUSE_BOOT_MAGIC;
    s_air_mouse_boot_token_check=~PF_AIR_MOUSE_BOOT_MAGIC;
    esp_restart();
}

extern "C" void pf_air_mouse_exit(void) {
    (void)pf_air_mouse_report(0,0,0,0);
    delay(50U);
    esp_restart(); /* One-shot boot token was consumed at startup. */
}
#if FIDO_V1_USB_TOOL
enum {
    PF_USB_TOOL_RID_KEYBOARD=1,
    PF_USB_TOOL_RID_MOUSE=2,
    PF_USB_TOOL_RID_CONSUMER=3,
    PF_USB_TOOL_RID_SYSTEM=4,
    PF_USB_TOOL_RID_ABS_MOUSE=5
};
static const uint8_t usb_tool_report_descriptor[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(PF_USB_TOOL_RID_KEYBOARD)),
    TUD_HID_REPORT_DESC_MOUSE(HID_REPORT_ID(PF_USB_TOOL_RID_MOUSE)),
    TUD_HID_REPORT_DESC_CONSUMER(HID_REPORT_ID(PF_USB_TOOL_RID_CONSUMER)),
    TUD_HID_REPORT_DESC_SYSTEM_CONTROL(HID_REPORT_ID(PF_USB_TOOL_RID_SYSTEM)),
    TUD_HID_REPORT_DESC_ABSMOUSE(HID_REPORT_ID(PF_USB_TOOL_RID_ABS_MOUSE))
};
#endif
static_assert(CFG_TUD_HID_EP_BUFSIZE >= 64, "CTAPHID needs 64-byte reports");

/* The Arduino core normally builds one immutable configuration descriptor.
 * DuckyScript ATTACKMODE is explicitly dynamic, so PicoFido owns all device,
 * string and configuration descriptors and changes them only while detached. */
enum {
    PF_USB_EP_HID=1,
    PF_USB_EP_MSC=2,
    PF_USB_HID_CONFIG_LEN=TUD_CONFIG_DESC_LEN+TUD_HID_INOUT_DESC_LEN,
    PF_USB_MSC_CONFIG_LEN=TUD_CONFIG_DESC_LEN+TUD_MSC_DESC_LEN,
    PF_USB_COMBO_CONFIG_LEN=TUD_CONFIG_DESC_LEN+TUD_HID_INOUT_DESC_LEN+TUD_MSC_DESC_LEN
};

static tusb_desc_device_t s_device_descriptor = {
    sizeof(tusb_desc_device_t), TUSB_DESC_DEVICE, 0x0200,
    0, 0, 0, CFG_TUD_ENDPOINT0_SIZE,
    PF_USB_VID, PF_USB_PID, PF_USB_BCD_DEVICE,
    1, 2, 3, 1
};
static char s_descriptor_manufacturer[33]=PF_USB_MANUFACTURER;
static char s_descriptor_product[33]=PF_USB_PRODUCT;
static char s_descriptor_serial[13]="000000000000";
static char s_default_serial[13]="000000000000";
static volatile uint8_t s_descriptor_attackmode=1U;
static bool s_descriptor_tool_role;
static bool s_descriptor_manager_drive;
static bool s_descriptor_air_mouse_role;
static bool s_descriptor_ready;

/* Apps may own the card only in the plain FIDO descriptor role. In all MSC
 * roles the host or USB Tool owns the same physical microSD medium. */
extern "C" bool pf_apps_storage_role_allowed(void) {
    return s_descriptor_ready && !s_descriptor_tool_role &&
           !s_descriptor_manager_drive && !s_descriptor_air_mouse_role;
}

static const uint8_t s_config_air_mouse_hid[] = {
    TUD_CONFIG_DESCRIPTOR(1,1,0,PF_USB_HID_CONFIG_LEN,0,500),
    TUD_HID_INOUT_DESCRIPTOR(0,0,HID_ITF_PROTOCOL_NONE,
        sizeof(air_mouse_report_descriptor),PF_USB_EP_HID,0x80|PF_USB_EP_HID,64,5)
};
static_assert(sizeof(s_config_air_mouse_hid)==PF_USB_HID_CONFIG_LEN,
              "Air Mouse HID configuration descriptor length mismatch");

static const uint8_t s_config_fido_hid[] = {
    TUD_CONFIG_DESCRIPTOR(1,1,0,PF_USB_HID_CONFIG_LEN,0,500),
    TUD_HID_INOUT_DESCRIPTOR(0,0,HID_ITF_PROTOCOL_NONE,
        sizeof(fido_report_descriptor),PF_USB_EP_HID,0x80|PF_USB_EP_HID,64,5)
};
static_assert(sizeof(s_config_fido_hid)==PF_USB_HID_CONFIG_LEN,
              "FIDO HID configuration descriptor length mismatch");
#if FIDO_V1_USB_TOOL
static const uint8_t s_config_tool_hid[] = {
    TUD_CONFIG_DESCRIPTOR(1,1,0,PF_USB_HID_CONFIG_LEN,0,500),
    TUD_HID_INOUT_DESCRIPTOR(0,0,HID_ITF_PROTOCOL_NONE,
        sizeof(usb_tool_report_descriptor),PF_USB_EP_HID,0x80|PF_USB_EP_HID,64,5)
};
static const uint8_t s_config_tool_storage[] = {
    TUD_CONFIG_DESCRIPTOR(1,1,0,PF_USB_MSC_CONFIG_LEN,0,500),
    TUD_MSC_DESCRIPTOR(0,0,PF_USB_EP_MSC,0x80|PF_USB_EP_MSC,64)
};
static const uint8_t s_config_tool_combo[] = {
    TUD_CONFIG_DESCRIPTOR(1,2,0,PF_USB_COMBO_CONFIG_LEN,0,500),
    TUD_HID_INOUT_DESCRIPTOR(0,0,HID_ITF_PROTOCOL_NONE,
        sizeof(usb_tool_report_descriptor),PF_USB_EP_HID,0x80|PF_USB_EP_HID,64,5),
    TUD_MSC_DESCRIPTOR(1,0,PF_USB_EP_MSC,0x80|PF_USB_EP_MSC,64)
};
static_assert(sizeof(s_config_tool_hid)==PF_USB_HID_CONFIG_LEN,
              "USB Tool HID descriptor length mismatch");
static_assert(sizeof(s_config_tool_storage)==PF_USB_MSC_CONFIG_LEN,
              "USB Tool STORAGE descriptor length mismatch");
static_assert(sizeof(s_config_tool_combo)==PF_USB_COMBO_CONFIG_LEN,
              "USB Tool composite descriptor length mismatch");
#endif
#if FIDO_V1_MANAGER_DRIVE
static const uint8_t s_config_manager_combo[] = {
    TUD_CONFIG_DESCRIPTOR(1,2,0,PF_USB_COMBO_CONFIG_LEN,0,500),
    TUD_HID_INOUT_DESCRIPTOR(0,0,HID_ITF_PROTOCOL_NONE,
        sizeof(fido_report_descriptor),PF_USB_EP_HID,0x80|PF_USB_EP_HID,64,5),
    TUD_MSC_DESCRIPTOR(1,0,PF_USB_EP_MSC,0x80|PF_USB_EP_MSC,64)
};
static_assert(sizeof(s_config_manager_combo)==PF_USB_COMBO_CONFIG_LEN,
              "Manager Drive composite descriptor length mismatch");
#endif

static void descriptor_copy(char *out,size_t out_len,const char *value)
{
    if(!out || out_len==0U)return;
    if(!value)value="";
    strncpy(out,value,out_len-1U);
    out[out_len-1U]='\0';
}

static void descriptor_identity(uint16_t vid,uint16_t pid,uint16_t bcd,
                                const char *manufacturer,const char *product,
                                const char *serial)
{
    s_device_descriptor.idVendor=vid;
    s_device_descriptor.idProduct=pid;
    s_device_descriptor.bcdDevice=bcd;
    descriptor_copy(s_descriptor_manufacturer,sizeof(s_descriptor_manufacturer),manufacturer);
    descriptor_copy(s_descriptor_product,sizeof(s_descriptor_product),product);
    descriptor_copy(s_descriptor_serial,sizeof(s_descriptor_serial),serial);
}

static bool usb_tool_role(void) {
#if FIDO_V1_USB_TOOL
    return !s_air_mouse_role && ws_usb_tool_enabled();
#else
    return false;
#endif
}

#if FIDO_V1_USB_TOOL
extern "C" void pf_usb_configuration_descriptor_requested(void);
#endif

extern "C" uint8_t const *tud_descriptor_device_cb(void)
{
    return reinterpret_cast<uint8_t const *>(&s_device_descriptor);
}

extern "C" uint16_t const *tud_descriptor_string_cb(uint8_t index,uint16_t)
{
    static uint16_t value[33];
    if(index==0U) {
        value[0]=(uint16_t)((TUSB_DESC_STRING<<8)|4U);
        value[1]=0x0409U;
        return value;
    }
    const char *text=index==1U?s_descriptor_manufacturer:
                     index==2U?s_descriptor_product:
                     index==3U?s_descriptor_serial:nullptr;
    if(!text)return nullptr;
    size_t length=strlen(text);
    if(length>32U)length=32U;
    for(size_t i=0;i<length;++i)value[i+1U]=(uint8_t)text[i];
    value[0]=(uint16_t)((TUSB_DESC_STRING<<8)|(2U*length+2U));
    return value;
}

extern "C" uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
    if(index!=0U)return nullptr;
    if(s_descriptor_air_mouse_role)return s_config_air_mouse_hid;
#if FIDO_V1_USB_TOOL
    pf_usb_configuration_descriptor_requested();
    if(s_descriptor_tool_role) {
        switch(s_descriptor_attackmode) {
        case 2U:return s_config_tool_storage;
        case 3U:return s_config_tool_combo;
        case 0U: /* A request racing detach receives the last safe HID shape. */
        case 1U:
        default:return s_config_tool_hid;
        }
    }
#endif
#if FIDO_V1_MANAGER_DRIVE
    if(s_descriptor_manager_drive)return s_config_manager_combo;
#endif
    return s_config_fido_hid;
}

extern "C" uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    if (instance != 0) return nullptr;
    if(s_air_mouse_role)return air_mouse_report_descriptor;
#if FIDO_V1_USB_TOOL
    if (usb_tool_role()) return usb_tool_report_descriptor;
#endif
    return fido_report_descriptor;
}

static uint16_t load_hid_descriptor(uint8_t *dst, uint8_t *itf) {
    /* One TinyUSB HID instance is used in every boot role. FIDO exposes CTAP;
     * USB Tool exposes Keyboard, relative/absolute Mouse, Consumer and System
     * Control report IDs. The role is
     * selected before enumeration and never changes without a restart. */
    if (!dst || !itf) return 0;
    const uint8_t hid_itf = *itf;
    uint8_t ep = tinyusb_get_free_duplex_endpoint();
    if (!ep) return 0;
    const bool tool=usb_tool_role();
    const bool mouse=s_air_mouse_role;
    uint8_t string_id = tinyusb_add_string_descriptor(mouse?"EvilKey Air Mouse":tool?"EvilKey USB Tool HID":"EvilKey HID");
#if FIDO_V1_USB_TOOL
    const uint16_t report_len=mouse?(uint16_t)sizeof(air_mouse_report_descriptor):
        tool?(uint16_t)sizeof(usb_tool_report_descriptor):(uint16_t)sizeof(fido_report_descriptor);
#else
    const uint16_t report_len=mouse?(uint16_t)sizeof(air_mouse_report_descriptor):(uint16_t)sizeof(fido_report_descriptor);
#endif
    const uint8_t descriptor[] = {
        TUD_HID_INOUT_DESCRIPTOR(hid_itf, string_id, HID_ITF_PROTOCOL_NONE,
            report_len, ep, (uint8_t)(ep | 0x80), 64, 5)
    };
    memcpy(dst, descriptor, sizeof(descriptor));
    *itf = (uint8_t)(hid_itf + 1U);
    return sizeof(descriptor);
}

#if FIDO_V1_MANAGER_DRIVE
static USBMSC *s_msc;
static SPIClass s_manager_sd_spi(HSPI);
static volatile bool s_manager_media_ready;

static bool manager_drive_prepare_sd(void) {
    if (!s_manager_sd_spi.begin(WS_SD_SCLK, WS_SD_MISO, WS_SD_MOSI, WS_SD_CS)) {
        ESP_LOGE(TAG, "Manager Drive: cannot start SD SPI bus");
        return false;
    }
    /* Mounting is used only to let the pinned Arduino SD driver initialise the
     * card and expose its public RAW-sector API. Firmware never opens a file on
     * this filesystem while MSC is active. The host may write raw sectors when
     * the authenticated Manager Drive preference is not read-only. */
    if (!SD.begin(WS_SD_CS, s_manager_sd_spi, FIDO_V1_MANAGER_DRIVE_SD_HZ,
                  "/manager-drive", 1, false)) {
        ESP_LOGW(TAG, "Manager Drive: no readable FAT microSD card");
        s_manager_sd_spi.end();
        return false;
    }
    const size_t sector_size = SD.sectorSize();
    const size_t sectors = SD.numSectors();
    if (sector_size != 512U || sectors == 0U || (uint64_t)sectors > UINT32_MAX) {
        ESP_LOGE(TAG, "Manager Drive: unsupported card geometry (%u B, %u sectors)",
                 (unsigned)sector_size, (unsigned)sectors);
        SD.end();
        s_manager_sd_spi.end();
        return false;
    }
    ESP_LOGI(TAG, "Manager Drive: microSD ready, %u sectors, USB mode %s",
             (unsigned)sectors, ws_manager_drive_read_only()?"read-only":"read/write");
    return true;
}

static int32_t manager_drive_read(uint32_t lba, uint32_t offset,
                                  void *buffer, uint32_t bufsize) {
    if (!s_manager_media_ready || !buffer || bufsize == 0U) return -1;
    const uint32_t sector_size = (uint32_t)SD.sectorSize();
    const uint32_t sectors = (uint32_t)SD.numSectors();
    if (sector_size != 512U || sectors == 0U) return -1;
    const uint64_t capacity = (uint64_t)sectors * sector_size;
    uint64_t absolute = (uint64_t)lba * sector_size + offset;
    if (absolute >= capacity || (uint64_t)bufsize > capacity - absolute) return -1;

    uint8_t scratch[512];
    uint8_t *out = static_cast<uint8_t *>(buffer);
    uint32_t remaining = bufsize;
    while (remaining) {
        const uint32_t sector = (uint32_t)(absolute / sector_size);
        const uint32_t in_sector = (uint32_t)(absolute % sector_size);
        uint32_t chunk = sector_size - in_sector;
        if (chunk > remaining) chunk = remaining;
        if (in_sector == 0U && chunk == sector_size) {
            if (!SD.readRAW(out, sector)) return -1;
        } else {
            if (!SD.readRAW(scratch, sector)) return -1;
            memcpy(out, scratch + in_sector, chunk);
        }
        out += chunk;
        remaining -= chunk;
        absolute += chunk;
    }
    return (int32_t)bufsize;
}

static int32_t manager_drive_write(uint32_t lba, uint32_t offset,
                                   uint8_t *buffer, uint32_t bufsize) {
    if (!s_manager_media_ready || !buffer || bufsize == 0U ||
        ws_manager_drive_read_only()) return -1;
    const uint32_t sector_size = (uint32_t)SD.sectorSize();
    const uint32_t sectors = (uint32_t)SD.numSectors();
    if (sector_size != 512U || sectors == 0U) return -1;
    const uint64_t capacity = (uint64_t)sectors * sector_size;
    uint64_t absolute = (uint64_t)lba * sector_size + offset;
    if (absolute >= capacity || (uint64_t)bufsize > capacity - absolute) return -1;

    uint8_t scratch[512];
    uint8_t *in = buffer;
    uint32_t remaining = bufsize;
    while (remaining) {
        const uint32_t sector = (uint32_t)(absolute / sector_size);
        const uint32_t in_sector = (uint32_t)(absolute % sector_size);
        uint32_t chunk = sector_size - in_sector;
        if (chunk > remaining) chunk = remaining;
        if (in_sector == 0U && chunk == sector_size) {
            if (!SD.writeRAW(in, sector)) return -1;
        } else {
            if (!SD.readRAW(scratch, sector)) return -1;
            memcpy(scratch + in_sector, in, chunk);
            if (!SD.writeRAW(scratch, sector)) return -1;
        }
        in += chunk;
        remaining -= chunk;
        absolute += chunk;
    }
    return (int32_t)bufsize;
}

static bool manager_drive_start_stop(uint8_t, bool start, bool load_eject) {
    if (load_eject && !start) {
        s_manager_media_ready = false;
        if (s_msc) s_msc->mediaPresent(false);
        ESP_LOGI(TAG, "Manager Drive: host ejected media");
    }
    return true;
}

static bool manager_drive_register(void) {
    s_msc = new (std::nothrow) USBMSC();
    if (!s_msc) {
        ESP_LOGE(TAG, "Manager Drive: cannot allocate USBMSC object");
        return false;
    }
    s_msc->vendorID("EvilKey");
    s_msc->productID("MANAGER DRIVE");
    s_msc->productRevision("1.0");
    s_msc->onStartStop(manager_drive_start_stop);
    s_msc->onRead(manager_drive_read);
    s_msc->onWrite(manager_drive_write);
    s_msc->isWritable(!ws_manager_drive_read_only());

    const bool media = manager_drive_prepare_sd();
    const uint32_t blocks = media ? (uint32_t)SD.numSectors() : 1U;
    if (!s_msc->begin(blocks, 512U)) {
        ESP_LOGE(TAG, "Manager Drive: USBMSC begin failed");
        return false;
    }
    s_manager_media_ready = media;
    s_msc->mediaPresent(media);
    return true;
}
#endif

#if FIDO_V1_USB_TOOL
static USBMSC *s_tool_msc;
static volatile bool s_tool_storage_present;
static volatile uint32_t s_tool_storage_last_activity_ms;
static volatile uint32_t s_tool_storage_auto_detach_armed_ms;
static volatile uint16_t s_tool_storage_io_in_flight;
static volatile bool s_tool_storage_auto_detach_armed;
static volatile bool s_tool_storage_host_write_seen;
static volatile bool s_tool_storage_sync_after_last_write;
static portMUX_TYPE s_tool_storage_guard=portMUX_INITIALIZER_UNLOCKED;

class ToolStorageIoGuard {
public:
    ToolStorageIoGuard() {
        portENTER_CRITICAL(&s_tool_storage_guard);
        s_tool_storage_io_in_flight=(uint16_t)(s_tool_storage_io_in_flight+1U);
        portEXIT_CRITICAL(&s_tool_storage_guard);
    }
    ~ToolStorageIoGuard() {
        portENTER_CRITICAL(&s_tool_storage_guard);
        if(s_tool_storage_io_in_flight)
            s_tool_storage_io_in_flight=(uint16_t)(s_tool_storage_io_in_flight-1U);
        portEXIT_CRITICAL(&s_tool_storage_guard);
    }
};

static int32_t tool_storage_read(uint32_t lba, uint32_t offset,
                                 void *buffer, uint32_t bufsize) {
    ToolStorageIoGuard io_guard;
    if (!s_tool_storage_present || !buffer || bufsize == 0U) return -1;
    const uint32_t sector_size = (uint32_t)SD.sectorSize();
    const uint32_t sectors = (uint32_t)SD.numSectors();
    if (sector_size != 512U || sectors == 0U) return -1;
    const uint64_t capacity=(uint64_t)sectors*sector_size;
    uint64_t absolute=(uint64_t)lba*sector_size+offset;
    if (absolute>=capacity || (uint64_t)bufsize>capacity-absolute) return -1;
    uint8_t scratch[512];
    uint8_t *out=(uint8_t *)buffer;
    uint32_t remaining=bufsize;
    while(remaining) {
        uint32_t sector=(uint32_t)(absolute/sector_size);
        uint32_t in_sector=(uint32_t)(absolute%sector_size);
        uint32_t chunk=sector_size-in_sector;if(chunk>remaining)chunk=remaining;
        if(in_sector==0U && chunk==sector_size) {if(!SD.readRAW(out,sector))return -1;}
        else {if(!SD.readRAW(scratch,sector))return -1;memcpy(out,scratch+in_sector,chunk);}
        out+=chunk;remaining-=chunk;absolute+=chunk;
    }
    portENTER_CRITICAL(&s_tool_storage_guard);
    s_tool_storage_last_activity_ms=millis();
    portEXIT_CRITICAL(&s_tool_storage_guard);
    return (int32_t)bufsize;
}

static int32_t tool_storage_write(uint32_t lba, uint32_t offset,
                                  uint8_t *buffer, uint32_t bufsize) {
    ToolStorageIoGuard io_guard;
    if (!s_tool_storage_present || !buffer || bufsize == 0U) return -1;
    const uint32_t sector_size=(uint32_t)SD.sectorSize();
    const uint32_t sectors=(uint32_t)SD.numSectors();
    if(sector_size!=512U || sectors==0U)return -1;
    const uint64_t capacity=(uint64_t)sectors*sector_size;
    uint64_t absolute=(uint64_t)lba*sector_size+offset;
    if(absolute>=capacity || (uint64_t)bufsize>capacity-absolute)return -1;
    uint8_t scratch[512];uint8_t *in=buffer;uint32_t remaining=bufsize;
    while(remaining) {
        uint32_t sector=(uint32_t)(absolute/sector_size);
        uint32_t in_sector=(uint32_t)(absolute%sector_size);
        uint32_t chunk=sector_size-in_sector;if(chunk>remaining)chunk=remaining;
        if(in_sector==0U && chunk==sector_size) {if(!SD.writeRAW(in,sector))return -1;}
        else {if(!SD.readRAW(scratch,sector))return -1;memcpy(scratch+in_sector,in,chunk);if(!SD.writeRAW(scratch,sector))return -1;}
        in+=chunk;remaining-=chunk;absolute+=chunk;
    }
    portENTER_CRITICAL(&s_tool_storage_guard);
    s_tool_storage_last_activity_ms=millis();
    s_tool_storage_host_write_seen=true;
    s_tool_storage_sync_after_last_write=false;
    portEXIT_CRITICAL(&s_tool_storage_guard);
    return (int32_t)bufsize;
}

static void tool_storage_scsi_complete(uint8_t const scsi_cmd[16]) {
    if(!scsi_cmd)return;
    if(scsi_cmd[0]==0x35U || scsi_cmd[0]==0x91U) {
        const uint32_t now=millis();
        portENTER_CRITICAL(&s_tool_storage_guard);
        if(s_tool_storage_present) {
            s_tool_storage_sync_after_last_write=true;
            s_tool_storage_last_activity_ms=now;
        }
        portEXIT_CRITICAL(&s_tool_storage_guard);
    }
}

static bool tool_storage_start_stop(uint8_t, bool start, bool load_eject) {
    if(load_eject && !start) {
        portENTER_CRITICAL(&s_tool_storage_guard);
        s_tool_storage_present=false;
        s_tool_storage_auto_detach_armed=false;
        portEXIT_CRITICAL(&s_tool_storage_guard);
        if(s_tool_msc)s_tool_msc->mediaPresent(false);
    }
    return true;
}

static bool tool_storage_register(void) {
    if(!pf_usb_tool_media_ready()) return true; /* enumerate empty media if no card */
    s_tool_msc=new (std::nothrow) USBMSC();
    if(!s_tool_msc)return false;
    s_tool_msc->vendorID("EvilKey");
    s_tool_msc->productID("DUCKY STORAGE");
    s_tool_msc->productRevision("3.0");
    s_tool_msc->onStartStop(tool_storage_start_stop);
    s_tool_msc->onRead(tool_storage_read);
    s_tool_msc->onWrite(tool_storage_write);
    s_tool_msc->onScsiComplete(tool_storage_scsi_complete);
    s_tool_msc->isWritable(true);
    uint32_t blocks=(uint32_t)SD.numSectors();
    if(blocks==0U)blocks=1U;
    if(!s_tool_msc->begin(blocks,512U))return false;
    s_tool_storage_present=false;
    s_tool_storage_last_activity_ms=millis();
    s_tool_storage_auto_detach_armed_ms=0U;
    s_tool_storage_io_in_flight=0U;
    s_tool_storage_auto_detach_armed=false;
    s_tool_storage_host_write_seen=false;
    s_tool_storage_sync_after_last_write=false;
    s_tool_msc->mediaPresent(false);
    return true;
}

extern "C" bool pf_usb_tool_storage_set_present(bool present) {
    if(!s_tool_msc) return !present;
    if(present && !pf_usb_tool_media_ready()) return false;
    portENTER_CRITICAL(&s_tool_storage_guard);
    s_tool_storage_present=present;
    s_tool_storage_last_activity_ms=millis();
    s_tool_storage_auto_detach_armed=false;
    if(present) {
        s_tool_storage_host_write_seen=false;
        s_tool_storage_sync_after_last_write=false;
    }
    portEXIT_CRITICAL(&s_tool_storage_guard);
    s_tool_msc->mediaPresent(present);
    return true;
}

extern "C" uint32_t pf_usb_tool_storage_activity_age_ms(void) {
    portENTER_CRITICAL(&s_tool_storage_guard);
    const uint32_t last=s_tool_storage_last_activity_ms;
    portEXIT_CRITICAL(&s_tool_storage_guard);
    return (uint32_t)(millis()-last);
}

extern "C" bool pf_usb_tool_storage_present(void) {
    portENTER_CRITICAL(&s_tool_storage_guard);
    const bool present=s_tool_storage_present;
    portEXIT_CRITICAL(&s_tool_storage_guard);
    return present;
}

extern "C" void pf_usb_tool_storage_arm_auto_detach(void) {
    const uint32_t now=millis();
    portENTER_CRITICAL(&s_tool_storage_guard);
    s_tool_storage_auto_detach_armed_ms=now;
    s_tool_storage_auto_detach_armed=s_tool_storage_present;
    portEXIT_CRITICAL(&s_tool_storage_guard);
}

extern "C" void pf_usb_tool_storage_cancel_auto_detach(void) {
    portENTER_CRITICAL(&s_tool_storage_guard);
    s_tool_storage_auto_detach_armed=false;
    portEXIT_CRITICAL(&s_tool_storage_guard);
}

extern "C" bool pf_usb_tool_storage_host_write_seen(void) {
    portENTER_CRITICAL(&s_tool_storage_guard);
    const bool seen=s_tool_storage_host_write_seen;
    portEXIT_CRITICAL(&s_tool_storage_guard);
    return seen;
}

static uint32_t tool_storage_auto_detach_remaining_locked(uint32_t now,
                                                          uint32_t idle_ms) {
    const uint32_t since_arm=(uint32_t)(now-s_tool_storage_auto_detach_armed_ms);
    const uint32_t since_io=(uint32_t)(now-s_tool_storage_last_activity_ms);
    const uint32_t arm_left=since_arm>=idle_ms?0U:idle_ms-since_arm;
    const uint32_t io_left=since_io>=idle_ms?0U:idle_ms-since_io;
    return arm_left>io_left?arm_left:io_left;
}

extern "C" uint32_t pf_usb_tool_storage_auto_detach_remaining_ms(uint32_t idle_ms) {
    const uint32_t now=millis();
    portENTER_CRITICAL(&s_tool_storage_guard);
    const uint32_t remaining=(!s_tool_storage_auto_detach_armed ||
        !s_tool_storage_present)?0U:tool_storage_auto_detach_remaining_locked(
            now,idle_ms);
    portEXIT_CRITICAL(&s_tool_storage_guard);
    return remaining;
}

extern "C" uint8_t pf_usb_tool_storage_auto_detach_state(uint32_t idle_ms) {
    const uint32_t now=millis();
    portENTER_CRITICAL(&s_tool_storage_guard);
    uint8_t state=PF_USB_TOOL_AUTO_DETACH_READY;
    if(!s_tool_storage_auto_detach_armed || !s_tool_storage_present)
        state=PF_USB_TOOL_AUTO_DETACH_UNARMED;
    else if(s_tool_storage_host_write_seen && !s_tool_storage_sync_after_last_write)
        state=PF_USB_TOOL_AUTO_DETACH_WAIT_SYNC;
    else if(s_tool_storage_io_in_flight!=0U ||
            tool_storage_auto_detach_remaining_locked(now,idle_ms)!=0U)
        state=PF_USB_TOOL_AUTO_DETACH_WAIT_IDLE;
    portEXIT_CRITICAL(&s_tool_storage_guard);
    return state;
}

extern "C" bool pf_usb_tool_storage_claim_auto_detach(uint32_t idle_ms) {
    bool claimed=false;
    const uint32_t now=millis();
    portENTER_CRITICAL(&s_tool_storage_guard);
    if(s_tool_storage_auto_detach_armed && s_tool_storage_present &&
       s_tool_storage_io_in_flight==0U &&
       (!s_tool_storage_host_write_seen || s_tool_storage_sync_after_last_write) &&
       tool_storage_auto_detach_remaining_locked(now,idle_ms)==0U) {
        /* This state change and callback I/O admission use the same lock. A
         * callback that starts later observes media absent; one already in
         * progress keeps io_in_flight nonzero and prevents this claim. */
        s_tool_storage_present=false;
        s_tool_storage_auto_detach_armed=false;
        claimed=true;
    }
    portEXIT_CRITICAL(&s_tool_storage_guard);
    if(claimed && s_tool_msc)s_tool_msc->mediaPresent(false);
    return claimed;
}

extern "C" bool pf_usb_tool_apply_attackmode_profile(
    uint8_t mode,bool custom_identity,uint16_t vid,uint16_t pid,
    const char *manufacturer,const char *product,const char *serial)
{
    if(!s_descriptor_tool_role || mode>3U)return false;
    const bool storage=(mode&2U)!=0U;
    if(storage && (!s_tool_msc || !pf_usb_tool_media_ready()))return false;
    if(custom_identity && ((!manufacturer || !product || !serial) ||
       (manufacturer[0]=='\0')!=(product[0]=='\0') ||
       (manufacturer[0]=='\0')!=(serial[0]=='\0')))return false;

    /* Let the host observe a real electrical disconnect before any bytes that
     * describe this device are changed. This also closes the old class pipes. */
    (void)tud_disconnect();
    delay(250U);

    if(custom_identity) {
        descriptor_identity(vid,pid,FIDO_V1_USB_TOOL_BCD_DEVICE,
            manufacturer[0]?manufacturer:FIDO_V1_USB_TOOL_MANUFACTURER,
            product[0]?product:FIDO_V1_USB_TOOL_PRODUCT,
            serial[0]?serial:s_default_serial);
    } else {
        descriptor_identity(FIDO_V1_USB_TOOL_VID,FIDO_V1_USB_TOOL_PID,
            FIDO_V1_USB_TOOL_BCD_DEVICE,FIDO_V1_USB_TOOL_MANUFACTURER,
            FIDO_V1_USB_TOOL_PRODUCT,s_default_serial);
    }
    s_descriptor_attackmode=mode;
    if(!pf_usb_tool_storage_set_present(storage))return false;
    if(mode==0U)return true;
    return tud_connect();
}

extern "C" uint16_t pf_usb_tool_current_vid(void)
{
    return s_device_descriptor.idVendor;
}

extern "C" uint16_t pf_usb_tool_current_pid(void)
{
    return s_device_descriptor.idProduct;
}
#endif

extern "C" bool pf_manager_drive_media_ready(void) {
#if FIDO_V1_MANAGER_DRIVE
    return s_manager_media_ready;
#else
    return false;
#endif
}

extern "C" void pf_manager_drive_apply_read_only(bool read_only) {
#if FIDO_V1_MANAGER_DRIVE
    /* write callback also checks the persisted flag, so protection is effective
     * immediately even if the host caches an earlier MODE SENSE response. */
    if (s_msc) s_msc->isWritable(!read_only);
    ESP_LOGI(TAG, "Manager Drive: runtime USB write protection %s",
             read_only?"enabled":"disabled");
#else
    (void)read_only;
#endif
}

static void usb_event(void *, esp_event_base_t base, int32_t id, void *) {
    if (base != ARDUINO_USB_EVENTS) return;
    switch (id) {
    case ARDUINO_USB_STARTED_EVENT: pf_engine_usb_state(1); break;
    case ARDUINO_USB_STOPPED_EVENT: pf_engine_usb_state(0); break;
    case ARDUINO_USB_SUSPEND_EVENT: pf_engine_usb_state(2); break;
    case ARDUINO_USB_RESUME_EVENT: pf_engine_usb_state(1); break;
    default: break;
    }
}

extern "C" bool pf_arduino_usb_start(void) {
    const bool tool=usb_tool_role();
    const bool mouse=s_air_mouse_role;
    esp_err_t err = tinyusb_enable_interface(USB_INTERFACE_HID,
                                             TUD_HID_INOUT_DESC_LEN,
                                             load_hid_descriptor);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cannot register HID role: %s", esp_err_to_name(err));
        return false;
    }

    bool manager_drive = false;
#if FIDO_V1_MANAGER_DRIVE
    manager_drive = !tool && !mouse && ws_manager_drive_enabled();
    if (manager_drive && !manager_drive_register()) {
        ESP_LOGE(TAG, "Manager Drive requested but MSC registration failed");
        return false;
    }
#endif
#if FIDO_V1_USB_TOOL
    if (tool) {
        if (!pf_usb_tool_begin())
            ESP_LOGW(TAG, "USB Tool started without readable script storage");
        if (!tool_storage_register()) {
            ESP_LOGE(TAG, "USB Tool: cannot register STORAGE interface");
            return false;
        }
    }
#endif

    uint8_t mac[6]={0};
    esp_efuse_mac_get_default(mac);
    snprintf(s_default_serial,sizeof(s_default_serial),"%02X%02X%02X%02X%02X%02X",
             mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    s_descriptor_tool_role=tool;
    s_descriptor_manager_drive=manager_drive;
    s_descriptor_air_mouse_role=mouse;
    s_descriptor_attackmode=tool?1U:(manager_drive?3U:1U);
    if(mouse) {
        descriptor_identity(FIDO_V1_AIR_MOUSE_VID,FIDO_V1_AIR_MOUSE_PID,
            FIDO_V1_AIR_MOUSE_BCD_DEVICE,FIDO_V1_AIR_MOUSE_MANUFACTURER,
            FIDO_V1_AIR_MOUSE_PRODUCT,s_default_serial);
    } else if(tool) {
        descriptor_identity(FIDO_V1_USB_TOOL_VID,FIDO_V1_USB_TOOL_PID,
            FIDO_V1_USB_TOOL_BCD_DEVICE,FIDO_V1_USB_TOOL_MANUFACTURER,
            FIDO_V1_USB_TOOL_PRODUCT,s_default_serial);
    } else if(manager_drive) {
        descriptor_identity(FIDO_V1_MANAGER_DRIVE_VID,FIDO_V1_MANAGER_DRIVE_PID,
            FIDO_V1_MANAGER_DRIVE_BCD_DEVICE,FIDO_V1_MANAGER_DRIVE_MANUFACTURER,
            FIDO_V1_MANAGER_DRIVE_PRODUCT,s_default_serial);
    } else {
        descriptor_identity(PF_USB_VID,PF_USB_PID,PF_USB_BCD_DEVICE,
            PF_USB_MANUFACTURER,PF_USB_PRODUCT,s_default_serial);
    }

    /* Every descriptor family gets its own development identity. In particular,
     * the Yubico-compatible FIDO-only PID is never reused for MSC or USB Tool. */
    const uint16_t vid=mouse?FIDO_V1_AIR_MOUSE_VID:tool?FIDO_V1_USB_TOOL_VID:(manager_drive?FIDO_V1_MANAGER_DRIVE_VID:PF_USB_VID);
    const uint16_t pid=mouse?FIDO_V1_AIR_MOUSE_PID:tool?FIDO_V1_USB_TOOL_PID:(manager_drive?FIDO_V1_MANAGER_DRIVE_PID:PF_USB_PID);
    USB.VID(vid);
    USB.PID(pid);
    USB.usbClass(0);
    USB.usbSubClass(0);
    USB.usbProtocol(0);
    USB.usbVersion(0x0200);
    USB.firmwareVersion(mouse?FIDO_V1_AIR_MOUSE_BCD_DEVICE:tool?FIDO_V1_USB_TOOL_BCD_DEVICE:(manager_drive?FIDO_V1_MANAGER_DRIVE_BCD_DEVICE:PF_USB_BCD_DEVICE));
    USB.productName(mouse?FIDO_V1_AIR_MOUSE_PRODUCT:tool?FIDO_V1_USB_TOOL_PRODUCT:(manager_drive?FIDO_V1_MANAGER_DRIVE_PRODUCT:PF_USB_PRODUCT));
    USB.manufacturerName(mouse?FIDO_V1_AIR_MOUSE_MANUFACTURER:tool?FIDO_V1_USB_TOOL_MANUFACTURER:(manager_drive?FIDO_V1_MANAGER_DRIVE_MANUFACTURER:PF_USB_MANUFACTURER));
    USB.serialNumber(s_default_serial);
    USB.usbPower(500); // Descriptor budget only, not a measured consumption.
    USB.usbAttributes(0x80); // Bus powered; no remote-wakeup claim.
    USB.webUSB(false);
    USB.onEvent(usb_event);
    s_descriptor_ready=USB.begin();
    return s_descriptor_ready;
}

bool PicoFidoArduinoClass::begin() {
    if (started_) return true;
    if (attempted_) return false; // Fail closed: partial initialization needs reboot.
    attempted_ = true;
    s_air_mouse_role=esp_reset_reason()==ESP_RST_SW &&
        s_air_mouse_boot_token==PF_AIR_MOUSE_BOOT_MAGIC &&
        s_air_mouse_boot_token_check==~PF_AIR_MOUSE_BOOT_MAGIC;
    s_air_mouse_boot_token=0;
    s_air_mouse_boot_token_check=0;
    if (esp_secure_boot_enabled() || esp_flash_encryption_enabled()) {
        ESP_LOGE(TAG, "This DEV sketch must not run on a provisioned secure device");
        return false;
    }
    /* R29 requires the board's 8 MB OPI PSRAM. Keep the latency-sensitive
     * LVGL DMA draw buffers in internal SRAM; PSRAM is for variable/cold data. */
    if (!psramFound()) {
        ESP_LOGE(TAG, "PSRAM is not available. Select Tools > PSRAM > OPI PSRAM");
        return false;
    }
    ESP_LOGI(TAG, "PSRAM ready: %u bytes total, %u bytes free",
             (unsigned)ESP.getPsramSize(), (unsigned)ESP.getFreePsram());
    const esp_partition_t *data = esp_partition_find_first(
        (esp_partition_type_t)0x40, (esp_partition_subtype_t)0x01, "part0");
    const esp_partition_t *keys = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, "wsdev");
    const esp_partition_t *app = esp_ota_get_running_partition();
    if (!data || !keys || !app || data->address != 0x200000 ||
        data->size != 0x100000 || keys->address != 0x400000 ||
        keys->size != 0x10000 || app->address != 0x10000 ||
        app->size != 0x1F0000 || data->encrypted || keys->encrypted) {
        ESP_LOGE(TAG, "Wrong partitions.csv. Refusing to start; nothing was erased");
        return false;
    }
    started_ = pf_engine_start() == 0;
    return started_;
}
