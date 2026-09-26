// SPDX-License-Identifier: Apache-2.0
/*
 * Derived from Arduino-ESP32 3.3.12 cores/esp32/USBMSC.cpp.
 * The local copy avoids modifying the installed Arduino core and adds a
 * per-LUN SCSI-completion hook required to observe a successfully acknowledged
 * SYNCHRONIZE CACHE command. Sector reads and writes remain synchronous.
 */
#include "PfUsbMsc.h"

#if SOC_USB_OTG_SUPPORTED && CONFIG_TINYUSB_MSC_ENABLED

#include "esp32-hal-tinyusb.h"
#include <cstring>

namespace {
constexpr uint8_t PF_MSC_MAX_LUN = 3U;
constexpr uint8_t PF_SCSI_SYNCHRONIZE_CACHE_10 = 0x35U;
constexpr uint8_t PF_SCSI_SYNCHRONIZE_CACHE_16 = 0x91U;

typedef struct {
  bool media_present;
  bool is_writable;
  uint8_t vendor_id[8];
  uint8_t product_id[16];
  uint8_t product_rev[4];
  uint16_t block_size;
  uint32_t block_count;
  pf_msc_start_stop_cb start_stop;
  pf_msc_read_cb read;
  pf_msc_write_cb write;
  pf_msc_scsi_cb scsi;
  pf_msc_scsi_complete_cb scsi_complete;
} pf_msc_lun_t;

static uint8_t s_active_lun;
static pf_msc_lun_t s_luns[PF_MSC_MAX_LUN];

static void copy_padded_string(void *dst, const void *src, size_t max_len) {
  if (!dst || !src || !max_len) return;
  size_t length = strlen(static_cast<const char *>(src));
  if (length > max_len) length = max_len;
  memcpy(dst, src, length);
}

static uint16_t pf_tusb_msc_load_descriptor(uint8_t *dst, uint8_t *itf) {
  const uint8_t string_index = tinyusb_add_string_descriptor("EvilKey MSC");
  const uint8_t ep_num = tinyusb_get_free_duplex_endpoint();
  TU_VERIFY(ep_num != 0U);
  const uint8_t descriptor[TUD_MSC_DESC_LEN] = {
      TUD_MSC_DESCRIPTOR(*itf, string_index, ep_num,
                         static_cast<uint8_t>(0x80U | ep_num),
                         CFG_TUD_ENDPOINT_SIZE)};
  *itf += 1U;
  memcpy(dst, descriptor, sizeof(descriptor));
  return sizeof(descriptor);
}
} // namespace

uint8_t tud_msc_get_maxlun_cb(void) {
  return s_active_lun ? static_cast<uint8_t>(s_active_lun - 1U) : 0U;
}

void tud_msc_inquiry_cb(uint8_t lun, uint8_t vendor_id[8],
                        uint8_t product_id[16], uint8_t product_rev[4]) {
  if (lun >= s_active_lun) return;
  copy_padded_string(vendor_id, s_luns[lun].vendor_id, 8U);
  copy_padded_string(product_id, s_luns[lun].product_id, 16U);
  copy_padded_string(product_rev, s_luns[lun].product_rev, 4U);
}

bool tud_msc_test_unit_ready_cb(uint8_t lun) {
  return lun < s_active_lun && s_luns[lun].media_present;
}

void tud_msc_capacity_cb(uint8_t lun, uint32_t *block_count,
                         uint16_t *block_size) {
  if (!block_count || !block_size || lun >= s_active_lun ||
      !s_luns[lun].media_present) {
    if (block_count) *block_count = 0U;
    if (block_size) *block_size = 0U;
    return;
  }
  *block_count = s_luns[lun].block_count;
  *block_size = s_luns[lun].block_size;
}

bool tud_msc_start_stop_cb(uint8_t lun, uint8_t power_condition, bool start,
                           bool load_eject) {
  if (lun >= s_active_lun) return false;
  return !s_luns[lun].start_stop ||
         s_luns[lun].start_stop(power_condition, start, load_eject);
}

int32_t tud_msc_read10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                          void *buffer, uint32_t bufsize) {
  if (lun >= s_active_lun || !s_luns[lun].media_present ||
      !s_luns[lun].read) return 0;
  return s_luns[lun].read(lba, offset, buffer, bufsize);
}

int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                           uint8_t *buffer, uint32_t bufsize) {
  if (lun >= s_active_lun || !s_luns[lun].media_present ||
      !s_luns[lun].write) return 0;
  return s_luns[lun].write(lba, offset, buffer, bufsize);
}

int32_t tud_msc_scsi_cb(uint8_t lun, uint8_t const scsi_cmd[16],
                        void *buffer, uint16_t bufsize) {
  if (lun >= s_active_lun || !s_luns[lun].media_present || !scsi_cmd)
    return -1;
  if (s_luns[lun].scsi) {
    const int32_t result = s_luns[lun].scsi(scsi_cmd, buffer, bufsize);
    if (result >= 0) return result;
  }
  switch (scsi_cmd[0]) {
  case SCSI_CMD_PREVENT_ALLOW_MEDIUM_REMOVAL:
  case PF_SCSI_SYNCHRONIZE_CACHE_10:
  case PF_SCSI_SYNCHRONIZE_CACHE_16:
    // SD.writeRAW is synchronous. A zero-length successful response means
    // there is no additional device-side cache to drain.
    return 0;
  default:
    tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20U, 0x00U);
    return -1;
  }
}

void tud_msc_scsi_complete_cb(uint8_t lun, uint8_t const scsi_cmd[16]) {
  if (lun < s_active_lun && scsi_cmd && s_luns[lun].scsi_complete)
    s_luns[lun].scsi_complete(scsi_cmd);
}

bool tud_msc_is_writable_cb(uint8_t lun) {
  return lun < s_active_lun && s_luns[lun].is_writable;
}

USBMSC::USBMSC() : _lun(0xFFU) {
  if (s_active_lun >= PF_MSC_MAX_LUN) return;
  _lun = s_active_lun++;
  memset(&s_luns[_lun], 0, sizeof(s_luns[_lun]));
  s_luns[_lun].is_writable = true;
  if (_lun == 0U)
    tinyusb_enable_interface(USB_INTERFACE_MSC, TUD_MSC_DESC_LEN,
                             pf_tusb_msc_load_descriptor);
}

USBMSC::~USBMSC() { end(); }

bool USBMSC::begin(uint32_t block_count, uint16_t block_size) {
  if (_lun >= PF_MSC_MAX_LUN) return false;
  s_luns[_lun].block_size = block_size;
  s_luns[_lun].block_count = block_count;
  return block_size != 0U && block_count != 0U && s_luns[_lun].read &&
         s_luns[_lun].write;
}

void USBMSC::end() {
  if (_lun >= PF_MSC_MAX_LUN) return;
  s_luns[_lun].media_present = false;
  s_luns[_lun].is_writable = false;
  s_luns[_lun].read = nullptr;
  s_luns[_lun].write = nullptr;
  s_luns[_lun].start_stop = nullptr;
  s_luns[_lun].scsi = nullptr;
  s_luns[_lun].scsi_complete = nullptr;
}

void USBMSC::vendorID(const char *vid) {
  if (_lun < PF_MSC_MAX_LUN) copy_padded_string(s_luns[_lun].vendor_id, vid, 8U);
}
void USBMSC::productID(const char *pid) {
  if (_lun < PF_MSC_MAX_LUN) copy_padded_string(s_luns[_lun].product_id, pid, 16U);
}
void USBMSC::productRevision(const char *rev) {
  if (_lun < PF_MSC_MAX_LUN) copy_padded_string(s_luns[_lun].product_rev, rev, 4U);
}
void USBMSC::mediaPresent(bool present) {
  if (_lun < PF_MSC_MAX_LUN) s_luns[_lun].media_present = present;
}
void USBMSC::isWritable(bool writable) {
  if (_lun < PF_MSC_MAX_LUN) s_luns[_lun].is_writable = writable;
}
void USBMSC::onStartStop(pf_msc_start_stop_cb cb) {
  if (_lun < PF_MSC_MAX_LUN) s_luns[_lun].start_stop = cb;
}
void USBMSC::onRead(pf_msc_read_cb cb) {
  if (_lun < PF_MSC_MAX_LUN) s_luns[_lun].read = cb;
}
void USBMSC::onWrite(pf_msc_write_cb cb) {
  if (_lun < PF_MSC_MAX_LUN) s_luns[_lun].write = cb;
}
void USBMSC::onScsi(pf_msc_scsi_cb cb) {
  if (_lun < PF_MSC_MAX_LUN) s_luns[_lun].scsi = cb;
}
void USBMSC::onScsiComplete(pf_msc_scsi_complete_cb cb) {
  if (_lun < PF_MSC_MAX_LUN) s_luns[_lun].scsi_complete = cb;
}

#endif // SOC_USB_OTG_SUPPORTED && CONFIG_TINYUSB_MSC_ENABLED
