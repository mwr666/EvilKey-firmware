// SPDX-License-Identifier: Apache-2.0
// Project-local Arduino-ESP32 MSC adapter with a completion callback for
// successful SCSI commands. The public surface intentionally mirrors USBMSC.
#pragma once

#include "soc/soc_caps.h"
#if SOC_USB_OTG_SUPPORTED

#include <stdbool.h>
#include <stdint.h>
#include "sdkconfig.h"

#if CONFIG_TINYUSB_MSC_ENABLED

typedef bool (*pf_msc_start_stop_cb)(uint8_t power_condition, bool start,
                                     bool load_eject);
typedef int32_t (*pf_msc_read_cb)(uint32_t lba, uint32_t offset, void *buffer,
                                  uint32_t bufsize);
typedef int32_t (*pf_msc_write_cb)(uint32_t lba, uint32_t offset,
                                   uint8_t *buffer, uint32_t bufsize);
typedef int32_t (*pf_msc_scsi_cb)(uint8_t const scsi_cmd[16], void *buffer,
                                  uint16_t bufsize);
typedef void (*pf_msc_scsi_complete_cb)(uint8_t const scsi_cmd[16]);

class USBMSC {
public:
  USBMSC();
  ~USBMSC();
  bool begin(uint32_t block_count, uint16_t block_size);
  void end();
  void vendorID(const char *vid);
  void productID(const char *pid);
  void productRevision(const char *ver);
  void mediaPresent(bool media_present);
  void isWritable(bool is_writable);
  void onStartStop(pf_msc_start_stop_cb cb);
  void onRead(pf_msc_read_cb cb);
  void onWrite(pf_msc_write_cb cb);
  void onScsi(pf_msc_scsi_cb cb);
  void onScsiComplete(pf_msc_scsi_complete_cb cb);

private:
  uint8_t _lun;
};

#endif // CONFIG_TINYUSB_MSC_ENABLED
#endif // SOC_USB_OTG_SUPPORTED
