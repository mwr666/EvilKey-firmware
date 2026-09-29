/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Pico FIDO for Waveshare ESP32-S3-Touch-AMOLED-1.64 PCB V1.
 * Arduino-ESP32 3.3.12 recommended (3.3.11 supported); USB-OTG (TinyUSB); USB CDC on boot DISABLED.
 * DEVELOPMENT ONLY: master keys are in unencrypted NVS.
 * Run prepare_arduino.py ONCE before opening/verifying this sketch.
 */
#include <Arduino.h>
#include "src/PicoFidoArduino.h"
#if defined(EVILKEY_APPS_LINK_PROBE)
#include "src/apps/ek_vm.h"
static volatile uintptr_t s_apps_probe_symbols[4];
#endif

void setup() {
#if defined(EVILKEY_APPS_LINK_PROBE)
  // Compile-only measurement: retain the VM entry points in the linked BIN.
  s_apps_probe_symbols[0] = (uintptr_t)&ek_vm_open;
  s_apps_probe_symbols[1] = (uintptr_t)&ek_vm_init;
  s_apps_probe_symbols[2] = (uintptr_t)&ek_vm_step;
  s_apps_probe_symbols[3] = (uintptr_t)&ek_vm_close;
#endif
  // UART0, NOT native USB CDC. A serial monitor is not needed to start FIDO.
  Serial0.begin(115200);
  delay(50);
  Serial0.println("Pico FIDO / Waveshare V1 / ARDUINO DEVELOPMENT");
  if (!PicoFidoArduino.begin()) {
    Serial0.println("FIDO startup failed; inspect UART0. Storage was not erased.");
    for (;;) delay(1000);
  }
}

void loop() {
  // The FIDO engine, native TinyUSB and display run in their own FreeRTOS tasks.
  // Never add USB.begin(), USBHID, WiFi, BLE, analogRead or a second I2C driver.
  delay(1000);
}
