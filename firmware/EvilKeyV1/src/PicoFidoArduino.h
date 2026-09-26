/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#ifdef __cplusplus
class PicoFidoArduinoClass {
public:
    bool begin();
private:
    bool started_ = false;
    bool attempted_ = false;
};
extern PicoFidoArduinoClass PicoFidoArduino;
#endif
