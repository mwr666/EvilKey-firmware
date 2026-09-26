#!/usr/bin/env python3
from pathlib import Path
import re
import sys
ROOT = Path(__file__).resolve().parents[1]
errors=[]

def need(path, *parts):
    text=(ROOT/path).read_text(encoding='utf-8')
    for part in parts:
        if part not in text:
            errors.append(f'{path}: missing {part!r}')
    return text

cfg=need(Path('EvilKeyV1/src/pf_build_config.h'),
         'ESP_ARDUINO_VERSION_VAL(3, 3, 11)',
         'ESP_ARDUINO_VERSION_VAL(3, 3, 12)',
         '3.3.11 or 3.3.12 only')
if cfg.count('ESP_ARDUINO_VERSION_VAL(3, 3, 12)') != 1:
    errors.append('pf_build_config.h: unexpected 3.3.12 guard multiplicity')
stack=need(Path('tools/check_usb_stack.py'),
           '(3, 3, 11): "5b6bfb437b851b78578574ca44d157e115bf7930"',
           '(3, 3, 12): "d8fcd0b428848010d3b3773b5b0e02515693f0e0"',
           'PREFERRED = (3, 3, 12)',
           'xTaskCreate(usb_device_task, "usbd", 4096',
           'NEW_CALL = CALL.replace(b"4096", b"16384")',
           'PICO_FIDO_DUCKY_OS_HOOK_S2',
           'pf_usb_configuration_descriptor_requested')
port=need(Path('ARDUINO_PORT.json'), '3.3.12 recommended', 'R14_ARDUINO_3_3_12')
prep=need(Path('prepare_arduino.py'), '3.3.12-recommended;3.3.11-supported')
if errors:
    print('\n'.join('FAIL: '+e for e in errors), file=sys.stderr)
    raise SystemExit(1)
print('PASS: Arduino-ESP32 3.3.12 compatibility guard + reversible S2 tooling present; 3.3.11 retained')
