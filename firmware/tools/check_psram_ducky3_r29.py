#!/usr/bin/env python3
"""R29 source guard: OPI PSRAM + DuckyScript 3 HID compatibility patch."""
from pathlib import Path
import importlib.util

ROOT=Path(__file__).resolve().parents[2]
FW=ROOT/'firmware'

def need(path,*tokens):
    text=path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text:
            raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text

build=need(FW/'build_arduino.py','PSRAM=enabled','build.psram_type=opi','build.memory_type=qio_opi','FlashMode=qio')
if 'PSRAM=disabled' in build:
    raise SystemExit('FAIL: PSRAM is still disabled in Arduino FQBN')
need(FW/'EvilKeyV1/src/PicoFidoArduino.cpp',
     'if (!psramFound())',
     'Tools > PSRAM > OPI PSRAM',
     'ESP.getPsramSize()',
     'ESP.getFreePsram()')
need(FW/'EvilKeyV1/src/UsbTool.cpp',
     'if(psramFound())p=ps_malloc(bytes);',
     'if(!p)p=malloc(bytes);')
need(FW/'templates/port/ws_lvgl.c',
     'MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL')
prepare=need(FW/'prepare_arduino.py','ducky3_hid_patch.py','ducky3.TRANSFORMS')
patch=need(FW/'tools/ducky3_hid_patch.py',
     'RANDOM_SPECIAL','RANDOM_CHAR','!@#$%^&*()','.random_max = 9,')
need(FW/'tools/analyze_hak5_compat.py',
     'PINNED_HAK5_MASTER = "4fa639fd06972cd7efd9c48cc73136443f9cffb1"',
     'candidate-compatible',
     'candidate-compatible')
print('PASS: R29 enables OPI PSRAM while keeping LVGL DMA buffers in internal SRAM')
print('PASS: R29 generator adds RANDOM_SPECIAL and RANDOM_CHAR to the pinned HID interpreter')
print('PASS: R29 ships a non-executing Hak5 payload compatibility auditor')
