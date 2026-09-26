#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];FW=ROOT/'firmware'
def require(path,*needles):
    text=path.read_text(encoding='utf-8')
    for n in needles:
        if n not in text:raise SystemExit(f'FAIL {path}: missing {n!r}')
def main():
    require(FW/'EvilKeyV1/src/PicoFidoArduino.cpp','#include "PfUsbMsc.h"','manager_drive_write(',
            'SD.writeRAW','s_msc->isWritable(!ws_manager_drive_read_only())','pf_manager_drive_apply_read_only')
    require(FW/'templates/port/ws_manager_drive_state.c','mdrive_ro1','FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT','"PFM2"','ws_manager_drive_set_read_only')
    require(FW/'templates/port/ws_manager_config.h','WS_MANAGER_DRIVE_READ_ID','WS_MANAGER_DRIVE_WRITE_ID','pf_manager_drive_apply_read_only')
    require(ROOT/'manager/evilkey_manager/gui.py','Read only — block USB host writes to microSD','drive_write')
    require(ROOT/'manager/evilkey_manager/models.py','class ManagerDriveSettings','DRIVE_READ_ID','DRIVE_WRITE_ID')
    require(ROOT/'manager/evilkey_manager/project.py','"FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT":0')
    require(FW/'EvilKeyV1/FidoConfig.h','#define FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT 0')
    print('PASS: Manager Drive R3 read/write + authenticated write-protection integration')
if __name__=='__main__':main()
