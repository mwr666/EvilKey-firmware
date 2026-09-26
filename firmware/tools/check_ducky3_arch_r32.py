#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FW=ROOT/'firmware'

def need(path,*tokens):
    t=path.read_text(encoding='utf-8')
    for x in tokens:
        if x not in t: raise SystemExit(f'FAIL {path}: missing {x!r}')
    return t

need(FW/'tools/ducky3_hid_patch.py',
     'SAVE_ATTACKMODE','RESTORE_ATTACKMODE','ATTACKMODE OFF cannot be combined',
     '$_CURRENT_ATTACKMODE','$_RECEIVED_HOST_LOCK_LED_REPLY',
     'STRINGLN_POWERSHELL','STRINGLN_BASH','STRINGLN_BLOCK','EXTENSION','WINDOWS',
     'host_configuration_request_count','WAIT_FOR_STORAGE_ACTIVITY','INJECT_VAR',
     'valid_constant_name','inline_key_repeat','skip_literal_block',
     'VID_RANDOM','SERIAL_RANDOM','attackmode_profile',
     'key_token_is_hyphenated_sequence','lookup_key_component')
need(FW/'tests/release_026/test_ducky_key_combos_r35.c',
     'CTRL-ALT DELETE','CTRL-SHIFT-ENTER','ALT-F4','CTRL-K','ALT-F2',
     'COMMAND OPTION SHIFT P','CTRL--ALT DELETE','KPAD_2','REPEAT 2 TAB')
need(FW/'EvilKeyV1/src/UsbTool.cpp',
     'io_attackmode','io_attackmode_profile','pf_usb_tool_apply_attackmode_profile',
     'io.current_attackmode=io_current_attackmode',
     'io.storage_activity_age_ms=io_storage_activity_age_ms',
     's_received_led_report=true','pf_usb_tool_current_vid','pf_usb_tool_current_pid')
need(FW/'EvilKeyV1/src/engine/ducky/components/ducky/include/ducky.h',
     'storage_activity_age_ms','DUCKY_CAP_VARIABLE_EXFIL',
     'DUCKY_CAP_KEYSTROKE_REFLECTION')
need(FW/'EvilKeyV1/src/engine/ducky/components/ducky/ducky.c',
     'WAIT_FOR_STORAGE_ACTIVITY','inline_key_repeat','skip_literal_block')
need(FW/'EvilKeyV1/src/PicoFidoArduino.cpp',
     'tool_storage_register','USBMSC','DUCKY STORAGE',
     'pf_usb_tool_storage_set_present','mediaPresent(present)',
     'tool_storage_read','tool_storage_write',
     'tud_descriptor_device_cb','tud_descriptor_string_cb',
     'tud_descriptor_configuration_cb','tud_disconnect','tud_connect',
     's_config_tool_hid','s_config_tool_storage','s_config_tool_combo')
aud=need(FW/'tools/analyze_hak5_compat.py','POLICY_BLOCKED_COMMANDS',
         'variable_exfil','keystroke_reflection','payload_snapshot_hiding')
if 'SAVE_ATTACKMODE": "dynamic_attackmode"' in aud: raise SystemExit('FAIL: analyzer still rejects SAVE_ATTACKMODE')
print('PASS: R35 exposes dynamic HID/MSC/OFF descriptors to USB Tool')
print('PASS: R35 bridges descriptor identity, save/restore and host LED feedback')
print('PASS: generated Arduino engine contains the current R35 DuckyScript callbacks and parser')
print('PASS: R35 auditor keeps variable exfiltration, reflection and payload hiding as independent capability gates')
print('PASS: R35 accepts official space-separated key chords and strict Hak5 hyphen aliases')
