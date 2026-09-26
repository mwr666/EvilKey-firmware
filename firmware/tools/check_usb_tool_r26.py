#!/usr/bin/env python3
"""R26 USB Tool source guard: one TinyUSB owner, explicit RUN, layouts and fail-closed role state."""
from pathlib import Path
import json
import re

ROOT=Path(__file__).resolve().parents[2]
FW=ROOT/'firmware'; PORT=FW/'templates'/'port'; SRC=FW/'EvilKeyV1'/'src'


def need(path:Path,*tokens:str)->str:
    text=path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text:
            raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text


def main()->None:
    cfg=need(FW/'EvilKeyV1'/'FidoConfig.h',
        'FIDO_V1_USB_TOOL                 1',
        'FIDO_V1_USB_TOOL_DEFAULT         0',
        'FIDO_V1_USB_TOOL_PID             0xFCFB',
        'FIDO_V1_USB_TOOL_MAX_PAYLOAD     262144U')
    if re.search(r'^\s*#define\s+FIDO_V1_USB_TOOL_DEFAULT\s+1\b',cfg,re.M):
        raise SystemExit('FAIL: USB Tool must never autorole-enable by default')

    state=need(PORT/'ws_usb_tool_state.c',
        '"utool_v1"','"utlay_v1"','if(!storage_ok)',
        'enabled=FIDO_V1_USB_TOOL_DEFAULT?1U:0U;',
        'layout=(uint8_t)FIDO_V1_USB_TOOL_LAYOUT_DEFAULT;')
    need(PORT/'ws_usb_tool_state.h',
        'WS_USB_LAYOUT_US','WS_USB_LAYOUT_PL_PROGRAMMER','WS_USB_LAYOUT_DE',
        'WS_USB_LAYOUT_FR','WS_USB_LAYOUT_ES','WS_USB_LAYOUT_COUNT = 5')

    tool=need(SRC/'UsbTool.cpp',
        'ducky_run(script,len,&io,&cfg)',
        'static bool io_keyboard(', 'static bool io_mouse(', 'static bool io_consumer(',
        'if(physical_key==0x32U)physical_key=0x64U;',
        'return false;\n}\n\nstatic void io_delay',
        'SD.exists("/duckyscripts")','strcasecmp(dot,".duck")','strcasecmp(dot,".ds")',
        'while(pos>0U && strcasecmp(s_scripts[pos-1U],base)>0)',
        'extern "C" bool pf_usb_tool_run_selected(void)',
        'xTaskCreatePinnedToCore(run_task,"ducky"',
        'extern "C" void pf_usb_tool_stop(void)')
    begin=tool[tool.index('extern "C" bool pf_usb_tool_begin(void)'):tool.index('extern "C" void pf_usb_tool_end(void)')]
    if 'pf_usb_tool_run_selected' in begin or 'xTaskCreate' in begin or 'ducky_run' in begin:
        raise SystemExit('FAIL: payload autorun path exists in pf_usb_tool_begin()')
    if '#include <USBHID' in tool or 'USBHIDKeyboard' in tool:
        raise SystemExit('FAIL: USB Tool must not create a second Arduino HID owner')

    usb=need(SRC/'PicoFidoArduino.cpp',
        'static const uint8_t fido_report_descriptor[]',
        'static const uint8_t usb_tool_report_descriptor[]',
        'TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(PF_USB_TOOL_RID_KEYBOARD))',
        'TUD_HID_REPORT_DESC_MOUSE(HID_REPORT_ID(PF_USB_TOOL_RID_MOUSE))',
        'TUD_HID_REPORT_DESC_CONSUMER(HID_REPORT_ID(PF_USB_TOOL_RID_CONSUMER))',
        'if (usb_tool_role()) return usb_tool_report_descriptor;',
        'tinyusb_enable_interface(USB_INTERFACE_HID',
        'tool?FIDO_V1_USB_TOOL_PID',
        'if (tool && !pf_usb_tool_begin())')
    if usb.count('tinyusb_enable_interface(USB_INTERFACE_HID') != 1:
        raise SystemExit('FAIL: R26 must register exactly one Arduino/TinyUSB HID interface')
    if '#include <USBHID.h>' in usb or 'USBHIDKeyboard' in usb:
        raise SystemExit('FAIL: Arduino USBHID owner reintroduced')

    ui=need(PORT/'ws_ui.h','WS_SETTINGS_PAGE_USB_TOOL = 8','WS_SETTINGS_PAGE_COUNT = 9',
            'WS_USB_TOOL_ACTION_PREV','WS_USB_TOOL_ACTION_RUN_STOP','WS_USB_TOOL_ACTION_NEXT')
    need(PORT/'ws_lvgl.c','"USB TOOL"','"USB Tool mode"','"Keyboard layout"','"PREV"','"RUN"','"STOP"','"NEXT"')
    board=need(PORT/'ws_board.c','PICO_FIDO_R26_USB_TOOL',
        'WS_SETTINGS_ACTION_USB_TOOL_TOGGLE','ws_usb_tool_set_enabled(',
        'ws_manager_drive_set_enabled(false)',
        'WS_USB_TOOL_ACTION_RUN_STOP','pf_usb_tool_run_selected()','pf_usb_tool_stop()')

    prepare=need(FW/'prepare_arduino.py',
        '"ducky": (LOCK["s3_ducky_url"], LOCK["s3_ducky_commit"])',
        'roots["ducky"] / "components/ducky" / p for p in ("ducky.c", "ducky_keymap.c")',
        'USB_TOOL_R26','R26_USB_TOOL')
    # The generated CTAP set-report wrapper must consume tool output reports before
    # applying the FIDO-only 64-byte CTAP guard.
    need(FW/'prepare_arduino.py',
        'if (hid_set_report_cb && hid_set_report_cb(itf, report_id, report_type, buffer, bufsize) != 0) return;\\n    if (itf != 0 || report_id != 0 || !buffer || bufsize != 64) return;')

    lock=json.loads((FW/'UPSTREAM_LOCK.json').read_text(encoding='utf-8'))
    if lock.get('s3_ducky_commit')!='e1e172c26961b865da699969c109a99c78311434':
        raise SystemExit('FAIL: s3-ducky pin drifted')
    if lock.get('arduino_keyboard_layout_commit')!='3f7bad0a41839689684e3b46ce9deb0232f8ec2d':
        raise SystemExit('FAIL: keyboard-layout provenance drifted')
    if not (FW/'EvilKeyV1'/'data'/'upstream-licenses'/'arduino_keyboard_LICENSE').is_file():
        raise SystemExit('FAIL: Arduino Keyboard LGPL license copy missing')

    project=need(ROOT/'manager'/'evilkey_manager'/'project.py',
        '"FIDO_V1_USB_TOOL":1', '"FIDO_V1_USB_TOOL_DEFAULT":0',
        '"FIDO_V1_USB_TOOL_LAYOUT_DEFAULT":0', '"FIDO_V1_USB_TOOL_PID":0xFCFB',
        'The USB Tool and Manager Drive cannot be the default start profile at the same time.')
    need(ROOT/'manager'/'evilkey_manager'/'gui.py',
        "'USB Tool', 'USB keyboard, scripts, and data capture on microSD.',usb_tool", "k=='FIDO_V1_USB_TOOL_LAYOUT_DEFAULT'")
    need(FW/'examples'/'usb_tool'/'hello_world.duck','STRING EvilKey USB Tool')

    docs=need(ROOT/'docs'/'USB_TOOL.md',
        'Payloads never run during boot, USB enumeration, or card mounting.',
        '`US`, `PL Programmer`, `DE`, `FR`, or `ES`',
        'does not provide general UTF-8 typing',
        '`FEFF:FCFB`')

    print('PASS: R26 keeps one TinyUSB HID owner and selects CTAP vs USB Tool only at boot')
    print('PASS: USB Tool defaults OFF, corrupt NVS fails closed, and payloads require local RUN')
    print('PASS: s3-ducky is commit-pinned; SD payload browsing and five selectable layouts are wired')
    print('PASS: national layout tables mirror Arduino ISO-key 0x32 -> HID 0x64 translation')

if __name__=='__main__':
    main()
