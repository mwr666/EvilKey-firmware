#!/usr/bin/env python3
"""R27 USB Tool guard: compile-safe LVGL + Hak5 language/payload compatibility."""
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
        'FIDO_V1_USB_TOOL                 1','FIDO_V1_USB_TOOL_DEFAULT         0',
        'FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT "us"','FIDO_V1_USB_TOOL_PID             0xFCFB')
    if re.search(r'^\s*#define\s+FIDO_V1_USB_TOOL_DEFAULT\s+1\b',cfg,re.M):
        raise SystemExit('FAIL: USB Tool must default OFF')

    lvconf=need(FW/'templates'/'lvgl_conf.h','#define LV_FONT_MONTSERRAT_18 1')
    enabled={int(n) for n,v in re.findall(r'^#define\s+LV_FONT_MONTSERRAT_(\d+)\s+([01])\s*$',lvconf,re.M) if v=='1'}
    lvgl=need(PORT/'ws_lvgl.c','"USB TOOL"','"PREV"','"RUN"','"NEXT"','usb_tool_language_name')
    refs={int(n) for n in re.findall(r'lv_font_montserrat_(\d+)',lvgl)}
    bad=sorted(refs-enabled)
    if bad: raise SystemExit(f'FAIL: ws_lvgl.c references disabled Montserrat fonts: {bad}')
    if 'lv_font_montserrat_16' in lvgl:
        raise SystemExit('FAIL: R26 compile regression font 16 reintroduced')

    state=need(PORT/'ws_usb_tool_state.c','"utlang_v2"','FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT',
               'ws_usb_tool_language_code','ws_usb_tool_set_language_code','valid_language_code')
    need(PORT/'ws_usb_tool_state.h','WS_USB_LANGUAGE_CODE_MAX 20','ws_usb_tool_set_language_code')

    parser=need(SRC/'Hak5Language.cpp','pf_hak5_parse_language_json','parse_triplet','mapped<80U')
    need(SRC/'Hak5Language.h','pf_hak5_key_t','U+0020..U+007E')

    tool=need(SRC/'UsbTool.cpp',
        'MAX_SCRIPTS=320','MAX_PATH=192','scan_script_dir("/duckyscripts",0U)',
        'scan_script_dir("/payloads",0U)','scan_language_dir("/languages")',
        'scan_language_dir("/duckyscripts/hak5/languages")','pf_hak5_parse_language_json',
        'pf_usb_tool_select_language_delta','ws_usb_tool_set_language_code',
        'if(!strcasecmp(base,"payload.txt"))return true;',
        'return strstr(path,"/payloads/")==nullptr;',
        'ducky_run(script,len,&io,&cfg)','extern "C" bool pf_usb_tool_run_selected(void)')
    begin=tool[tool.index('extern "C" bool pf_usb_tool_begin(void)'):tool.index('extern "C" void pf_usb_tool_end(void)')]
    if 'pf_usb_tool_run_selected' in begin or 'xTaskCreate' in begin or 'ducky_run' in begin:
        raise SystemExit('FAIL: payload autorun path exists in pf_usb_tool_begin()')
    if '#include <USBHID' in tool or 'USBHIDKeyboard' in tool:
        raise SystemExit('FAIL: second Arduino HID owner reintroduced')

    usb=need(SRC/'PicoFidoArduino.cpp','static const uint8_t usb_tool_report_descriptor[]',
        'tinyusb_enable_interface(USB_INTERFACE_HID','tool?FIDO_V1_USB_TOOL_PID')
    if usb.count('tinyusb_enable_interface(USB_INTERFACE_HID')!=1:
        raise SystemExit('FAIL: expected exactly one TinyUSB HID owner')

    api=need(SRC/'pf_engine_api.h','pf_usb_tool_language_count','pf_usb_tool_language_name',
             'pf_usb_tool_select_language_delta')
    ui=need(PORT/'ws_ui.h','char usb_tool_script_name[80]','char usb_tool_language_name[28]')
    board=need(PORT/'ws_board.c','PICO_FIDO_R27_HAK5_COMPAT','pf_usb_tool_select_language_delta(dir)',
               'pf_usb_tool_language_name(v.usb_tool_language_name')

    lock=json.loads((FW/'UPSTREAM_LOCK.json').read_text(encoding='utf-8'))
    if lock.get('s3_ducky_commit')!='e1e172c26961b865da699969c109a99c78311434':
        raise SystemExit('FAIL: s3-ducky pin drifted')

    project=need(ROOT/'manager'/'evilkey_manager'/'project.py',
        '"FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT":"us"','[A-Za-z0-9_-]{1,19}')
    need(ROOT/'manager'/'evilkey_manager'/'gui.py',"'FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT'", '"USB Tool Support"')
    print('PASS: R27 removes the disabled LVGL Montserrat-16 reference and checks every font reference')
    print('PASS: Hak5 flat language JSON adapter and persistent language-code selection are wired')
    print('PASS: recursive /payloads payload.txt discovery fits the current 268-file Hak5 library')
    print('PASS: explicit local RUN/no-autorun and single TinyUSB HID owner remain enforced')

if __name__=='__main__': main()
