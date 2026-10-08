"""Fail closed if prepared BLE sources can erase NVS or use the default store."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]


def source_digest(root=ROOT):
    result=hashlib.sha256()
    for directory in (root/'EvilKeyV1',root/'.ble-libraries'):
        for file in sorted(directory.rglob('*')):
            if file.is_file() and file.suffix.lower() in ('.c','.cpp','.h','.hpp','.ino','.csv'):
                result.update(file.relative_to(root).as_posix().encode()+b'\0')
                result.update(hashlib.sha256(file.read_bytes()).digest())
    return result.hexdigest()


def code_only(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)


def calls_only(text):
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', code_only(text))


def verify(root=ROOT):
    libraries = root / '.ble-libraries'
    receipt = json.loads((libraries / 'PATCHES.json').read_text())
    for name, digest in receipt['modified_files'].items():
        if hashlib.sha256((libraries / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('Prepared BLE patch hash mismatch: ' + name)
    sources = list(libraries.rglob('*.cpp')) + list(libraries.rglob('*.c'))
    sources += [root/'EvilKeyV1/src/WsBle.cpp',
                root/'templates/engine_entry.c.inc', root/'templates/port/ws_controls.c']
    for path in sources:
        code = code_only(path.read_text(encoding='utf-8', errors='strict'))
        if re.search(r'\b(?:nvs_flash_erase\w*|nvs_erase_all|esp_flash_erase_chip|spi_flash_erase_chip)\s*\(', calls_only(code)):
            raise RuntimeError('Forbidden erase API: ' + str(path.relative_to(root)))
    device = code_only((libraries/'NimBLE-Arduino/src/NimBLEDevice.cpp').read_text())
    if 'nvs_flash_init_partition("wsdev")' not in device or re.search(r'\bnvs_flash_init\s*\(', calls_only(device)):
        raise RuntimeError('BLE must initialize wsdev without erase recovery')
    store = code_only((libraries/'NimBLE-Arduino/src/nimble/nimble/host/store/config/src/ble_store_nvs.c').read_text())
    opens = re.findall(r'\bnvs_open\w*\s*\(([^;]+);', store)
    if not opens or any(not item.startswith('"wsdev", pf_ble_store_namespace(),') for item in opens):
        raise RuntimeError('Every BLE storage handle must use its isolated namespace')
    backend = code_only((root/'EvilKeyV1/src/WsBle.cpp').read_text())
    for namespace in ('ek_ble_mouse', 'ek_ble_xbox', 'ek_ble_generic'):
        if namespace not in backend:
            raise RuntimeError('Missing dedicated BLE namespace')
    if 'pico_fido' in backend:
        raise RuntimeError('BLE backend must not open the FIDO namespace')
    start = backend[backend.index('bool pf_ble_start(void)'):]
    guard = 'if(!ws_controls_is_ble(pf_control_mode()))return false;'
    if guard not in start or start.index(guard)>start.index('xQueueCreate('):
        raise RuntimeError('BLE must reject non-BLE roles before allocation/start')
    startup = code_only((root/'EvilKeyV1/src/PicoFidoArduino.cpp').read_text())
    hook = startup[startup.index('bool bleInUse(void)'):startup.index('PfControlMode pf_control_mode')]
    if 'ws_controls_is_ble(ws_controls_boot_mode(' not in hook:
        raise RuntimeError('Arduino must retain BLE controller RAM only for validated BLE roles')
    if 'pf_control_restart(PF_CONTROL_NORMAL)' not in backend[backend.index('static void startup_failed()'):backend.index('static void worker(')]:
        raise RuntimeError('Partial BLE initialization failures must return to radio-off normal boot')
    print('PASS: BLE no-erase source gate; scoped wsdev bond store and verified patches.')
    return True


if __name__ == '__main__':
    verify()
