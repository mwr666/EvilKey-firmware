"""Prepare pinned, locally patched BLE libraries without changing global Arduino libraries."""
from pathlib import Path
import hashlib
import io
import json
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'BLE_LOCK.json'
DEST = ROOT / '.ble-libraries'
specs = [('ESP32-BLE-Gamepad', 'lemmingDev/ESP32-BLE-Gamepad', 'v0.8.0'),
         ('NimBLE-Arduino', 'h2zero/NimBLE-Arduino', '2.5.1')]

def replace_once(text, old, new):
    assert text.count(old)==1, 'Pinned dependency patch anchor changed'
    return text.replace(old,new,1)

def patch_libraries():
    device=DEST/'NimBLE-Arduino/src/NimBLEDevice.cpp'
    text=device.read_text(encoding='utf-8')
    begin=text.index('        esp_err_t err = nvs_flash_init();')
    end=text.index('        if (err != ESP_OK)',begin)
    text=text[:begin]+'        // EvilKey: initialization errors never erase persistent storage.\n        pf_ble_checkpoint(2, 0);\n        esp_err_t err = nvs_flash_init_partition("wsdev");\n        pf_ble_checkpoint(2, err);\n\n'+text[end:]
    text=replace_once(text,'bool NimBLEDevice::init(const std::string& deviceName) {',
        'extern "C" void pf_ble_checkpoint(unsigned phase, int error);\n#include "esp_timer.h"\nbool NimBLEDevice::init(const std::string& deviceName) {')
    for stage,call in [(3,'esp_bt_controller_init(&bt_cfg)'),(4,'esp_bt_controller_enable(ESP_BT_MODE_BLE)'),(5,'esp_nimble_hci_init()')]:
        old='        err = '+call+';'
        after=f'        pf_ble_checkpoint({stage}, err);'
        if stage==5:
            after='        if (err == ESP_OK) pf_ble_checkpoint(5, 0); // Keep the failed HCI substage.'
        text=replace_once(text,old,f'        pf_ble_checkpoint({stage}, 0);\n'+old+'\n'+after)
    text=replace_once(text,'        nimble_port_init();',
        '        pf_ble_checkpoint(6, 0);\n        err = nimble_port_init();\n        pf_ble_checkpoint(6, err);\n        if (err != ESP_OK) return false;')
    text=replace_once(text,'    while (!m_synced) {\n        ble_npl_time_delay(1);\n    }',
        '    pf_ble_checkpoint(7, 0);\n    const int64_t sync_deadline = esp_timer_get_time() + 5000000;\n    while (!m_synced) {\n        if (esp_timer_get_time() >= sync_deadline) { pf_ble_checkpoint(7, ESP_ERR_TIMEOUT); return false; }\n        ble_npl_time_delay(1);\n    }')
    assert 'nvs_flash_erase' not in text
    device.write_text(text,encoding='utf-8')
    hci=DEST/'NimBLE-Arduino/src/nimble/esp_port/esp-hci/src/esp_nimble_hci.c'
    text=hci.read_text(encoding='utf-8')
    text=replace_once(text,'esp_err_t esp_nimble_hci_init(void)',
        'extern void pf_ble_checkpoint(unsigned phase, int error);\nesp_err_t esp_nimble_hci_init(void)')
    text=replace_once(text,'    ret = ble_buf_alloc();',
        '    pf_ble_checkpoint(11, 0);\n    ret = ble_buf_alloc();\n    pf_ble_checkpoint(11, ret);')
    text=replace_once(text,'    if ((ret = esp_vhci_host_register_callback(&vhci_host_cb)) != ESP_OK) {',
        '    pf_ble_checkpoint(12, 0);\n    ret = esp_vhci_host_register_callback(&vhci_host_cb);\n    pf_ble_checkpoint(12, ret);\n    if (ret != ESP_OK) {')
    text=replace_once(text,'    vhci_send_sem = xSemaphoreCreateBinary();',
        '    pf_ble_checkpoint(13, 0);\n    vhci_send_sem = xSemaphoreCreateBinary();')
    text=replace_once(text,'        ret = ESP_ERR_NO_MEM;',
        '        ret = ESP_ERR_NO_MEM;\n        pf_ble_checkpoint(13, ret);')
    hci.write_text(text,encoding='utf-8')
    advertising=DEST/'NimBLE-Arduino/src/NimBLEAdvertising.cpp'
    text=advertising.read_text(encoding='utf-8')
    text=replace_once(text,'#include "NimBLEAdvertising.h"',
        '#include "NimBLEAdvertising.h"\nextern "C" void pf_ble_checkpoint(unsigned phase, int error);')
    text=replace_once(text,'        NIMBLE_LOGE(LOG_TAG, "Host not synced!");',
        '        pf_ble_checkpoint(17, BLE_HS_ENOTSYNCED);\n        NIMBLE_LOGE(LOG_TAG, "Host not synced!");')
    text=replace_once(text,'    if (rc != 0 && rc != BLE_HS_EALREADY) {\n        NIMBLE_LOGE(LOG_TAG, "Error enabling advertising;',
        '    if (rc != 0 && rc != BLE_HS_EALREADY) {\n        pf_ble_checkpoint(17, rc);\n        NIMBLE_LOGE(LOG_TAG, "Error enabling advertising;')
    for stage,call in [(16,'ble_gap_adv_set_data(&data.getPayload()[0], data.getPayload().size())'),
                       (18,'ble_gap_adv_rsp_set_data(&data.getPayload()[0], data.getPayload().size())')]:
        anchor='    int rc = '+call+';'
        text=replace_once(text,anchor,anchor+f'\n    if (rc != 0) pf_ble_checkpoint({stage}, rc);')
    advertising.write_text(text,encoding='utf-8')
    server=DEST/'NimBLE-Arduino/src/NimBLEServer.cpp'
    text=server.read_text(encoding='utf-8')
    text=replace_once(text,'bool NimBLEServer::start() {',
        'extern "C" void pf_ble_checkpoint(unsigned phase, int error);\nbool NimBLEServer::start() {')
    text=replace_once(text,'    int rc = ble_gatts_start();',
        '    int rc = ble_gatts_start();\n    if (rc != 0) pf_ble_checkpoint(15, rc);')
    server.write_text(text,encoding='utf-8')
    service=DEST/'NimBLE-Arduino/src/NimBLEService.cpp'
    text=service.read_text(encoding='utf-8')
    text=replace_once(text,'bool NimBLEService::start_internal() {',
        'extern "C" void pf_ble_checkpoint(unsigned phase, int error);\nbool NimBLEService::start_internal() {')
    for call in ['ble_gatts_count_cfg(m_pSvcDef)','ble_gatts_add_svcs(m_pSvcDef)']:
        anchor=('    int rc = ' if 'count' in call else '    rc = ')+call+';'
        text=replace_once(text,anchor,anchor+'\n    if (rc != 0) pf_ble_checkpoint(19, rc);')
    service.write_text(text,encoding='utf-8')
    store=DEST/'NimBLE-Arduino/src/nimble/nimble/host/store/config/src/ble_store_nvs.c'
    text=store.read_text(encoding='utf-8')
    text=replace_once(text,'#include "nvs.h"','#include "nvs.h"\nextern const char *pf_ble_store_namespace(void);')
    assert text.count('nvs_open(NIMBLE_NVS_NAMESPACE,')>=4
    text=text.replace('nvs_open(NIMBLE_NVS_NAMESPACE,','nvs_open_from_partition("wsdev", pf_ble_store_namespace(),')
    assert 'nvs_open(' not in text
    store.write_text(text,encoding='utf-8')
    config=DEST/'NimBLE-Arduino/src/nimconfig.h'
    text=config.read_text(encoding='utf-8')
    text=replace_once(text,'#include "nimconfig_rename.h"',
        '#include "nimconfig_rename.h"\n// EvilKey: peripheral only, one host. Override SDK defaults after sdkconfig.\n'
        '#undef CONFIG_BT_NIMBLE_ROLE_CENTRAL\n#define CONFIG_BT_NIMBLE_ROLE_CENTRAL 0\n'
        '#undef CONFIG_BT_NIMBLE_ROLE_OBSERVER\n#define CONFIG_BT_NIMBLE_ROLE_OBSERVER 0\n'
        '#undef CONFIG_BT_NIMBLE_MAX_CONNECTIONS\n#define CONFIG_BT_NIMBLE_MAX_CONNECTIONS 1\n'
        '// Host packet/GATT pools use PSRAM; controller, task stacks and LCD DMA stay internal.\n'
        '#undef CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_INTERNAL\n'
        '#undef CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_IRAM_8BIT\n'
        '#undef CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_DEFAULT\n'
        '#undef CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL\n'
        '#define CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL 1\n')
    config.write_text(text,encoding='utf-8')
    gamepad=DEST/'ESP32-BLE-Gamepad/BleGamepad.cpp'
    text=gamepad.read_text(encoding='utf-8')
    text=replace_once(text,'NimBLEDevice::init(BleGamepadInstance->deviceName);',
        'if (!NimBLEDevice::init(BleGamepadInstance->deviceName)) { vTaskDelete(NULL); return; }')
    # Eight-button Generic reports can be shorter than the 16-byte backing array.
    text=replace_once(text,'memcpy(&m, &_buttons, sizeof(_buttons));','memcpy(&m, &_buttons, numOfButtonBytes);')
    text=replace_once(text,'setSecurityAuth(true, false, false)','setSecurityAuth(true, false, true)')
    text=replace_once(text,'  BleGamepadInstance->onStarted(pServer);','')
    text=replace_once(text,'  vTaskDelay(portMAX_DELAY); // delay(portMAX_DELAY);',
        '  BleGamepadInstance->onStarted(pServer); // Advertising data is complete before readiness.\n'
        '  vTaskSuspend(NULL); // EvilKey owner retires this 20 KiB bootstrap before advertising.\n')
    gamepad.write_text(text,encoding='utf-8')
    status=DEST/'ESP32-BLE-Gamepad/BleConnectionStatus.cpp'
    text=status.read_text(encoding='utf-8').replace('connInfo.isEncrypted() || connInfo.isBonded()','connInfo.isEncrypted()')
    text=replace_once(text,'    this->authenticatedConnHandles.insert(connInfo.getConnHandle());\n    this->connected = true;\n}',
        '    if (connInfo.isEncrypted()) {\n        this->authenticatedConnHandles.insert(connInfo.getConnHandle());\n        this->connected = true;\n    }\n}')
    status.write_text(text,encoding='utf-8')
    status_header=DEST/'ESP32-BLE-Gamepad/BleConnectionStatus.h'
    text=status_header.read_text(encoding='utf-8')
    text=replace_once(text,'#include <set>','#include <set>\n#include <atomic>')
    text=replace_once(text,'bool connected = false;','std::atomic<bool> connected{false};')
    status_header.write_text(text,encoding='utf-8')
    (DEST/'PATCHES.json').write_text(json.dumps({
        'revision':4,'modified_files':{str(p.relative_to(DEST)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [device,hci,advertising,server,service,store,config,gamepad,status,status_header]},
        'changes':['NVS init error returns without erase','BLE bonds only in profile-specific wsdev namespaces',
                   'abort failed NimBLE initialization','bound Generic button report copy','encrypted-link readiness',
                   'peripheral only; one connection','server readiness after advertising setup',
                   'NimBLE host pools in PSRAM','HCI buffer/callback/semaphore diagnostics',
                   'retire suspended Gamepad bootstrap before advertising','preserve GATT/advertising return codes']},indent=2)+'\n')

def prepare():
    existing = json.loads(LOCK.read_text()) if LOCK.exists() else None
    receipts = []
    for name, repo, tag in specs:
        url = 'https://codeload.github.com/' + repo + '/zip/refs/tags/' + tag
        cache = ROOT / '.cache' / (name + '-' + tag + '.zip')
        cache.parent.mkdir(parents=True, exist_ok=True)
        if cache.exists():
            data = cache.read_bytes()
        else:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read()
            cache.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        if existing:
            prior = next(x for x in existing['dependencies'] if x['name'] == name)
            if prior['url'] != url or prior['sha256'] != digest:
                raise RuntimeError('Dependency archive mismatch: '+name)
        target = DEST / name
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                relative = Path(*Path(member.filename).parts[1:])
                if '..' in relative.parts or relative.is_absolute():
                    raise RuntimeError('Unsafe dependency archive member')
                if member.is_dir() or not relative.parts:
                    continue
                # Build source + license/properties only; examples are not dependencies.
                if relative.parts[0] in {'examples', '.github', 'docs'}:
                    continue
                output = target / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(archive.read(member))
        receipts.append({'name': name, 'tag': tag, 'url': url, 'sha256': digest})
        print(name, tag, digest)
    if not existing:
        LOCK.write_text(json.dumps({'schema': 'evilkey-ble-lock-v1', 'dependencies': receipts}, indent=2) + '\n')
    patch_libraries()
    license_dir=ROOT/'EvilKeyV1/data/upstream-licenses'
    license_dir.mkdir(exist_ok=True)
    for name,_,_ in specs:
        for file in (DEST/name).iterdir():
            if file.is_file() and file.name.lower().startswith(('license','notice','copying')):
                (license_dir/(name+'_'+file.name)).write_bytes(file.read_bytes())
    return DEST

if __name__ == '__main__':
    prepare()
