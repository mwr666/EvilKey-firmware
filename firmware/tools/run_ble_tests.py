"""Native BLE control/storage-guard tests; no hardware access."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig',required=True)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='evilkey-ble-native-') as directory:
        out=Path(directory)
        cases=[('ft3168_probe','cc',['-std=c11','-I'+str(ROOT/'templates/port'),
            str(ROOT/'tests/test_ft3168_probe.c')]),
            ('controls','cc',['-std=c11','-I'+str(ROOT/'templates/port'),
            str(ROOT/'tests/test_ble_controls.c'),str(ROOT/'templates/port/ws_controls.c')]),
            ('nvs_guard','c++',['-DEVILKEY_NVS_GUARD_LINKED=1','-I'+str(ROOT/'tests/ble_guard_stubs'),
            str(ROOT/'tests/test_nvs_runtime_guard.cpp'),str(ROOT/'EvilKeyV1/src/WsNvsGuard.cpp')]),
            ('ble_memory','cc',['-DESP_PLATFORM=1','-I'+str(ROOT/'tests/ble_memory_stubs'),
            '-I'+str(ROOT/'.ble-libraries/NimBLE-Arduino/src'),
            str(ROOT/'tests/test_ble_memory.c'),
            str(ROOT/'.ble-libraries/NimBLE-Arduino/src/nimble/esp_port/port/src/exp_nimble_mem.c')]),
            ('ble_bootstrap','cc',['-I'+str(ROOT/'tests/ble_bootstrap_stubs'),
            '-I'+str(ROOT/'EvilKeyV1/src'),str(ROOT/'tests/test_ble_bootstrap.c')])]
        for name,compiler,flags in cases:
            binary=out/(name+'.exe')
            # Zig's Windows target defines NDEBUG by default; keep assertions live.
            result=subprocess.run([args.zig,compiler,'-UNDEBUG']+flags+['-o',str(binary)],
                capture_output=True,text=True,encoding='utf-8',errors='replace')
            if result.returncode:
                raise RuntimeError(result.stderr)
            subprocess.run([str(binary)],check=True,timeout=30)
    subprocess.run([sys.executable,'-m','unittest','discover','-s',str(ROOT/'tests'),
        '-p','test_ble_storage_guard.py'],check=True)

if __name__=='__main__':main()
