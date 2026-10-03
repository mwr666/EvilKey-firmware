#!/usr/bin/env python3
"""Optional Arduino CLI build helper. Does not install tools or upload firmware."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--apps-vm-link-probe',action='store_true',
                    help='Link all Apps VM entry points to measure BIN size; compile only')
args=parser.parse_args()
if not (ROOT/'EvilKeyV1/src/engine_ready.h').is_file():
    raise SystemExit('Run python prepare_arduino.py first.')
from prepare_arduino import validate_output
from tools.prepare_ble import prepare as prepare_ble
from tools.check_ble_storage import verify as verify_ble_storage, source_digest
try:
    validate_output(ROOT/'EvilKeyV1/src/engine')
except (OSError, RuntimeError) as exc:
    raise SystemExit(f'Generated source check failed: {exc}')
cli=shutil.which('arduino-cli')
if not cli:
    raise SystemExit('arduino-cli is not in PATH. Use Verify in Arduino IDE, or install Arduino CLI.')
# The Waveshare board menu calls its fixed OPI configuration "enabled".
# Arduino-ESP32 3.3.12 resolves it to build.psram_type=opi and
# build.memory_type=qio_opi; the generic ESP32-S3 value "opi" is invalid here.
subprocess.run([sys.executable,str(ROOT/'tools/check_usb_stack.py'),'--require'],check=True)
ble_libraries=prepare_ble()
verify_ble_storage()
inputs_sha256=source_digest()
fqbn=('esp32:esp32:waveshare_esp32_s3_touch_amoled_164:USBMode=default,'
      'CDCOnBoot=default,MSCOnBoot=default,DFUOnBoot=default,PSRAM=enabled,'
      'FlashMode=qio,PartitionScheme=app3M_fat9M_16MB,EraseFlash=none')
out=ROOT/('build-arduino-apps-probe' if args.apps_vm_link_probe else 'build-arduino')
try:
    command=[cli,'compile','--fqbn',fqbn,'--build-path',str(out),
             '--warnings','default','--libraries',str(ble_libraries),
             '--build-property','compiler.c.elf.extra_flags=-Wl,--wrap=nvs_flash_erase -Wl,--wrap=nvs_flash_erase_partition -Wl,--wrap=esp_partition_erase_range -Wl,-u,__wrap_nvs_flash_erase -Wl,-u,__wrap_nvs_flash_erase_partition']
    cpp_flags='-DEVILKEY_NVS_GUARD_LINKED=1'
    if args.apps_vm_link_probe:
        cpp_flags+=' -DEVILKEY_APPS_LINK_PROBE'
    command.extend(['--build-property','compiler.cpp.extra_flags='+cpp_flags])
    command.append(str(ROOT/'EvilKeyV1'))
    subprocess.run(command,check=True)
except subprocess.CalledProcessError as exc:
    raise SystemExit(exc.returncode)
if source_digest()!=inputs_sha256:
    raise SystemExit('Source changed during compilation. Build is not eligible for flashing.')
properties=subprocess.run([cli,'compile','--fqbn',fqbn,'--show-properties',str(ROOT/'EvilKeyV1')],
                         check=True,capture_output=True,text=True,encoding='utf-8',errors='replace')
props=dict(line.split('=',1) for line in properties.stdout.splitlines() if '=' in line)
tool_prefix=Path(props['compiler.path'])/props['compiler.prefix']
nm=Path(str(tool_prefix)+'nm.exe')
symbols=subprocess.run([str(nm),str(out/'EvilKeyV1.ino.elf')],check=True,capture_output=True,text=True).stdout
required=['__wrap_nvs_flash_erase','__wrap_nvs_flash_erase_partition','__wrap_esp_partition_erase_range']
if any(not any(line.split()[-1:]==[name] for line in symbols.splitlines()) for name in required):
    raise SystemExit('Missing mandatory linked NVS guards. DO NOT UPLOAD.')
objdump=Path(str(tool_prefix)+'objdump.exe')
startup=subprocess.run([str(objdump),'-d','--disassemble=initArduino',str(out/'EvilKeyV1.ino.elf')],
                       check=True,capture_output=True,text=True).stdout
if '__wrap_esp_partition_erase_range' not in startup:
    raise SystemExit('Arduino NVS recovery is not routed through the guard. DO NOT UPLOAD.')
print('PASS: linked NVS guards; Arduino initialization erase recovery is intercepted.')
image=out/'EvilKeyV1.ino.bin'
if not image.is_file(): raise SystemExit('Expected application .bin was not found; inspect compiler output.')
if image.stat().st_size>0x400000:
    raise SystemExit('Application exceeds the reviewed 4 MiB factory partition. DO NOT UPLOAD.')
partition_image=out/'EvilKeyV1.ino.partitions.bin'
if not partition_image.is_file() or partition_image.stat().st_size!=0xC00:
    raise SystemExit('Expected 3072-byte partition image is missing. DO NOT UPLOAD.')
build_info={
    'schema':'evilkey-arduino-build-v1',
    'fqbn':fqbn,
    'sketch_path':str((ROOT/'EvilKeyV1').resolve()),
    'build_path':str(out.resolve()),
    'image_path':str(image.resolve()),
    'image_size':image.stat().st_size,
    'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),
    'partition_path':str(partition_image.resolve()),
    'partition_size':partition_image.stat().st_size,
    'partition_sha256':hashlib.sha256(partition_image.read_bytes()).hexdigest(),
    'erase_flash':'none',
    'app_offset':0x500000,'app_capacity':0x400000,
    'nvs_guard':'link-wrap-v1','build_inputs_sha256':inputs_sha256,
    'elf_sha256':hashlib.sha256((out/'EvilKeyV1.ino.elf').read_bytes()).hexdigest(),
    'apps_vm_link_probe':args.apps_vm_link_probe,
}
(out/'evilkey-build.json').write_text(
    json.dumps(build_info,indent=2)+'\n',encoding='utf-8')
print(f'Application image: {image} ({image.stat().st_size} bytes). No upload was performed.')
print(f'Build manifest: {out / "evilkey-build.json"}')
