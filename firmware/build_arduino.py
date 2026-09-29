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
fqbn=('esp32:esp32:waveshare_esp32_s3_touch_amoled_164:USBMode=default,'
      'CDCOnBoot=default,MSCOnBoot=default,DFUOnBoot=default,PSRAM=enabled,'
      'FlashMode=qio,PartitionScheme=app3M_fat9M_16MB,EraseFlash=none')
out=ROOT/('build-arduino-apps-probe' if args.apps_vm_link_probe else 'build-arduino')
try:
    command=[cli,'compile','--fqbn',fqbn,'--build-path',str(out),
             '--warnings','default']
    if args.apps_vm_link_probe:
        command.extend(['--build-property',
                        'compiler.cpp.extra_flags=-DEVILKEY_APPS_LINK_PROBE'])
    command.append(str(ROOT/'EvilKeyV1'))
    subprocess.run(command,check=True)
except subprocess.CalledProcessError as exc:
    raise SystemExit(exc.returncode)
image=out/'EvilKeyV1.ino.bin'
if not image.is_file(): raise SystemExit('Expected application .bin was not found; inspect compiler output.')
if image.stat().st_size>0x1F0000:
    raise SystemExit('Application exceeds the custom 0x1F0000-byte factory partition. DO NOT UPLOAD.')
build_info={
    'schema':'evilkey-arduino-build-v1',
    'fqbn':fqbn,
    'sketch_path':str((ROOT/'EvilKeyV1').resolve()),
    'build_path':str(out.resolve()),
    'image_path':str(image.resolve()),
    'image_size':image.stat().st_size,
    'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),
    'erase_flash':'none',
    'apps_vm_link_probe':args.apps_vm_link_probe,
}
(out/'evilkey-build.json').write_text(
    json.dumps(build_info,indent=2)+'\n',encoding='utf-8')
print(f'Application image: {image} ({image.stat().st_size} bytes). No upload was performed.')
print(f'Build manifest: {out / "evilkey-build.json"}')
