"""Compute a flash digest in the ROM loader, without streaming key bytes over USB."""
import argparse
from contextlib import redirect_stdout
import hashlib
import io
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / '.cache' / 'flash-reader'
LOADER_SHA256 = '76dd375f208b0fe142deef06c5fed8cfa462e194296988e404c9ed5f9cb656ef'


def prepare():
    if not (RUNTIME / 'esptool' / 'loader.py').is_file():
        subprocess.run([sys.executable, '-m', 'pip', 'install',
                        '--disable-pip-version-check', '--target', str(RUNTIME),
                        'esptool==5.3.1'], check=True, stdout=sys.stderr)
    if hashlib.sha256((RUNTIME / 'esptool' / 'loader.py').read_bytes()).hexdigest() != LOADER_SHA256:
        raise RuntimeError('Digest runtime differs from reviewed esptool 5.3.1')


def digest(port, address, length):
    if not re.fullmatch(r'COM[1-9][0-9]*', port, re.I) or \
            address < 0 or length <= 0 or address + length > 0x1000000:
        raise ValueError('Invalid port or flash range')
    prepare()
    sys.path.insert(0, str(RUNTIME))
    import esptool
    from esptool.cmds import attach_flash
    with redirect_stdout(io.StringIO()):
        device = esptool.get_default_connected_device(
            [port], port=port, connect_attempts=3, initial_baud=115200,
            chip='esp32s3', before='default-reset')
        try:
            if device.sync_stub_detected:
                # An existing stub implements the same digest command, with a
                # binary response. No new stub upload or flash write is needed.
                device = device.run_stub()
            attach_flash(device)
            if (device.flash_id() >> 16) & 0xff != 24:
                raise RuntimeError('Expected the reviewed 16 MiB flash device')
            device.flash_set_parameters(0x1000000)
            result = device.flash_md5sum(address, length)
        finally:
            device._port.close()
    if not re.fullmatch(r'[0-9a-fA-F]{32}', result):
        raise RuntimeError('Invalid flash digest response')
    return result.lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port')
    parser.add_argument('address', type=lambda x: int(x, 0))
    parser.add_argument('length', type=lambda x: int(x, 0))
    args = parser.parse_args()
    print(digest(args.port, args.address, args.length))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('ERROR: flash digest: ' + str(exc), file=sys.stderr)
        sys.exit(2)
