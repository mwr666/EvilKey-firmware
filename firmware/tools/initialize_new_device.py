"""Explicit fresh-module initialization; never used by storage-preserving updates."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from .flash_safety import parse_table


def bootloader_fields(build_path):
    path = Path(build_path) / 'EvilKeyV1.ino.bootloader.bin'
    data = path.read_bytes()
    if not 24 <= len(data) < 0x8000 or data[0] != 0xE9 or not 1 <= data[1] <= 16 or \
            data[2:4] != bytes((2, 0x4F)) or struct.unpack_from('<H', data, 12)[0] != 9:
        raise RuntimeError('Expected ESP32-S3 DIO/80 MHz/16 MiB bootloader fitting below 0x8000')
    cursor, checksum = 24, 0xEF
    for _ in range(data[1]):
        if cursor + 8 > len(data):
            raise RuntimeError('Truncated bootloader segment header')
        length = struct.unpack_from('<I', data, cursor + 4)[0]
        cursor += 8
        if cursor + length > len(data):
            raise RuntimeError('Truncated bootloader segment')
        for byte in data[cursor:cursor + length]:
            checksum ^= byte
        cursor += length
    checksum_at = ((cursor + 16) // 16) * 16 - 1
    if checksum_at >= len(data) or data[checksum_at] != checksum:
        raise RuntimeError('Bootloader checksum mismatch')
    if data[23] != 1 or data[checksum_at + 1:checksum_at + 33] != hashlib.sha256(data[:checksum_at + 1]).digest():
        raise RuntimeError('Bootloader validation hash mismatch')
    return {'bootloader_path': str(path.resolve()), 'bootloader_size': len(data),
            'bootloader_sha256': hashlib.sha256(data).hexdigest()}


def validate_images(info):
    boot = bootloader_fields(info['build_path'])
    if any(info.get(key) != value for key, value in boot.items()):
        raise RuntimeError('Bootloader manifest is missing or stale; rebuild or enrich the verified manifest')
    table = Path(info['partition_path'])
    app = Path(info['image_path'])
    if parse_table(table.read_bytes()) != (0x500000, 0x400000) or \
            hashlib.sha256(table.read_bytes()).hexdigest() != info['partition_sha256'] or \
            hashlib.sha256(app.read_bytes()).hexdigest() != info['image_sha256'] or \
            not 0 < app.stat().st_size <= 0x400000:
        raise RuntimeError('Fresh initialization image/table mismatch')
    return [(0, Path(boot['bootloader_path'])), (0x8000, table), (0x500000, app)]


def confirm_initialization(answer):
    return answer.strip() == 'ERASE'


def initialize(esptool, port, info, observed_table, backup_root, *, confirmation):
    if not confirm_initialization(confirmation):
        raise RuntimeError('Fresh initialization requires exact ERASE confirmation')
    if not re.fullmatch(r'COM[1-9][0-9]*', port['address'], re.I):
        raise RuntimeError('Invalid COM port')
    images = validate_images(info)
    prefix = [str(esptool), '--chip', 'esp32s3', '--port', port['address'], '--baud', '115200',
              '--before', 'default-reset', '--after', 'no-reset']
    # esptool enforces the selected chip; verify physical flash before destruction.
    probe = subprocess.run(prefix + ['flash-id'], check=True, capture_output=True, text=True)
    if not re.search(r'Detected flash size:\s*16MB\b', probe.stdout):
        raise RuntimeError('Fresh initialization requires detected 16 MiB flash')
    backup = Path(backup_root) / ('fresh-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True, exist_ok=False)
    (backup / 'partition-before.bin').write_bytes(observed_table)
    receipt = {'schema': 'evilkey-fresh-initialization-v1', 'port': port['address'],
               'board_revision': info['board_revision'], 'data_preservation': False,
               'authorization': 'explicit ERASE; all module flash including NVS is discarded',
               'image_sha256': info['image_sha256'], 'partition_sha256': info['partition_sha256'],
               'bootloader_sha256': info['bootloader_sha256'], 'writes': [hex(a) for a, _ in images],
               'erase_completed': False, 'verified': False, 'status': 'in_progress'}
    receipt_path = backup / 'initialization.json'
    def save():
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    save()
    try:
        # Recheck immediately before erase, after the read-only probe.
        validate_images(info)
        subprocess.run(prefix + ['erase-flash'], check=True)
        receipt['erase_completed'] = True
        save()
        args = [value for address, path in images for value in (hex(address), str(path))]
        subprocess.run(prefix + ['write-flash', '--flash-mode', 'keep', '--flash-freq', 'keep',
                                 '--flash-size', 'keep'] + args, check=True)
        subprocess.run(prefix + ['verify-flash'] + args, check=True)
        readback = backup / 'partition-after.bin'
        subprocess.run(prefix + ['read-flash', '--no-progress', '0x8000', '3072', str(readback)], check=True)
        if readback.read_bytes() != images[1][1].read_bytes():
            raise RuntimeError('Partition table readback mismatch')
        receipt.update(verified=True, status='PASS')
        save()
    except (OSError, RuntimeError, subprocess.CalledProcessError, KeyboardInterrupt) as exc:
        receipt.update(status='FAIL', error=str(exc))
        save()
        raise
    # Reset only after all writes and readbacks succeeded; failures stay in ROM.
    reset_prefix = prefix.copy()
    reset_prefix[reset_prefix.index('no-reset')] = 'hard-reset'
    subprocess.run(reset_prefix + ['read-mac'], check=True)
    print('PASS: fresh module initialized; bootloader/BIN/table verified. Receipt: ' + str(receipt_path))
    print('If the programming COM port remains present or the screen is blank, press RESET without BOOT.')
    return receipt_path
