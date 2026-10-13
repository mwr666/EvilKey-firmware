import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'firmware'))
import flash_arduino as FLASH
from tools import initialize_new_device as FRESH


def fixture(root):
    root = root.resolve()
    header = bytearray(24)
    header[:4] = bytes((0xE9, 1, 2, 0x4F))
    header[12:14] = struct.pack('<H', 9)
    header[23] = 1
    segment = b'bootloader test payload'
    data = header + struct.pack('<II', 0x403C0000, len(segment)) + segment
    checksum = 0xEF
    for byte in segment:
        checksum ^= byte
    data += b'\0' * ((((len(data) + 16) // 16) * 16 - 1) - len(data)) + bytes((checksum,))
    data += hashlib.sha256(data).digest()
    boot = root / 'EvilKeyV1.ino.bootloader.bin'
    boot.write_bytes(data)
    records = []
    for name, kind, sub, offset, size in (
        ('nvs', 1, 2, 0x9000, 0x5000), ('otadata', 1, 0, 0xE000, 0x2000),
        ('part0', 0x40, 1, 0x200000, 0x100000), ('wsdev', 1, 2, 0x400000, 0x10000),
        ('factory', 0, 0, 0x500000, 0x400000)):
        records.append(struct.pack('<HBBII16sI', 0x50AA, kind, sub, offset, size, name.encode(), 0))
    raw = b''.join(records)
    raw += b'\xeb\xeb' + b'\xff' * 14 + hashlib.md5(raw).digest()
    raw += b'\xff' * (0xC00 - len(raw))
    table = root / 'EvilKeyV1.ino.partitions.bin'
    table.write_bytes(raw)
    app = root / 'EvilKeyV1.ino.bin'
    app.write_bytes(b'known application bytes')
    return dict(build_path=str(root), board_revision='v1.1', partition_path=str(table),
                image_path=str(app), image_sha256=hashlib.sha256(app.read_bytes()).hexdigest(),
                partition_sha256=hashlib.sha256(raw).hexdigest(), **FRESH.bootloader_fields(root))


class FreshTests(unittest.TestCase):
    def test_only_exact_erase_confirms_destruction(self):
        self.assertTrue(FRESH.confirm_initialization(' ERASE '))
        for text in ('', 'Y', 'yes', 'erase', 'N', 'ERASE ALL'):
            self.assertFalse(FRESH.confirm_initialization(text))

    def test_reviewed_table_uses_preservation_and_blank_table_needs_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = fixture(Path(tmp))
            self.assertFalse(FLASH.needs_initialization(Path(info['partition_path']).read_bytes()))
        self.assertTrue(FLASH.needs_initialization(b'\xff' * 0xC00))
        self.assertTrue(FLASH.needs_initialization(b'bad table'))

    def test_missing_confirmation_and_corrupt_image_stop_before_any_device_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = fixture(Path(tmp))
            with patch.object(FRESH.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    FRESH.initialize('esptool', {'address': 'COM6'}, info, b'', tmp, confirmation='Y')
                Path(info['image_path']).write_bytes(b'changed')
                with self.assertRaises(RuntimeError):
                    FRESH.initialize('esptool', {'address': 'COM6'}, info, b'', tmp, confirmation='ERASE')
                run.assert_not_called()

    def test_wrong_flash_size_stops_before_erase(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = fixture(Path(tmp))
            with patch.object(FRESH.subprocess, 'run', return_value=SimpleNamespace(stdout='Detected flash size: 8MB')) as run:
                with self.assertRaises(RuntimeError):
                    FRESH.initialize('esptool', {'address': 'COM6'}, info, b'', tmp, confirmation='ERASE')
                self.assertEqual(run.call_count, 1)
                self.assertIn('flash-id', run.call_args[0][0])

    def test_bootloader_corruption_and_wrong_chip_are_rejected(self):
        for index in (12, 35):
            with tempfile.TemporaryDirectory() as tmp:
                info = fixture(Path(tmp))
                path = Path(info['bootloader_path'])
                raw = bytearray(path.read_bytes())
                raw[index] ^= 1
                path.write_bytes(raw)
                with self.assertRaises(RuntimeError):
                    FRESH.validate_images(info)

    def run_install(self, fail=None):
        with tempfile.TemporaryDirectory() as tmp:
            info = fixture(Path(tmp))
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                if fail and fail in command:
                    raise subprocess.CalledProcessError(2, command)
                if 'read-flash' in command:
                    Path(command[-1]).write_bytes(Path(info['partition_path']).read_bytes())
                return SimpleNamespace(stdout='Detected flash size: 16MB', returncode=0)
            with patch.object(FRESH.subprocess, 'run', side_effect=run):
                if fail:
                    with self.assertRaises(subprocess.CalledProcessError):
                        FRESH.initialize('esptool', {'address': 'COM6'}, info, b'original', tmp, confirmation='ERASE')
                else:
                    receipt = FRESH.initialize('esptool', {'address': 'COM6'}, info, b'original', tmp, confirmation='ERASE')
                    self.assertTrue(json.loads(receipt.read_text())['verified'])
            return commands

    def test_correct_order_offsets_verification_and_reset(self):
        commands = self.run_install()
        self.assertEqual(len(commands), 6)
        for command, name in zip(commands, ('flash-id', 'erase-flash', 'write-flash', 'verify-flash', 'read-flash', 'read-mac')):
            self.assertIn(name, command)
        writes = commands[2]
        self.assertIn('0x0', writes)
        self.assertIn('0x8000', writes)
        self.assertIn('0x500000', writes)
        self.assertNotIn('0x10000', writes)
        self.assertIn('hard-reset', commands[-1])

    def test_verification_failure_never_resets_or_retries(self):
        commands = self.run_install('verify-flash')
        self.assertEqual(sum('erase-flash' in c for c in commands), 1)
        self.assertFalse(any('hard-reset' in c for c in commands))

    def test_interrupted_write_records_failure_without_reset_or_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = fixture(Path(tmp))
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                if 'write-flash' in command:
                    raise KeyboardInterrupt()
                return SimpleNamespace(stdout='Detected flash size: 16MB', returncode=0)
            with patch.object(FRESH.subprocess, 'run', side_effect=run):
                with self.assertRaises(KeyboardInterrupt):
                    FRESH.initialize('esptool', {'address': 'COM6'}, info, b'old', tmp, confirmation='ERASE')
            receipt = json.loads(next(Path(tmp).glob('fresh-*/initialization.json')).read_text())
            self.assertEqual(receipt['status'], 'FAIL')
            self.assertFalse(receipt['verified'])
            self.assertEqual(sum('erase-flash' in c for c in commands), 1)
            self.assertFalse(any('hard-reset' in c for c in commands))

    def test_unsupported_layout_cancellation_never_calls_installer(self):
        ports = [{'address': 'COM6', 'boards': '', 'label': 'ESP32'}]
        with patch.object(sys, 'argv', ['flash_arduino.py', '--board-revision', 'v1.1', '--use-verified-build']), \
             patch.object(FLASH.shutil, 'which', return_value='arduino-cli'), \
             patch.object(FLASH, 'discover_ports', return_value=ports), \
             patch.object(FLASH, 'load_verified_build_info', return_value={'fqbn': 'test'}), \
             patch.object(FLASH, 'resolve_esptool', return_value=Path('esptool')), \
             patch.object(FLASH, 'verify_device_partition', return_value=b'\xff' * 0xC00), \
             patch('builtins.input', side_effect=['COM6', 'Y', '']), \
             patch.object(FLASH, 'initialize_new_device') as initialize, \
             patch.object(FLASH, 'install_preserving_storage') as preserve:
            self.assertEqual(FLASH.main(), 0)
            initialize.assert_not_called()
            preserve.assert_not_called()


if __name__ == '__main__':
    unittest.main()
