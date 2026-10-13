from pathlib import Path
import json
import hashlib
import sys
import tempfile
import re
import subprocess
import shutil
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'firmware'))
import board_profiles as BOARD
import flash_arduino as FLASH


class BoardTests(unittest.TestCase):
    def test_revision_input_does_not_default_on_empty_or_unknown(self):
        for answer, expected in [('1', 'v1'), ('2', 'v1.1'), (' V1.1 ', 'v1.1'), ('v1', 'v1')]:
            self.assertEqual(BOARD.choose_revision(answer), expected)
        for answer in ('', 'q', 'V2', '3', 'COM5'):
            self.assertIsNone(BOARD.choose_revision(answer))

    def test_board_cancel_never_discovers_ports_or_builds(self):
        for answer in ('', 'q', 'wrong'):
            with patch('builtins.input', return_value=answer), \
                 patch.object(sys, 'argv', ['flash_arduino.py']), \
                 patch.object(FLASH, 'discover_ports') as ports, \
                 patch.object(FLASH.subprocess, 'run') as run:
                self.assertEqual(FLASH.main(), 0)
                ports.assert_not_called()
                run.assert_not_called()

    def test_v11_prompt_precedes_port_and_build_receives_revision(self):
        ports = [{'address': 'COM7', 'label': 'test', 'boards': '', 'protocol': 'serial'}]
        with patch('builtins.input', side_effect=['2', '1', 'Y']), \
             patch.object(sys, 'argv', ['flash_arduino.py']), \
             patch.object(FLASH.shutil, 'which', return_value='arduino-cli'), \
             patch.object(FLASH, 'discover_ports', return_value=ports), \
             patch.object(FLASH.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, \
             patch.object(FLASH, 'load_verified_build_info', side_effect=RuntimeError('stop before USB')) as load:
            self.assertEqual(FLASH.main(), 2)
            run.assert_called_once_with([sys.executable, str(FLASH.BUILD_SCRIPT), '--board-revision', 'v1.1'])
            load.assert_called_once_with('v1.1')

    def test_list_only_never_prompts_or_builds(self):
        with patch.object(sys, 'argv', ['flash_arduino.py', '--list-only']), \
             patch.object(FLASH.shutil, 'which', return_value='arduino-cli'), \
             patch.object(FLASH, 'discover_ports', return_value=[{'address': 'COM7', 'label': '', 'boards': ''}]), \
             patch('builtins.input') as ask, patch.object(FLASH.subprocess, 'run') as run:
            self.assertEqual(FLASH.main(), 0)
            ask.assert_not_called()
            run.assert_not_called()

    def test_wrong_missing_and_probe_revision_rejected_before_storage_checks(self):
        for revision in BOARD.REVISIONS:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                out = BOARD.build_path(root, revision)
                out.mkdir(parents=True)
                for identity in ({}, {'board_revision': 'v1.1' if revision == 'v1' else 'v1'},
                                 {'board_revision': revision, 'board_define': BOARD.board_define(revision),
                                  'apps_vm_link_probe': True}):
                    (out / 'evilkey-build.json').write_text(json.dumps({'schema': 'evilkey-arduino-build-v1', **identity}))
                    with patch.object(FLASH, 'ROOT', root), patch.object(FLASH, 'verify_ble_storage') as store:
                        with self.assertRaises(RuntimeError):
                            FLASH.load_verified_build_info(revision)
                        store.assert_not_called()

    def test_separate_output_profiles_and_c_cpp_flags(self):
        self.assertNotEqual(BOARD.build_path(ROOT, 'v1'), BOARD.build_path(ROOT, 'v1.1'))
        self.assertNotEqual(BOARD.build_path(ROOT, 'v1'), BOARD.build_path(ROOT, 'v1', True))
        source = (ROOT / 'firmware/build_arduino.py').read_text()
        self.assertIn('compiler.c.extra_flags=', source)
        self.assertIn('compiler.cpp.extra_flags=', source)

    @unittest.skipUnless(shutil.which('gcc'), 'GPIO preprocessing requires GCC; full board qualification must run it')
    def test_preprocessed_pin_profiles_match_manufacturer_table(self):
        compiler = shutil.which('gcc')
        self.assertIsNotNone(compiler, 'GPIO contract requires a C preprocessor')
        header = ROOT / 'firmware/templates/port/ws_pins.h'
        shared = {'WS_LCD_CLK': 10, 'WS_LCD_D0': 11, 'WS_LCD_D1': 12, 'WS_LCD_D2': 13,
                  'WS_LCD_D3': 14, 'WS_LCD_RESET': 21, 'WS_I2C_SDA': 47, 'WS_I2C_SCL': 48,
                  'WS_SD_CS': 38, 'WS_SD_MOSI': 39, 'WS_SD_MISO': 40, 'WS_SD_SCLK': 41,
                  'WS_USB_DM': 19, 'WS_USB_DP': 20, 'WS_BOOT': 0}
        for flag, pins in (([], {'WS_LCD_CS': 9, 'WS_IMU_INT1': 46, 'WS_IMU_INT2': -1,
                                'WS_TOUCH_INT': -1, 'WS_TOUCH_RESET': -1, 'WS_LCD_TE': -1}),
                           (['-DEVILKEY_BOARD_REVISION=10'], {'WS_LCD_CS': 9, 'WS_IMU_INT1': 46,
                                'WS_IMU_INT2': -1, 'WS_TOUCH_INT': -1, 'WS_TOUCH_RESET': -1, 'WS_LCD_TE': -1}),
                           (['-DEVILKEY_BOARD_REVISION=11'], {'WS_LCD_CS': 46, 'WS_IMU_INT1': 9,
                                'WS_IMU_INT2': 17, 'WS_TOUCH_INT': 18, 'WS_TOUCH_RESET': 21, 'WS_LCD_TE': 45})):
            result = subprocess.run([compiler, '-E', '-dM', '-x', 'c', *flag, str(header)],
                                    capture_output=True, text=True, check=True)
            macros = dict(re.findall(r'^#define\s+(WS_\w+)\s+([^\n]+)', result.stdout, re.M))
            for name, value in {**shared, **pins}.items():
                self.assertEqual(int(macros[name].strip('() ')), value, name)
        invalid = subprocess.run([compiler, '-E', '-x', 'c', '-DEVILKEY_BOARD_REVISION=12', str(header)],
                                 capture_output=True, text=True)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn('Unsupported EVILKEY_BOARD_REVISION', invalid.stderr)

    def test_generated_board_consumers_match_templates_and_hashes(self):
        import hashlib
        manifest = json.loads((ROOT / 'firmware/EvilKeyV1/GENERATED_MANIFEST.json').read_text())
        for name in ('ws_pins.h', 'ws_panel.h', 'ws_panel.c', 'ws_board.c'):
            template = (ROOT / 'firmware/templates/port' / name).read_text()
            generated_path = ROOT / 'firmware/EvilKeyV1/src/engine/board' / name
            generated = generated_path.read_text()
            if name.endswith('.c'):
                generated = generated.removeprefix('#include "../../pf_build_config.h"\n')
                generated = generated.replace('"../../apps/', '"../../EvilKeyV1/src/apps/')
                generated = generated.replace('"../../pf_engine_api.h"', '"pf_engine_api.h"')
                generated = generated.replace('"../sdk/src/led/led.h"', '"led/led.h"')
            self.assertEqual(generated, template)
            self.assertEqual(manifest['generated_sha256']['board/' + name], hashlib.sha256(generated_path.read_bytes()).hexdigest())

    def test_corrupt_images_or_stale_sources_cannot_reuse_a_verified_build(self):
        for corrupted in ('image', 'elf', 'partition', 'source'):
            with self.subTest(corrupted=corrupted), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                out = BOARD.build_path(root, 'v1.1')
                out.mkdir(parents=True)
                image, elf, partition = [out / ('EvilKeyV1.ino.' + suffix) for suffix in ('bin', 'elf', 'partitions.bin')]
                image.write_bytes(b'valid application')
                elf.write_bytes(b'valid linked elf')
                partition.write_bytes(b'\0' * 0xC00)
                info = {'schema': 'evilkey-arduino-build-v1', 'board_revision': 'v1.1',
                        'board_define': '-DEVILKEY_BOARD_REVISION=11', 'apps_vm_link_probe': False,
                        'build_path': str(out), 'sketch_path': str(root / 'EvilKeyV1'), 'image_path': str(image),
                        'partition_path': str(partition), 'image_size': image.stat().st_size,
                        'partition_size': 0xC00, 'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                        'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest(),
                        'partition_sha256': hashlib.sha256(partition.read_bytes()).hexdigest(),
                        'fqbn': 'vendor:arch:board:EraseFlash=none', 'erase_flash': 'none',
                        'nvs_guard': 'link-wrap-v1', 'app_offset': 0x500000, 'app_capacity': 0x400000,
                        'build_inputs_sha256': 'current inputs'}
                (out / 'evilkey-build.json').write_text(json.dumps(info))
                with patch.object(FLASH, 'ROOT', root), patch.object(FLASH, 'verify_partition_layout'), \
                     patch.object(FLASH, 'verify_ble_storage'), \
                     patch.object(FLASH, 'source_digest', return_value='current inputs') as digest, \
                     patch.object(FLASH, 'parse_table', return_value=(0x500000, 0x400000)):
                    self.assertEqual(FLASH.load_verified_build_info('v1.1')['board_revision'], 'v1.1')
                    if corrupted == 'source':
                        digest.return_value = 'changed inputs'
                    else:
                        {'image': image, 'elf': elf, 'partition': partition}[corrupted].write_bytes(b'corrupted')
                    with self.assertRaises(RuntimeError):
                        FLASH.load_verified_build_info('v1.1')


if __name__ == '__main__':
    unittest.main()
