from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware"))
SPEC = importlib.util.spec_from_file_location(
    "picofido_flash_arduino", ROOT / "firmware" / "flash_arduino.py"
)
assert SPEC and SPEC.loader
FLASH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLASH)


class FlashArduinoTests(unittest.TestCase):
    def test_only_y_confirms_upload(self):
        for value in ("Y", "y", " y "):
            self.assertTrue(FLASH.confirm_upload(value))
        for value in ("N", "", "WGRYWAJ", "yes", "1"):
            self.assertFalse(FLASH.confirm_upload(value))

    def test_n_cancels_before_build_or_upload(self):
        ports = [{"address": "COM7", "label": "EvilKey", "protocol": "serial", "boards": ""}]
        with patch.object(FLASH.shutil, "which", return_value="arduino-cli"), \
             patch.object(FLASH, "discover_ports", return_value=ports), \
             patch("builtins.input", side_effect=["1", "N"]), \
             patch.object(FLASH.subprocess, "run") as run, \
             patch.object(FLASH.sys, "argv", ["flash_arduino.py"]):
            self.assertEqual(FLASH.main(), 0)
            run.assert_not_called()

    def test_y_builds_rechecks_port_and_uses_storage_preserving_installer(self):
        ports = [{"address": "COM7", "label": "EvilKey", "protocol": "serial", "boards": ""}]
        info = {"fqbn": "vendor:arch:board:EraseFlash=none", "image_path": "C:/private/firmware.bin"}
        with patch.object(FLASH.shutil, "which", return_value="arduino-cli"), \
             patch.object(FLASH, "discover_ports", side_effect=[ports, ports]) as discover, \
             patch.object(FLASH, "load_verified_build_info", return_value=info), \
             patch.object(FLASH, "resolve_esptool", return_value=Path("esptool.exe")), \
             patch.object(FLASH, "verify_device_partition", return_value=b"reviewed table"), \
             patch.object(FLASH, "install_preserving_storage") as install, \
             patch("builtins.input", side_effect=["1", "Y"]), \
             patch.object(FLASH.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
             patch.object(FLASH.sys, "argv", ["flash_arduino.py"]):
            self.assertEqual(FLASH.main(), 0)
            self.assertEqual(discover.call_count, 2)
            run.assert_called_once_with([FLASH.sys.executable, str(FLASH.BUILD_SCRIPT)])
            install.assert_called_once_with(Path("esptool.exe"), ports[0], info,
                                            b"reviewed table", FLASH.ROOT / '.flash-backups')

    def test_port_parser_lists_only_unique_windows_com_ports_numerically(self):
        payload = {
            "detected_ports": [
                {"port": {"address": "COM12", "label": "USB Serial", "protocol": "serial"}},
                {"port": {"address": "/dev/ttyACM0", "protocol": "serial"}},
                {"port": {"address": "com3", "label": "PicoFido", "protocol": "serial"},
                 "matching_boards": [{"name": "Waveshare ESP32-S3"}]},
                {"port": {"address": "COM3", "label": "duplicate", "protocol": "serial"}},
            ]
        }
        ports = FLASH.parse_windows_com_ports(payload)
        self.assertEqual([port["address"] for port in ports], ["COM3", "COM12"])

    def test_port_must_be_selected_from_displayed_list(self):
        ports = [
            {"address": "COM3", "label": "COM3", "protocol": "serial", "boards": ""},
            {"address": "COM12", "label": "COM12", "protocol": "serial", "boards": ""},
        ]
        self.assertEqual(FLASH.choose_port(ports, "2")["address"], "COM12")
        self.assertEqual(FLASH.choose_port(ports, "com3")["address"], "COM3")
        self.assertIsNone(FLASH.choose_port(ports, "COM99"))
        self.assertIsNone(FLASH.choose_port(ports, "3"))

    def test_write_guard_bounds_application_and_rejects_protected_sectors(self):
        self.assertEqual(FLASH.APP_OFFSET, 0x500000)
        FLASH.validate_write(FLASH.APP_OFFSET, 2205088,
                             app_offset=FLASH.APP_OFFSET, app_capacity=FLASH.APP_CAPACITY)
        for offset, size in FLASH.PROTECTED.values():
            with self.assertRaises(RuntimeError):
                FLASH.validate_write(offset, size,
                                     app_offset=FLASH.APP_OFFSET, app_capacity=FLASH.APP_CAPACITY)
        with self.assertRaises(RuntimeError):
            FLASH.validate_command(["esptool.exe", "erase-flash"])

    def test_app_partition_is_disjoint_from_nvs_and_other_data(self):
        FLASH.verify_partition_layout()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            table = root / "EvilKeyV1" / "partitions.csv"
            table.parent.mkdir()
            table.write_text("nvs,data,nvs,0x9000,0x10000\n"
                             "factory,app,factory,0x10000,0x1F0000\n",
                             encoding="utf-8")
            with patch.object(FLASH, "ROOT", root):
                with self.assertRaises(RuntimeError):
                    FLASH.verify_partition_layout()

    def test_device_partition_mismatch_stops_before_app_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "expected.bin"
            expected.write_bytes(b"original table")
            info = {"partition_path": str(expected), "partition_size": len(expected.read_bytes())}
            port = {"address": "COM7"}

            def wrong_table(command: list[str], **_: object) -> SimpleNamespace:
                self.assertIn("read-flash", command)
                self.assertNotIn("write-flash", command)
                Path(command[-1]).write_bytes(b"changed table!")
                return SimpleNamespace(returncode=0)

            with patch.object(FLASH.subprocess, "run", side_effect=wrong_table) as run:
                with self.assertRaises(RuntimeError):
                    FLASH.verify_device_partition(Path("esptool.exe"), port, info)
                run.assert_called_once()

    def test_menu_and_build_manifest_contract_are_wired(self):
        menu = (ROOT / "EvilKey.cmd").read_text(encoding="utf-8")
        wrapper = (ROOT / "scripts" / "commands" / "Flash_firmware.cmd").read_text(encoding="utf-8")
        build = (ROOT / "firmware" / "build_arduino.py").read_text(encoding="utf-8")
        self.assertIn('"11" call scripts\\commands\\Flash_firmware.cmd', menu)
        self.assertIn("firmware\\flash_arduino.py", wrapper)
        self.assertIn("evilkey-arduino-build-v1", build)
        self.assertIn("EraseFlash=none", build)


if __name__ == "__main__":
    unittest.main()
