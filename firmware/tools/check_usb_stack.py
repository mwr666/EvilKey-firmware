#!/usr/bin/env python3
"""Reversible S2 patch for Arduino-ESP32 3.3.11/3.3.12.

S2 retains the 16384 B usbd stack from S1 and adds a passive hook counting
GET CONFIGURATION DESCRIPTOR calls for DuckyScript 3 OS detection.

Only the local core file and its backup are involved. No USB, UART, pip, or
device programming. The core change affects other projects using this install.
Keep the 16384 B stack for EvilKey 0.4.0. --restore is only for retiring this
project requirement. R14 prefers Arduino-ESP32 3.3.12 and also supports 3.3.11;
other versions are rejected until validated.
Python 3.10+; standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

SUPPORTED = {
    (3, 3, 11): "5b6bfb437b851b78578574ca44d157e115bf7930",
    (3, 3, 12): "d8fcd0b428848010d3b3773b5b0e02515693f0e0",
}
PREFERRED = (3, 3, 12)
CALL = b'xTaskCreate(usb_device_task, "usbd", 4096, NULL, configMAX_PRIORITIES - 1, NULL);'
NEW_CALL = CALL.replace(b"4096", b"16384")
MARKER = b'PICO_FIDO_USBD_STACK_TEST_S1: usbd stack=16384 bytes'
PRAGMA = b'#pragma message ("' + MARKER + b'")'
HOOK_MARKER = b'PICO_FIDO_DUCKY_OS_HOOK_S2: count GET CONFIGURATION DESCRIPTOR'
HOOK_PRAGMA = b'#pragma message ("' + HOOK_MARKER + b'")'
CONFIG_CALLBACK = b'''__attribute__((weak)) uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
  //log_d("%u", index);
  return tinyusb_config_descriptor;
}'''
CONFIG_CALLBACK_CRLF = CONFIG_CALLBACK.replace(b"\n", b"\r\n")


class Stop(RuntimeError):
    """A validation failure: do not continue or override safeguards."""


def vstr(version: tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized(data: bytes) -> bytes:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.replace(b"\r\n", b"\n")


def git_blob_sha(data: bytes) -> str:
    data = normalized(data)
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def expected_original(data: bytes, version: tuple[int, int, int]) -> None:
    expected_blob = SUPPORTED[version]
    blob = git_blob_sha(data)
    if blob != expected_blob:
        raise Stop(
            f"Plik core nie jest oczekiwanym oryginalem {vstr(version)}. Nic nie zmieniono.\n"
            f"Oczekiwany Git blob: {expected_blob}\nOdczytany Git blob:  {blob}\n"
            "Zachowaj ten komunikat i plik esp32-hal-tinyusb.c do analizy."
        )
    if data.count(CALL) != 1 or MARKER in data:
        raise Stop("Could not identify one original xTaskCreate statement. Stopped.")


def legacy_patch_bytes(data: bytes, version: tuple[int, int, int]) -> bytes:
    expected_original(data, version)
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    return data.replace(CALL, PRAGMA + newline + b"  " + NEW_CALL, 1)


def patch_bytes(data: bytes, version: tuple[int, int, int]) -> bytes:
    patched = legacy_patch_bytes(data, version)
    newline = b"\r\n" if b"\r\n" in patched else b"\n"
    callback = CONFIG_CALLBACK_CRLF if newline == b"\r\n" else CONFIG_CALLBACK
    if patched.count(callback) != 1 or HOOK_MARKER in patched:
        raise Stop("Could not identify one configuration descriptor callback. Stopped.")
    replacement = (
        HOOK_PRAGMA + newline
        + b'__attribute__((weak)) void pf_usb_configuration_descriptor_requested(void) {}'
        + newline + newline
        + callback.replace(
            b'  //log_d("%u", index);' + newline,
            b'  //log_d("%u", index);' + newline
            + b'  pf_usb_configuration_descriptor_requested();' + newline,
            1,
        )
    )
    return patched.replace(callback, replacement, 1)


def ensure_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise Stop(f"Expected a regular file, not a link: {path}")


def read_version(core: Path) -> tuple[int, int, int]:
    header = core / "esp_arduino_version.h"
    ensure_regular_file(header)
    text = header.read_text(encoding="utf-8-sig")
    parts: list[int] = []
    for name in ("MAJOR", "MINOR", "PATCH"):
        matches = re.findall(r"(?m)^\s*#\s*define\s+ESP_ARDUINO_VERSION_" + name + r"\s+(\d+)\b", text)
        if len(matches) != 1:
            raise Stop("Could not verify the Arduino-ESP32 version unambiguously.")
        parts.append(int(matches[0]))
    version = tuple(parts)
    if version not in SUPPORTED:
        allowed = ", ".join(vstr(v) for v in sorted(SUPPORTED))
        raise Stop(f"Obslugiwane wersje Arduino-ESP32: {allowed}. Odczytano: {vstr(version)}")
    return version  # type: ignore[return-value]


def validate_core(core: Path) -> tuple[Path, tuple[int, int, int]]:
    version = read_version(core)
    target = core / "esp32-hal-tinyusb.c"
    ensure_regular_file(target)
    return target, version


def backup_paths(target: Path, storage: Path, version: tuple[int, int, int]) -> tuple[Path, Path, Path]:
    key = hashlib.sha256(str(target.resolve()).encode("utf-8")).hexdigest()[:20]
    folder = storage / ("arduino-esp32-" + vstr(version) + "-" + key)
    return folder, folder / "original-esp32-hal-tinyusb.c", folder / "state.json"


def atomic_replace(path: Path, expected: bytes, replacement: bytes) -> None:
    """Write a same-directory temporary file; verify before replacing target."""
    if path.read_bytes() != expected:
        raise Stop("The file changed during the operation; it was not replaced.")
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, name = tempfile.mkstemp(prefix=".pico-fido-S1-", suffix=".tmp", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        if path.read_bytes() != expected:
            raise Stop("The file changed before writing; it was not replaced.")
        os.replace(temp, path)
        if path.read_bytes() != replacement:
            raise Stop("Read-back does not match the write. Preserve the backup.")
    finally:
        if temp.exists():
            temp.unlink()


def load_backup(target: Path, backup: Path, manifest: Path,
                version: tuple[int, int, int]) -> tuple[bytes, bytes]:
    ensure_regular_file(backup)
    ensure_regular_file(manifest)
    info = json.loads(manifest.read_text(encoding="utf-8"))
    original = backup.read_bytes()
    expected_original(original, version)
    patched = patch_bytes(original, version)
    recorded_test = info.get("test")
    recorded_patch = legacy_patch_bytes(original, version) if recorded_test == "S1" else patched
    if (info.get("target") != str(target.resolve()) or
            info.get("core_version") != vstr(version) or
            info.get("original_sha256") != sha256(original) or
            info.get("patched_sha256") != sha256(recorded_patch) or
            info.get("original_git_blob_lf") != SUPPORTED[version] or
            recorded_test not in ("S1", "S2")):
        raise Stop("Manifest or backup mismatch; the core was not overwritten.")
    return original, patched


def save_backup(target: Path, storage: Path, original: bytes, patched: bytes,
                version: tuple[int, int, int]) -> Path:
    folder, backup, manifest = backup_paths(target, storage, version)
    if backup.exists() or manifest.exists():
        if not (backup.exists() and manifest.exists()):
            raise Stop(f"Incomplete previous backup: {folder}. It was not overwritten.")
        old_original, old_patched = load_backup(target, backup, manifest, version)
        if old_original != original or old_patched != patched:
            raise Stop("Istniejaca kopia nie odpowiada aktualnym bajtom. Przerwano.")
        return folder
    folder.mkdir(parents=True, exist_ok=True)
    with backup.open("xb") as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    if backup.read_bytes() != original:
        raise Stop("Could not verify the backup; the core was not changed.")
    info = {
        "test": "S2", "core_version": vstr(version), "target": str(target.resolve()),
        "original_git_blob_lf": SUPPORTED[version], "original_sha256": sha256(original),
        "patched_sha256": sha256(patched), "stack_before_bytes": 4096,
        "stack_after_bytes": 16384, "ducky_os_configuration_hook": True,
    }
    with manifest.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(info, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    load_backup(target, backup, manifest, version)
    return folder


def execute(action: str, core: Path, storage: Path) -> tuple[Path, tuple[int, int, int]]:
    target, version = validate_core(core)
    current = target.read_bytes()
    folder, backup, manifest = backup_paths(target, storage, version)
    print(f"Core {vstr(version)}: {target}")
    print(f"UWAGA: ten core jest wspolny dla projektow uzywajacych instalacji {vstr(version)}.")
    if MARKER in current:
        original, patched = load_backup(target, backup, manifest, version)
        legacy = legacy_patch_bytes(original, version)
        if current not in (legacy, patched):
            raise Stop("Core zmieniono po instalacji S1/S2. Odmowa nadpisania; zachowaj plik.")
        if action == "restore":
            atomic_replace(target, current, original)
            print("RESTORE OK: the 4096 B core was restored. Device firmware was not changed.")
            print("A future build or upload will use the restored stack.")
        elif current == legacy and action == "apply":
            atomic_replace(target, current, patched)
            print("APPLY OK: S1 was extended to S2; GET CONFIGURATION DESCRIPTOR counter added.")
            print(f"Original backup: {folder}")
        elif current == legacy:
            print(f"CHECK: S1 is active for {vstr(version)}, but the S2 OS detection hook is missing.")
            print("Close Arduino IDE, then run --apply.")
        else:
            print(f"CHECK OK: S2 is installed for {vstr(version)}; usbd=16384 B and the OS hook is active.")
            print(f"Backup: {folder}")
        return target, version
    expected_original(current, version)
    if action == "restore":
        print(f"RESTORE OK: core {vstr(version)} already has its original 4096 B value. Nothing changed.")
        return target, version
    if action == "check":
        print(f"CHECK OK: original core {vstr(version)}; usbd=4096 B. Nothing changed.")
        print("Close Arduino IDE before running --apply.")
        return target, version
    patched = patch_bytes(current, version)
    folder = save_backup(target, storage, current, patched, version)
    atomic_replace(target, current, patched)
    print("APPLY OK: usbd stack 4096 -> 16384 B and OS detection hook; task priority unchanged.")
    print(f"Backup: {folder}")
    print("Compile the same sketch. The full log must include:")
    print(MARKER.decode("ascii"))
    print(HOOK_MARKER.decode("ascii"))
    print("Without both lines, the core rebuild is unconfirmed; do not interpret the S2 test.")
    print("Keep S2 active for this project. Do not erase the entire flash.")
    return target, version


def autodetect_core(local: str) -> Path:
    base = Path(local) / "Arduino15/packages/esp32/hardware/esp32"
    candidates = [base / vstr(PREFERRED) / "cores/esp32"]
    candidates += [base / vstr(v) / "cores/esp32" for v in sorted(SUPPORTED, reverse=True) if v != PREFERRED]
    found = [c for c in candidates if (c / "esp_arduino_version.h").is_file()]
    if not found:
        allowed = ", ".join(vstr(v) for v in sorted(SUPPORTED))
        raise Stop(f"Arduino-ESP32 {allowed} was not found in {base}.")
    if len(found) > 1:
        print(f"INFO: multiple supported cores found; selecting preferred {vstr(PREFERRED)}. "
              "Use --core-dir to select another installation explicitly.")
    return found[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--require", action="store_true", help="Check and require the 16384 B stack; read only")
    modes.add_argument("--check", action="store_true", help="Check without writing")
    modes.add_argument("--apply", action="store_true", help="Back up and install the S2 patch")
    modes.add_argument("--restore", action="store_true", help="Restore the local core file, not device firmware")
    parser.add_argument("--core-dir", type=Path,
                        help="Optional cores/esp32 directory in Arduino-ESP32 3.3.11 or 3.3.12")
    args = parser.parse_args(argv)
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        print("STOP: LOCALAPPDATA is missing. Run this script on the Windows Arduino host.", file=sys.stderr)
        return 1
    storage = Path(local) / "PicoFidoDiagnostics/usbd-stack-S1"
    action = "apply" if args.apply else "restore" if args.restore else "check"
    try:
        core = args.core_dir or autodetect_core(local)
        target, version = execute(action, core, storage)
        required_bytes = target.read_bytes()
        if args.require and (NEW_CALL not in required_bytes or HOOK_MARKER not in required_bytes):
            raise Stop(
                f"Firmware 0.4.0 requires S2 (usbd=16384 B + OS hook) in Arduino-ESP32 {vstr(version)}. "
                "Close the IDE and run --apply, then --require."
            )
        return 0
    except (Stop, OSError, ValueError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        print("Do not bypass checks or delete backups. Keep the full diagnostic message.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
