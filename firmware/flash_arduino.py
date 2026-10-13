#!/usr/bin/env python3
"""Build and install EvilKey with verified, storage-preserving layout migration."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from tools.flash_safety import validate_write, validate_command
from tools.check_ble_storage import verify as verify_ble_storage, source_digest
from tools.flash_safety import PROTECTED, parse_table
from tools.install_preserving_storage import install as install_preserving_storage
from board_profiles import REVISIONS, build_path, prompt_revision, verify_board_identity
from tools.initialize_new_device import initialize as initialize_new_device, confirm_initialization

ROOT = Path(__file__).resolve().parent
BUILD_SCRIPT = ROOT / "build_arduino.py"
COM_PORT = re.compile(r"^COM([1-9][0-9]*)$", re.IGNORECASE)
APP_OFFSET = 0x500000
APP_CAPACITY = 0x400000
PARTITION_OFFSET = 0x8000


def verify_partition_layout() -> None:
    """Require the reviewed factory layout before writing any flash sector."""
    table = ROOT / "EvilKeyV1" / "partitions.csv"
    entries: dict[str, tuple[int, int]] = {}
    with table.open(encoding="utf-8", newline="") as source:
        for row in csv.reader(line for line in source if not line.lstrip().startswith("#")):
            if len(row) < 5 or not row[0].strip():
                continue
            entries[row[0].strip()] = (int(row[3].strip(), 0), int(row[4].strip(), 0))
    if entries.get("factory") != (APP_OFFSET, APP_CAPACITY):
        raise RuntimeError("Factory partition offset or size changed; app-only upload cancelled.")
    if set(entries)!=set(PROTECTED)|{'factory'} or any(entries.get(name)!=span for name,span in PROTECTED.items()):
        raise RuntimeError('Protected partition offsets/size changed; upload cancelled.')
    app_end = APP_OFFSET + APP_CAPACITY
    for name, (offset, size) in entries.items():
        if name != "factory" and offset < app_end and offset + size > APP_OFFSET:
            raise RuntimeError(f"Partition {name} overlaps the app image; upload cancelled.")


def resolve_esptool(cli: str, fqbn: str) -> Path:
    """Use the esptool installed for this exact Arduino board profile."""
    result = subprocess.run(
        [cli, "compile", "--fqbn", fqbn, "--show-properties", str(ROOT / "EvilKeyV1")],
        check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines()
                      if "=" in line)
    tool_root = properties.get("runtime.tools.esptool_py.path")
    if not tool_root:
        raise RuntimeError("Arduino did not identify its esptool installation.")
    executable = Path(tool_root) / "esptool.exe"
    if not executable.is_file():
        raise RuntimeError(f"Arduino esptool is missing: {executable}")
    return executable


def port_sort_key(port: dict[str, str]) -> tuple[int, str]:
    match = COM_PORT.fullmatch(port["address"])
    return (int(match.group(1)) if match else 1_000_000, port["address"].upper())


def parse_windows_com_ports(payload: object) -> list[dict[str, str]]:
    """Extract unique COM ports from Arduino CLI 1.x board-list JSON."""
    rows = payload.get("detected_ports", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return []
    ports: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        port = row.get("port", row)
        if not isinstance(port, dict):
            continue
        address = str(port.get("address", "")).strip().upper()
        if not COM_PORT.fullmatch(address):
            continue
        protocol = str(port.get("protocol", "serial")).strip() or "serial"
        label = str(port.get("label", address)).strip() or address
        boards = row.get("matching_boards", [])
        board_names = []
        if isinstance(boards, list):
            for board in boards:
                if isinstance(board, dict) and board.get("name"):
                    board_names.append(str(board["name"]))
        ports[address] = {
            "address": address,
            "label": label,
            "protocol": protocol,
            "boards": ", ".join(board_names),
        }
    return sorted(ports.values(), key=port_sort_key)


def discover_ports(cli: str) -> list[dict[str, str]]:
    result = subprocess.run(
        [cli, "board", "list", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return parse_windows_com_ports(json.loads(result.stdout))


def show_ports(ports: list[dict[str, str]]) -> None:
    print("\nAvailable COM ports:")
    for index, port in enumerate(ports, 1):
        detail = port["boards"] or port["label"] or "unidentified device"
        print(f"  {index}. {port['address']:<7} {detail}")


def choose_port(ports: list[dict[str, str]], answer: str) -> dict[str, str] | None:
    value = answer.strip().upper()
    if value.isdigit():
        index = int(value)
        return ports[index - 1] if 1 <= index <= len(ports) else None
    return next((port for port in ports if port["address"] == value), None)


def confirm_upload(answer: str) -> bool:
    """Only an explicit Y authorizes the selected-port build and upload."""
    return answer.strip().upper() == "Y"


def load_verified_build_info(revision: str = "v1") -> dict[str, object]:
    expected_build = build_path(ROOT, revision).resolve()
    manifest_path = expected_build / "evilkey-build.json"
    if not manifest_path.is_file():
        raise RuntimeError("No manifest for a fresh firmware build.")
    info = json.loads(manifest_path.read_text(encoding="utf-8"))
    if info.get("schema") != "evilkey-arduino-build-v1":
        raise RuntimeError("Unknown build manifest format.")
    verify_board_identity(info, revision)
    manifest_build_path = Path(str(info.get("build_path", ""))).resolve()
    sketch_path = Path(str(info.get("sketch_path", ""))).resolve()
    image_path = Path(str(info.get("image_path", ""))).resolve()
    if manifest_build_path != expected_build or sketch_path != (ROOT / "EvilKeyV1").resolve():
        raise RuntimeError("The manifest points to an unexpected project or build directory.")
    if info.get("erase_flash") != "none" or "EraseFlash=none" not in str(info.get("fqbn", "")):
        raise RuntimeError("NVS preservation is not guaranteed: EraseFlash=none is required.")
    verify_partition_layout()
    verify_ble_storage()
    elf=expected_build/'EvilKeyV1.ino.elf'
    if info.get('nvs_guard')!='link-wrap-v1' or info.get('build_inputs_sha256')!=source_digest() or \
            not elf.is_file() or hashlib.sha256(elf.read_bytes()).hexdigest()!=info.get('elf_sha256'):
        raise RuntimeError('NVS guard/source/ELF verification is missing or stale; upload cancelled.')
    if info.get('app_offset')!=APP_OFFSET or info.get('app_capacity')!=APP_CAPACITY:
        raise RuntimeError('Manifest does not use the reviewed application layout')
    if not image_path.is_file() or image_path != expected_build / 'EvilKeyV1.ino.bin':
        raise RuntimeError("The application image listed in the manifest is missing.")
    digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
    if digest != info.get("image_sha256") or image_path.stat().st_size != info.get("image_size"):
        raise RuntimeError("The firmware image does not match the build manifest.")
    if image_path.stat().st_size > APP_CAPACITY:
        raise RuntimeError("The image exceeds the factory partition; upload cancelled.")
    partition_path = Path(str(info.get("partition_path", ""))).resolve()
    if partition_path != expected_build / 'EvilKeyV1.ino.partitions.bin' or not partition_path.is_file():
        raise RuntimeError("The built partition image is missing.")
    if partition_path.stat().st_size != info.get("partition_size") or \
            partition_path.stat().st_size != 0xC00 or \
            hashlib.sha256(partition_path.read_bytes()).hexdigest() != info.get("partition_sha256"):
        raise RuntimeError("The built partition image does not match the manifest.")
    if parse_table(partition_path.read_bytes())!=(APP_OFFSET,APP_CAPACITY):
        raise RuntimeError('Built partition table is not the reviewed layout')
    return info


def verify_device_partition(esptool: Path, port: dict[str, str],
                            info: dict[str, object]) -> bytes:
    """Read and validate the device layout; leave it in ROM for storage hashing."""
    with tempfile.TemporaryDirectory(prefix="evilkey-partition-check-") as directory:
        observed = Path(directory) / "partition.bin"
        subprocess.run([
            str(esptool), "--chip", "esp32s3", "--port", port["address"],
            "--baud", "115200", "--before", "default-reset", "--after", "no-reset",
            "read-flash", hex(PARTITION_OFFSET), str(info["partition_size"]),
            str(observed),
        ], check=True)
        data=observed.read_bytes()
        if len(data)!=0xC00:
            raise RuntimeError('Incomplete device partition readback')
        return data


def needs_initialization(observed):
    try:
        parse_table(observed)
        return False
    except (RuntimeError, UnicodeError):
        return True


def prompt_initialization(port, revision):
    print('\nNo supported EvilKey partition table was detected.')
    print(f'Fresh initialization of PCB {revision.upper()} on {port["address"]} will ERASE ALL 16 MiB of flash,')
    print('including NVS credentials/settings and all other internal data, then install the EvilKey partition table.')
    print('The microSD card is not erased. If you need existing internal data, cancel now.')
    try:
        answer=input('Type ERASE to initialize this new module, or press Enter to cancel: ')
    except (EOFError, KeyboardInterrupt):
        return None
    return answer if confirm_initialization(answer) else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--board-revision', choices=REVISIONS,
                        help='Explicit PCB revision; otherwise prompt before selecting COM')
    parser.add_argument(
        "--list-only", action="store_true",
        help="Only display detected COM ports; never build or upload.",
    )
    parser.add_argument(
        "--use-verified-build", action="store_true",
        help="Use an existing image only if its source, ELF, BIN and partition manifest checks pass; fail closed if stale.",
    )
    args = parser.parse_args()
    revision = args.board_revision
    if not args.list_only and revision is None:
        revision = prompt_revision()
        if revision is None:
            print('Cancelled. No build or upload was performed.')
            return 0
    cli = shutil.which("arduino-cli")
    if not cli:
        print("ERROR: arduino-cli is not in PATH.", file=sys.stderr)
        return 2
    try:
        ports = discover_ports(cli)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read ports from Arduino CLI: {exc}", file=sys.stderr)
        return 2
    if not ports:
        print("No COM port detected. Connect EvilKey through its native USB port.")
        return 2
    show_ports(ports)
    if args.list_only:
        print("\n--list-only mode: no build or upload was performed.")
        return 0

    selected = choose_port(ports, input("\nEnter the list number or COM port name: "))
    if selected is None:
        print("Cancelled: the selected port is not in the list above.")
        return 2
    print(f"\nSelected PCB {revision.upper()} on {selected['address']}. Uploading will restart the device.")
    print("Application at 0x500000; a reviewed older layout also requires the 0x8000 table sector.")
    print("Normal EvilKey updates preserve internal data; fresh initialization requires a separate erase confirmation.")
    if not confirm_upload(input(f"Build and flash PCB {revision.upper()} to {selected['address']}? (Y/N): ")):
        print("Cancelled. No build or upload was performed.")
        return 0

    if args.use_verified_build:
        print("\n[1/2] Verifying the existing compiled image against current sources...")
    else:
        print("\n[1/2] Building fresh firmware...")
        build = subprocess.run([sys.executable, str(BUILD_SCRIPT), '--board-revision', revision])
        if build.returncode:
            print("ERROR: build failed. Upload was not started.", file=sys.stderr)
            return build.returncode
    try:
        info = load_verified_build_info(revision)
        esptool = resolve_esptool(cli, str(info["fqbn"]))
        current_ports = discover_ports(cli)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError,
            json.JSONDecodeError) as exc:
        print(f"ERROR: pre-upload check failed: {exc}", file=sys.stderr)
        return 2
    current = next((port for port in current_ports if port["address"] == selected["address"]), None)
    if current is None:
        print(f"ERROR: port {selected['address']} disappeared after the build. Upload cancelled.", file=sys.stderr)
        return 2

    print("\nChecking the partition table already stored on the device...")
    try:
        observed=verify_device_partition(esptool, current, info)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: device partition check failed: {exc}", file=sys.stderr)
        return 2
    try:
        if needs_initialization(observed):
            confirmation=prompt_initialization(current,revision)
            if confirmation is None:
                print('Cancelled. No flash erase or write was performed; device remains in download mode.')
                return 0
            initialize_new_device(esptool,current,info,observed,ROOT/'.flash-backups',confirmation=confirmation)
        else:
            print(f"\n[2/2] Installing and verifying protected storage on {current['address']}...")
            install_preserving_storage(esptool,current,info,observed,ROOT/'.flash-backups')
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: verified esptool installation exited with code {exc.returncode}.", file=sys.stderr)
        return exc.returncode
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: installation verification failed: {exc}. Do not boot this candidate.", file=sys.stderr)
        return 2
    print(f"\nREADY: firmware was uploaded through {current['address']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
