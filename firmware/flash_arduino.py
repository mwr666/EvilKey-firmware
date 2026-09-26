#!/usr/bin/env python3
"""Interactively build and upload EvilKey to a user-selected Windows COM port."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
BUILD_PATH = ROOT / "build-arduino"
BUILD_INFO = BUILD_PATH / "evilkey-build.json"
BUILD_SCRIPT = ROOT / "build_arduino.py"
COM_PORT = re.compile(r"^COM([1-9][0-9]*)$", re.IGNORECASE)


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


def load_verified_build_info() -> dict[str, object]:
    if not BUILD_INFO.is_file():
        raise RuntimeError("No manifest for a fresh firmware build.")
    info = json.loads(BUILD_INFO.read_text(encoding="utf-8"))
    if info.get("schema") != "evilkey-arduino-build-v1":
        raise RuntimeError("Unknown build manifest format.")
    build_path = Path(str(info.get("build_path", ""))).resolve()
    sketch_path = Path(str(info.get("sketch_path", ""))).resolve()
    image_path = Path(str(info.get("image_path", ""))).resolve()
    if build_path != BUILD_PATH.resolve() or sketch_path != (ROOT / "EvilKeyV1").resolve():
        raise RuntimeError("The manifest points to an unexpected project or build directory.")
    if info.get("erase_flash") != "none" or "EraseFlash=none" not in str(info.get("fqbn", "")):
        raise RuntimeError("NVS preservation is not guaranteed: EraseFlash=none is required.")
    if not image_path.is_file() or image_path.parent != BUILD_PATH.resolve():
        raise RuntimeError("The application image listed in the manifest is missing.")
    digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
    if digest != info.get("image_sha256") or image_path.stat().st_size != info.get("image_size"):
        raise RuntimeError("The firmware image does not match the build manifest.")
    return info


def upload_command(cli: str, port: dict[str, str], info: dict[str, object]) -> list[str]:
    return [
        cli,
        "upload",
        "--fqbn",
        str(info["fqbn"]),
        "--port",
        port["address"],
        "--protocol",
        port["protocol"],
        "--build-path",
        str(BUILD_PATH.resolve()),
        str((ROOT / "EvilKeyV1").resolve()),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list-only", action="store_true",
        help="Only display detected COM ports; never build or upload.",
    )
    args = parser.parse_args()
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
    print(f"\nSelected {selected['address']}. Uploading will restart the device.")
    print("NVS will not be erased (EraseFlash=none profile).")
    if not confirm_upload(input(f"Build and flash firmware to {selected['address']}? (Y/N): ")):
        print("Cancelled. No build or upload was performed.")
        return 0

    print("\n[1/2] Building fresh firmware...")
    build = subprocess.run([sys.executable, str(BUILD_SCRIPT)])
    if build.returncode:
        print("ERROR: build failed. Upload was not started.", file=sys.stderr)
        return build.returncode
    try:
        info = load_verified_build_info()
        current_ports = discover_ports(cli)
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"ERROR: pre-upload check failed: {exc}", file=sys.stderr)
        return 2
    current = next((port for port in current_ports if port["address"] == selected["address"]), None)
    if current is None:
        print(f"ERROR: port {selected['address']} disappeared after the build. Upload cancelled.", file=sys.stderr)
        return 2

    print(f"\n[2/2] Uploading to {current['address']}...")
    try:
        subprocess.run(upload_command(cli, current, info), check=True)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: Arduino CLI upload exited with code {exc.returncode}.", file=sys.stderr)
        return exc.returncode
    print(f"\nREADY: firmware was uploaded through {current['address']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
