#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an ABI v4 .ekapp from Wasm and raw RGB565 sprites."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

HEADER = struct.Struct("<8sHHHHHHH32sI32s64s32sI2s64s32s32s")
HEADER_SIZE = HEADER.size
ICON_BYTES = 64 * 64 * 2
PAYLOAD_OFFSET = HEADER_SIZE + ICON_BYTES
PACKAGE_REVISION = 5
UI_PROFILE = "corner-exit-v1"
UI_PROFILE_BYTES = struct.pack("<H", 1) + bytes(30)
ENTRY = struct.Struct("<HHHHIII")
WASM_MAGIC = b"\0asm\x01\0\0\0"


def field(value: str, length: int, encoding: str) -> bytes:
    raw = value.encode(encoding)
    if not value.strip() or len(raw) >= length or any(b < 0x20 or b == 0x7f for b in raw) or \
            any(0x80 <= ord(c) <= 0x9f for c in value):
        raise ValueError("invalid package metadata field")
    return raw + bytes(length - len(raw))


def assets_blob(manifest_path: Path | None) -> bytes:
    if manifest_path is None:
        return b""
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))["assets"]
    if not isinstance(entries, list) or len(entries) > 32:
        raise ValueError("at most 32 assets are supported")
    if not entries:
        return b""
    table = bytearray(b"EKASSET1" + struct.pack("<HH", len(entries), 0))
    pixels = bytearray()
    previous = 0
    for item in entries:
        ident = item["id"]
        width, height = item["width"], item["height"]
        if not isinstance(ident, int) or not previous < ident <= 65535 or \
                not isinstance(width, int) or not 1 <= width <= 280 or \
                not isinstance(height, int) or not 1 <= height <= 456:
            raise ValueError("invalid asset ID or dimensions")
        previous = ident
        source = (manifest_path.parent / item["file"]).resolve()
        if not source.is_relative_to(manifest_path.parent.resolve()):
            raise ValueError("asset path leaves manifest directory")
        image = source.read_bytes()
        if len(image) != width * height * 2:
            raise ValueError(f"incorrect RGB565 length: {source.name}")
        flags = 1 if item.get("transparent_zero", False) else 0
        table += ENTRY.pack(ident, flags, width, height,
                            12 + len(entries) * ENTRY.size + len(pixels),
                            len(image), 0)
        pixels += image
    blob = bytes(table + pixels)
    if len(blob) > 1024 * 1024:
        raise ValueError("asset blob exceeds 1 MiB")
    return blob


def encode_package(program: bytes, blob: bytes, app_id: str, owner: str,
                   license_id: str, version: str, name: str, image: bytes,
                   ui_profile: str, abi: int = 4) -> bytes:
    if abi not in (4, 5):
        raise ValueError("only ABI 4 and 5 supported")
    if ui_profile != UI_PROFILE:
        raise ValueError("explicit ui_profile='corner-exit-v1' is required; reserve 56x56 touch and 48x48 visual zones")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,30}", app_id) or \
            app_id.endswith(".") or ".." in app_id:
        raise ValueError("invalid app ID")
    parts = version.split(".")
    if len(parts) != 3 or any(not p.isascii() or not p.isdigit() or
                              int(p) > 65535 for p in parts):
        raise ValueError("version must be major.minor.patch in u16 range")
    if not 8 <= len(program) <= 65536 or not program.startswith(WASM_MAGIC):
        raise ValueError("invalid or oversized WebAssembly module")
    if len(blob) > 1024 * 1024:
        raise ValueError("asset blob exceeds 1 MiB")
    if len(image) != ICON_BYTES:
        raise ValueError("icon must be a 64x64 little-endian RGB565 image (8192 bytes)")
    payload = program + blob
    header = HEADER.pack(b"EKEYAPP1", HEADER_SIZE, PACKAGE_REVISION, abi, 0, *map(int, parts),
                         field(app_id, 32, "ascii"), len(program),
                         hashlib.sha256(payload).digest(),
                         field(owner, 64, "utf-8"),
                         field(license_id, 32, "ascii"), len(blob), bytes(2),
                         field(name, 64, "utf-8"), hashlib.sha256(image).digest(), UI_PROFILE_BYTES)
    return header + image + payload


def pack(wasm: Path, output: Path, app_id: str, owner: str,
         license_id: str, version: str, assets: Path | None,
         name: str, icon: Path, ui_profile: str, abi: int = 4) -> Path:
    if output.name != f"{app_id}.ekapp":
        raise ValueError("output filename must match app ID")
    package = encode_package(wasm.read_bytes(), assets_blob(assets), app_id, owner,
                             license_id, version, name, icon.read_bytes(), ui_profile, abi)
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(package)
    if output.read_bytes() != package:
        raise IOError("package readback mismatch")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wasm", "output", "id", "owner", "license", "version", "name", "icon", "ui-profile"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--abi", type=int, choices=[4,5], default=4)
    args = parser.parse_args()
    print(pack(Path(args.wasm), Path(args.output), args.id, args.owner,
               args.license, args.version, args.assets, args.name, Path(args.icon), args.ui_profile, args.abi))


if __name__ == "__main__":
    main()
