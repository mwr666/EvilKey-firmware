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

HEADER = struct.Struct("<8sHHHHHHH32sI32s64s32sI2s")
ENTRY = struct.Struct("<HHHHIII")
WASM_MAGIC = b"\0asm\x01\0\0\0"


def field(value: str, length: int, encoding: str) -> bytes:
    raw = value.encode(encoding)
    if not raw or len(raw) >= length or any(b < 0x20 or b == 0x7f for b in raw):
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


def pack(wasm: Path, output: Path, app_id: str, owner: str,
         license_id: str, version: str, assets: Path | None) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,30}", app_id) or \
            app_id.endswith(".") or ".." in app_id:
        raise ValueError("invalid app ID")
    if output.name != f"{app_id}.ekapp":
        raise ValueError("output filename must match app ID")
    parts = version.split(".")
    if len(parts) != 3 or any(not p.isascii() or not p.isdigit() or
                              int(p) > 65535 for p in parts):
        raise ValueError("version must be major.minor.patch in u16 range")
    program = wasm.read_bytes()
    if not 8 <= len(program) <= 65536 or not program.startswith(WASM_MAGIC):
        raise ValueError("invalid or oversized WebAssembly module")
    blob = assets_blob(assets)
    payload = program + blob
    header = HEADER.pack(b"EKEYAPP1", 192, 3, 4, 0, *map(int, parts),
                         field(app_id, 32, "ascii"), len(program),
                         hashlib.sha256(payload).digest(),
                         field(owner, 64, "utf-8"),
                         field(license_id, 32, "ascii"), len(blob), bytes(2))
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(header + payload)
    if output.read_bytes() != header + payload:
        raise IOError("package readback mismatch")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wasm", "output", "id", "owner", "license", "version"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--assets", type=Path)
    args = parser.parse_args()
    print(pack(Path(args.wasm), Path(args.output), args.id, args.owner,
               args.license, args.version, args.assets))


if __name__ == "__main__":
    main()
