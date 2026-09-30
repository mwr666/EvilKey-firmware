#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compile and exercise the private firmware's ABI v4 parser and Wasm host."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "firmware/EvilKeyV1/src/apps"
SDK = ROOT / "apps/sdk/include"
TOOLS = ROOT / "firmware/tools"
BUILD = ROOT / "firmware/build-arduino/apps-abi4-tests"


def run(*args: str) -> None:
    subprocess.run(args, check=True, cwd=ROOT)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", default=shutil.which("zig"))
    args = parser.parse_args()
    if not args.zig:
        parser.error("Zig 0.13.0 is required; pass --zig")
    if subprocess.check_output([args.zig, "version"], text=True).strip() != "0.13.0":
        parser.error("Zig 0.13.0 is required")
    if (SDK / "evilkey_app_abi.h").read_bytes() != (VM / "evilkey_app_abi.h").read_bytes():
        raise AssertionError("firmware and MIT SDK ABI declarations differ")
    BUILD.mkdir(parents=True, exist_ok=True)
    wasm = BUILD / "probe.wasm"
    bad = BUILD / "bad-command.wasm"
    for output, define in ((wasm, None), (bad, "-DEVILKEY_PROBE_BAD_COMMAND")):
        run(args.zig, "cc", "-target", "wasm32-freestanding", "-O2", "-nostdlib",
            "-Wl,--no-entry", "-Wl,-z,stack-size=32768",
            "-Wl,--export=app_input_ptr", "-Wl,--export=app_init",
            "-Wl,--export=app_step", "-Wl,--export=app_probe_input",
            "-Wl,--initial-memory=20000", "-Wl,--max-memory=20000",
            "-Wl,--strip-all", f"-I{SDK}", *([define] if define else []),
            "-o", str(output), str(TOOLS / "apps_abi4_guest.c"))
    sprite = BUILD / "sprite.rgb565"
    sprite.write_bytes(bytes([0x1f, 0x00, 0xe0, 0x07, 0x00, 0xf8, 0xff, 0xff]))
    assets = BUILD / "assets.json"
    assets.write_text(json.dumps({"assets": [{"id": 1, "file": sprite.name,
                                               "width": 2, "height": 2}]}),
                      encoding="utf-8")
    bundle = BUILD / "abi4.probe.ekapp"
    bundle.unlink(missing_ok=True)
    run(sys.executable, str(ROOT / "apps/sdk/pack_ekapp.py"),
        "--wasm", str(wasm), "--output", str(bundle), "--id", "abi4.probe",
        "--owner", "Michał Wojciechowski", "--license", "MIT",
        "--version", "0.0.1", "--assets", str(assets))
    data = bundle.read_bytes()
    if hashlib.sha256(data[192:]).digest() != data[58:90]:
        raise AssertionError("payload SHA-256 mismatch")
    host = BUILD / "apps_abi4_probe.exe"
    sources = sorted((VM / "wasm3").glob("*.c")) + [
        VM / "ek_vm.c", VM / "ek_assets.c", VM / "ek_package.c",
        TOOLS / "apps_abi4_probe.c",
    ]
    run(args.zig, "cc", "-O2", f"-I{VM / 'wasm3'}", "-o", str(host),
        *(str(s) for s in sources))
    run(str(host), str(bundle), str(bad))
    print(f"ABI v4 probe package: {bundle} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
