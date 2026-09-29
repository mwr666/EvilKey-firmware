#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the public Apps ABI with synthetic guests; no app package needed."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "EvilKeyV1" / "src" / "apps"
TOOLS = ROOT / "tools"
BUILD = ROOT / "build-arduino" / "apps-tests"
HEADER = struct.Struct("<8sHHHHHHH32sI32s64s32s6s")


def run(*arguments: str | Path) -> None:
    command = [str(argument) for argument in arguments]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def guest(zig: Path, name: str, *defines: str, memory: str = "20000") -> Path:
    output = BUILD / f"{name}.wasm"
    run(zig, "cc", "-target", "wasm32-freestanding", "-O2", "-nostdlib",
        "-Wl,--no-entry", "-Wl,-z,stack-size=32768",
        f"-Wl,--initial-memory={memory}", f"-Wl,--max-memory={memory}",
        "-Wl,--strip-all", *defines, "-o", output,
        TOOLS / "apps_vm_probe_guests.c")
    return output


def sample_bundle(program: Path) -> Path:
    data = program.read_bytes()
    if HEADER.size != 192 or not data.startswith(b"\0asm\x01\0\0\0"):
        raise ValueError("unexpected synthetic guest")

    def field(value: str, size: int) -> bytes:
        encoded = value.encode("utf-8")
        if len(encoded) >= size:
            raise ValueError("sample metadata too long")
        return encoded.ljust(size, b"\0")

    header = HEADER.pack(
        b"EKEYAPP1", 192, 2, 3, 0, 1, 0, 0,
        field("demo.app", 32), len(data), hashlib.sha256(data).digest(),
        field("Example Author", 64), field("MIT", 32), bytes(6),
    )
    path = BUILD / "demo.app.ekapp"
    path.write_bytes(header + data)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", type=Path, required=True,
                        help="path to Zig 0.13.0")
    args = parser.parse_args()
    version = subprocess.check_output([str(args.zig), "version"], text=True).strip()
    if version != "0.13.0":
        parser.error(f"Zig 0.13.0 required; found {version}")
    BUILD.mkdir(parents=True, exist_ok=True)

    guests = [
        guest(args.zig, "valid", "-DEVILKEY_PROBE_VALID"),
        guest(args.zig, "loop"),
        guest(args.zig, "forbidden", "-DEVILKEY_PROBE_FORBIDDEN"),
        guest(args.zig, "overmemory", memory="400000"),
        guest(args.zig, "pixel_bomb", "-DEVILKEY_PROBE_PIXEL_BOMB"),
        guest(args.zig, "recursion", "-DEVILKEY_PROBE_RECURSION"),
        guest(args.zig, "legacy_abi", "-DEVILKEY_PROBE_LEGACY_ABI"),
        guest(args.zig, "bad_pointer", "-DEVILKEY_PROBE_BAD_POINTER"),
        guest(args.zig, "bad_command", "-DEVILKEY_PROBE_BAD_COMMAND"),
    ]
    sources = sorted((VM / "wasm3").glob("*.c")) + [
        VM / "ek_vm.c", TOOLS / "apps_vm_probe.c",
    ]
    for profile, defines in (
        ("host", ()),
        ("arduino_esp32", ("-DARDUINO", "-DARDUINO_ARCH_ESP32")),
    ):
        executable = BUILD / f"apps_vm_probe_{profile}.exe"
        run(args.zig, "cc", "-O2", *defines,
            f"-I{VM / 'wasm3'}", "-o", executable, *sources)
        run(executable, *guests)

    package_probe = BUILD / "apps_package_probe.exe"
    run(args.zig, "cc", "-O2", "-o", package_probe,
        VM / "ek_package.c", TOOLS / "apps_package_probe.c")
    run(package_probe, sample_bundle(guests[0]))

    exit_probe = BUILD / "apps_exit_probe.exe"
    run(args.zig, "cc", "-O2", "-o", exit_probe,
        VM / "ek_exit_dialog.c", TOOLS / "apps_exit_probe.c")
    run(exit_probe)
    print("Apps ABI v3: synthetic VM, package, and exit-dialog probes passed")


if __name__ == "__main__":
    main()
