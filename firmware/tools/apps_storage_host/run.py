#!/usr/bin/env python3
"""Run production ek_storage.cpp against a fault-injectable host File mock."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", default=shutil.which("zig"))
    args = parser.parse_args()
    if not args.zig:
        parser.error("pass --zig with Zig 0.13.0")
    root = Path(__file__).resolve().parents[3]
    here = Path(__file__).resolve().parent
    apps = root / "firmware/EvilKeyV1/src/apps"
    with tempfile.TemporaryDirectory(prefix="evilkey-save-test-") as directory:
        exe = Path(directory) / "save_test.exe"
        command = [args.zig, "c++", "-std=c++17", "-O2", f"-I{here}",
                   "-x", "c++", str(here / "save_test.cpp"),
                   str(apps / "ek_storage.cpp"), str(apps / "ek_package.c"),
                   str(apps / "ek_assets.c"), "-o", str(exe)]
        build = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if build.returncode:
            print(build.stdout, end="")
            print(build.stderr, end="")
            raise SystemExit(build.returncode)
        subprocess.run([exe], cwd=root, check=True)


if __name__ == "__main__":
    main()
