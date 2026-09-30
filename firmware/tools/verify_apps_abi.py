#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run generic ABI v4 and shared exit-dialog host probes."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "firmware/tools"
VM = ROOT / "firmware/EvilKeyV1/src/apps"
BUILD = ROOT / "firmware/build-arduino/apps-abi4-tests"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", type=Path, required=True, help="path to Zig 0.13.0")
    args = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT / "apps/verify_abi_v4.py"),
                    "--zig", str(args.zig)], check=True)
    exit_probe = BUILD / "apps_exit_probe.exe"
    subprocess.run([str(args.zig), "cc", "-O2", "-o", str(exit_probe),
                    str(VM / "ek_exit_dialog.c"), str(TOOLS / "apps_exit_probe.c")],
                   check=True)
    subprocess.run([str(exit_probe)], check=True)
    print("Apps ABI v4 and shared exit-dialog probes passed")


if __name__ == "__main__":
    main()
