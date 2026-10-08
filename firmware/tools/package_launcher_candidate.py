#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collect verified private launcher binaries; never flash or publish."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "firmware"))
from flash_arduino import load_verified_build_info

GAMES = (("EvilBlocks", "evil.blocks"), ("EvilPinball", "evil.pinball"),
         ("EvilBreaker", "evil.breaker"), ("EvilInvaders", "evil.invaders"),
         ("EvilRacer", "evil.racer"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-name', default='apps-launcher-candidate')
    args = parser.parse_args()
    if not args.output_name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.output_name):
        raise SystemExit('Output name must be a lowercase directory slug')
    info = load_verified_build_info()
    if info.get('app_offset') != 0x10000:
        raise SystemExit('Historical 0.5.1 launcher packager cannot package the BLE layout. Use the verified BLE candidate manifest.')
    out = ROOT / 'release' / args.output_name
    if out.exists():
        raise SystemExit(f"Refusing to overwrite {out}")
    packages = []
    for repo, ident in GAMES:
        directory = ROOT.parent / repo / "package"
        meta = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        source = directory / f"{ident}.ekapp"
        if meta["package_revision"] != 5 or meta.get("ui_profile") != "corner-exit-v1" or meta["bundle_sha256"] != sha(source):
            raise ValueError(f"Package mismatch: {ident}")
        archive = ROOT / "release/apps" / f"{ident}_{meta['version']}_ABI4.zip"
        with zipfile.ZipFile(archive) as z:
            if set(z.namelist()) != {source.name, "manifest.json", "LICENSE.md", "SDK-MIT-LICENSE.txt"}:
                raise ValueError(f"Non-binary-only ZIP: {archive}")
            if z.read(source.name) != source.read_bytes():
                raise ValueError(f"ZIP package differs: {ident}")
        packages.append((source, archive, meta))
    out.mkdir(parents=True)
    files = []

    def copy(source, name):
        dest = out / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        if sha(dest) != sha(source):
            raise ValueError(f"Copy mismatch: {dest}")
        files.append({"file": name, "size": dest.stat().st_size, "sha256": sha(dest)})

    copy(Path(info["image_path"]), "EvilKey_apps_launcher_candidate.bin")
    for source, archive, meta in packages:
        copy(source, "sd/evilkey/apps/" + source.name)
        copy(archive, "apps/" + archive.name)
    manifest = {
        "schema": "evilkey-launcher-candidate-v1", "private": True,
        "firmware_version": "0.5.1-development-candidate", "runtime_abi": 4,
        "package_revision": 5, "ui_profile": "corner-exit-v1", "app_offset": "0x10000", "app_capacity": "0x1F0000",
        "system_touch_zone": {"x": 0, "y": 0, "width": 56, "height": 56},
        "system_visual_zone": {"x": 0, "y": 0, "width": 48, "height": 48},
        "exit_grip": {"x": 4, "y": 4, "width": 40, "height": 40},
        "exit_active_band": {"x": 0, "y": 0, "width": 280, "height": 160},
        "exit_completion_latched": True,
        "launcher_pagination": "cyclic-intro-and-grids",
        "partition_sha256": info["partition_sha256"],
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
        "device_acceptance": "pending", "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "SHA256SUMS.txt").write_text("".join(f"{r['sha256']}  {r['file']}\n" for r in files), encoding="ascii")
    (out / "README.md").write_text("""# Private Apps launcher candidate

Settings <- Apps <- Home -> Screensaver. Apps is skipped without valid apps.
From Home, swipe your finger right for Saver and left for Apps/Settings.
Apps opens on an animated introduction matching Settings. Swipe up for the
first 3x3 grid; swipe down from that grid to return to the introduction.
Pages form a cycle like Settings: swipe down from the introduction for the
last grid and up from the last grid for the introduction. Dots include the
introduction and each grid, with one highlighted marker.
This development firmware retains version 0.5.1; it is not a public release.
Package revision 5 requires corner-exit-v1 and these five updated apps.
Runtime ABI remains v4. Drag right from the top-left 56x56 system touch zone to
open the firmware-owned Yes/No exit dialog. The visible grip is 40x40 at (4,4);
the visual exclusion square is 48x48. App-origin drags remain app-owned.
After capture the active band expands to full width and the upper 160px.
At 100% completion latches through further travel; release opens Yes/No.
Multi-touch, contact replacement and stale input still cancel safely.

Firmware: write only the factory application at 0x10000 after verifying the
existing device partition table. Do not erase flash or write NVS, a key store,
bootloader or partition table. Use the repository's verified app-only flasher.

microSD: back up old app packages and saves; replace only the five .ekapp files
in /evilkey/apps/ if their hashes differ. Preserve every .save and all other files. App IDs and save
formats are unchanged. Apps are available in the ordinary FIDO USB role;
disable Manager Drive / USB Tool / Air Mouse before launching games.

Test navigation with old packages first, then all five updated apps, save/resume,
Yes/No exit and USB/FIDO with an existing credential. Record Diagnostics values
for mount/scan/icons and UI delay. Device acceptance is tracked separately.
No source code or application saves are included in this bundle.
""", encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
