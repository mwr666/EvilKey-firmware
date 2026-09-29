#!/usr/bin/env python3
"""Sync the four Apps-edited port templates into the committed Arduino engine.

Refuses unrecognized generated edits. The full engine generator remains the
canonical regeneration path; this narrow sync avoids replacing its upstream
cache or unrelated generated source during Apps development.
"""
from __future__ import annotations
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates" / "port"
ENGINE = ROOT / "EvilKeyV1" / "src" / "engine" / "board"
MANIFEST = ROOT / "EvilKeyV1" / "GENERATED_MANIFEST.json"
FILES = ("ws_board.c", "ws_lvgl.c", "ws_ui.c", "ws_ui.h")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generated(name: str) -> bytes:
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    if name.endswith(".c"):
        source = '#include "../../pf_build_config.h"\n' + source
    if name == "ws_board.c":
        source = source.replace('#include "pf_engine_api.h"',
                                '#include "../../pf_engine_api.h"')
        source = source.replace('#include "led/led.h"',
                                '#include "../sdk/src/led/led.h"')
    if name == "ws_lvgl.c":
        source = source.replace('#include "pf_firmware_version.h"',
                                '#include "../../pf_firmware_version.h"')
    return source.encode("utf-8")


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    updates = []
    for name in FILES:
        path = ENGINE / name
        key = f"board/{name}"
        current = path.read_bytes()
        wanted = generated(name)
        clean = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--",
             f"firmware/EvilKeyV1/src/engine/{key}"],
            cwd=ROOT.parent, check=False,
        ).returncode == 0
        if digest(current) not in (manifest["generated_sha256"][key],
                                   digest(wanted)) and not clean:
            raise SystemExit(f"Refusing modified generated source: {path}")
        updates.append((path, key, wanted))
    for path, key, wanted in updates:
        path.write_bytes(wanted)
        manifest["generated_sha256"][key] = digest(wanted)
        print(f"Synced {key}")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
