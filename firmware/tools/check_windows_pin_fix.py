#!/usr/bin/env python3
"""Validate the Windows ClientPIN probe patch definition and, if present, generated engine sources."""
from __future__ import annotations

from pathlib import Path
import importlib.util
import re
import sys

MARKER="PF_WINDOWS_PIN_PROBE_FIX_R1"
ROOT=Path(__file__).resolve().parents[1]
PROJECT=ROOT.parent
TOUCH=ROOT/"tools"/"touch_patch.py"


def die(msg: str) -> None:
    print("FAIL:", msg, file=sys.stderr)
    raise SystemExit(1)


def check_patch_definition() -> None:
    if not TOUCH.is_file(): die(f"missing {TOUCH}")
    text=TOUCH.read_text(encoding="utf-8")
    if MARKER not in text: die(f"{MARKER} not found in touch_patch.py")
    for required in [
        "s=windows_pin_probe_fix(s)",
        "CTAP2_ERR_PIN_INVALID",
        "3 + !alwaysUv",
        'FIDO_2_2',
    ]:
        if required not in text: die(f"patch definition missing anchor: {required}")

    spec=importlib.util.spec_from_file_location("touch_patch_check", TOUCH)
    if not spec or not spec.loader: die("cannot import touch_patch.py")
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    probe='''    if (!file_has_data(ef_pin)) {\n        CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);\n    }\n    else {\n        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);\n    }'''
    out=mod.windows_pin_probe_fix(probe)
    if "CTAP2_ERR_PIN_INVALID" not in out or "CTAP2_ERR_PIN_AUTH_INVALID" in out:
        die("windows_pin_probe_fix() self-test failed")
    print("PASS: touch_patch.py contains the Windows PIN probe + CTAP version fixes")


def zero_probe_status(path: Path) -> None:
    text=path.read_text(encoding="utf-8")
    pattern=re.compile(
        r'if \(!file_has_data\(ef_pin\)\) \{\s*'
        r'CBOR_ERROR\(CTAP2_ERR_PIN_NOT_SET\);\s*\}\s*else \{\s*'
        r'CBOR_ERROR\((CTAP2_ERR_PIN_[A-Z_]+)\);\s*\}', re.S)
    matches=pattern.findall(text)
    if not matches: die(f"cannot locate empty-pin probe in {path}")
    if "CTAP2_ERR_PIN_INVALID" not in matches:
        die(f"generated {path.name} does not contain PIN_INVALID probe; found {matches}")
    print(f"PASS: generated {path.name} uses CTAP2_ERR_PIN_INVALID for configured-PIN probe")


def check_engine_if_present() -> None:
    engine=ROOT/"EvilKeyV1"/"src"/"engine"/"fido"/"src"/"fido"
    if not engine.exists():
        print("INFO: generated engine not present; source-patch validation only")
        return
    make=engine/"cbor_make_credential.c"
    assertion=engine/"cbor_get_assertion.c"
    info=engine/"cbor_get_info.c"
    for p in (make,assertion,info):
        if not p.is_file(): die(f"generated file missing: {p}")
    zero_probe_status(make)
    zero_probe_status(assertion)
    ti=info.read_text(encoding="utf-8")
    if '"FIDO_2_2"' in ti: die("generated GetInfo still advertises invalid FIDO_2_2")
    if '"FIDO_2_3"' not in ti: die("generated GetInfo does not advertise FIDO_2_3")
    print("PASS: generated GetInfo no longer advertises FIDO_2_2")


def main() -> int:
    check_patch_definition()
    check_engine_if_present()
    print("PASS: Windows PIN compatibility fix validation complete")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
