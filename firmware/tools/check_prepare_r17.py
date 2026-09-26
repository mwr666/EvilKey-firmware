#!/usr/bin/env python3
"""R17 guard: generated Arduino sources must never include local .inc files."""
from pathlib import Path
import importlib.util
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FW = ROOT / "firmware"
PORT = FW / "templates" / "port"


def fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")


def main() -> None:
    header = PORT / "local_uv_binding.h"
    old = PORT / "local_uv_binding.inc"
    local = FW / "templates" / "local_uv_engine.inc"
    if not header.is_file():
        fail("local_uv_binding.h missing")
    if old.exists():
        fail("obsolete local_uv_binding.inc still present")
    text = local.read_text(encoding="utf-8")
    if '#include "local_uv_binding.h"' not in text:
        fail("local_uv_engine.inc does not include the Arduino-stageable .h binding")
    if '#include "local_uv_binding.inc"' in text:
        fail("local_uv_engine.inc still includes unsupported .inc")

    spec = importlib.util.spec_from_file_location("prepare_arduino_r17", FW / "prepare_arduino.py")
    assert spec and spec.loader
    prep = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prep)

    # Reproduce the exact path relationship that failed on Windows in R16:
    # engine/fido/src/fido/cbor_client_pin.c -> engine/board/local_uv_binding.h.
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        origin = base / "upstream/fido/src/fido/cbor_client_pin.c"
        output = base / "sketch/src/engine/fido/src/fido/cbor_client_pin.c"
        target = base / "sketch/src/engine/board/local_uv_binding.h"
        origin.parent.mkdir(parents=True)
        output.parent.mkdir(parents=True)
        target.parent.mkdir(parents=True)
        origin.write_text("/* fixture */\n", encoding="utf-8")
        target.write_text("#pragma once\n", encoding="utf-8")
        rewritten = prep.rewrite_includes(
            '#include "local_uv_binding.h"\n', origin, output,
            {header.resolve(): target.resolve()}, [PORT],
            base / "config.h", base / "pf_engine_api.h")
        expected = '#include "../../../board/local_uv_binding.h"\n'
        if rewritten != expected:
            fail(f"unexpected rewritten include: {rewritten!r}")
        output.write_text(rewritten, encoding="utf-8")
        prep.validate_local_includes(base / "sketch/src/engine")

    print("PASS: R17 uses Arduino-stageable local_uv_binding.h")
    print("PASS: generated cbor_client_pin.c rewrites to ../../../board/local_uv_binding.h")
    print("PASS: generated local include validation accepts the R17 layout")


if __name__ == "__main__":
    main()
