#!/usr/bin/env python3
"""R33 source guard: writable/readable $_OS plus executable regression coverage."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FW = ROOT / "firmware"


def need(path: Path, *tokens: str) -> str:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        if token not in text:
            raise SystemExit(f"FAIL {path}: missing {token!r}")
    return text


patch = need(
    FW / "tools" / "ducky3_hid_patch.py",
    "uint16_t os;",
    'equal_case(name, "$_OS")',
    "runtime->os = (uint16_t)value;",
    "return runtime->os;",
    ".os = 0U,",
    'if (equal_case(name, "WINDOWS")) return 1;',
    'if (equal_case(name, "LINUX")) return 2;',
)
if patch.count('equal_case(name, "$_OS")') < 2:
    raise SystemExit("FAIL: $_OS must be present in both read and write paths")

need(
    FW / "tests" / "release_026" / "test_ducky_os_r33.c",
    "$_OS = WINDOWS",
    "IF ($_OS == WINDOWS) THEN",
    "DEFINE #NOT_WINDOWS 7",
    "$_OS = #NOT_WINDOWS",
    "PASS: $_OS read/write and symbolic OS constants",
)
need(
    FW / "tools" / "run_ducky_runtime_tests.py",
    "patch.patch_ducky_c",
    "test_ducky_os_r33.c",
    "patched pinned DuckyScript runtime host regression",
)

print("PASS: R33 patches both $_OS assignment and expression-read paths")
print("PASS: R33 ships an executable pinned-runtime regression for WINDOWS and #NOT_WINDOWS")
