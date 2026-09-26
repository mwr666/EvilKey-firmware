#!/usr/bin/env python3
"""Static, ordering and host-parse guard for the KeyHunter bootstrap."""

from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = (
    ROOT
    / "microSD_EVILKEY_EXAMPLES"
    / "duckyscripts"
    / "library"
    / "logger"
    / "KeyHunter"
    / "Install"
    / "payload.txt"
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


source = PAYLOAD.read_text(encoding="utf-8")
for forbidden in ("Win32_LogicalDisk", "Get-WmiObject", "gwmi "):
    if forbidden.lower() in source.lower():
        fail(f"blocking WMI bootstrap remains: {forbidden}")

required = (
    "[IO.DriveInfo]::GetDrives()",
    "? IsReady|? VolumeLabel -eq #DUCKY_DRIVER_LABEL",
    "sleep -m 100",
    "1..900",
    "$_JITTER_MAX = 4",
    "ATTACKMODE HID STORAGE",
    "KeyHunter\\Install\\Install-KeyHunter.ps1",
)
for marker in required:
    if marker not in source:
        fail(f"missing KeyHunter marker: {marker}")

order_markers = (
    'STRING powershell -NoP -W Hidden -EP Bypass -C "',
    "    ENTER",
    "VAR $RESULT_SCROLL_BASE = $_SCROLLLOCK_ON",
    "VAR $RESULT_CAPS_BASE = $_CAPSLOCK_ON",
    "ATTACKMODE HID STORAGE",
    "VAR $RESULT_TRIES = #RESULT_WAIT_TRIES",
)
positions = [source.index(marker) for marker in order_markers]
if positions != sorted(positions) or len(set(positions)) != len(positions):
    fail(
        "unsafe bootstrap order; expected hidden PowerShell, ENTER, lock-state "
        "baselines, HID STORAGE, result wait"
    )

storage_position = positions[4]
last_string_position = source.rfind("STRING ")
if last_string_position > storage_position:
    fail("keyboard input remains after ATTACKMODE HID STORAGE")

for forbidden in (
    "$_HOST_LOCK_LED_REPLY_GENERATION",
    "SAVE_HOST_KEYBOARD_LOCK_STATE",
    "RESTORE_HOST_KEYBOARD_LOCK_STATE",
):
    if forbidden in source:
        fail(f"non-standard or blocking lock-state mechanism remains: {forbidden}")

chunks: list[str] = []
for line in source.splitlines():
    stripped = line.lstrip()
    if stripped.startswith("STRING "):
        chunks.append(stripped[len("STRING ") :])

if not chunks:
    fail("payload has no STRING chunks")

expanded_chunks = [chunk.replace("#DUCKY_DRIVER_LABEL", "DUCKY") for chunk in chunks]
command = "".join(expanded_chunks)
if len(command) > 259:
    fail(f"expanded Run command is {len(command)} characters (limit 259)")
if max(map(len, expanded_chunks)) > 60:
    fail(f"expanded STRING chunk exceeds 60 characters: {max(map(len, expanded_chunks))}")
if not command.startswith('powershell -NoP -W Hidden -EP Bypass -C "'):
    fail("unexpected PowerShell launcher prefix")
if not command.endswith("KeyHunter\\Install\\Install-KeyHunter.ps1')}\""):
    fail("unexpected PowerShell launcher suffix")

inner = command.split('-C "', 1)[1][:-1]
encoded = base64.b64encode(inner.encode("utf-8")).decode("ascii")
parser_probe = rf"""
$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))
$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) {{
    $errors | ForEach-Object {{ [Console]::Error.WriteLine($_.Message) }}
    exit 1
}}
"""

result = subprocess.run(
    ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
    input=parser_probe,
    text=True,
    capture_output=True,
    timeout=20,
)
if result.returncode:
    sys.stderr.write(result.stdout)
    sys.stderr.write(result.stderr)
    fail("reconstructed PowerShell command does not parse")

print(
    "PASS: KeyHunter bootstrap types before STORAGE, uses standard lock-state pulse, DriveInfo, and parses in Windows "
    f"PowerShell and fits Run ({len(command)}/259 chars, "
    f"max chunk {max(map(len, expanded_chunks))}/60)"
)
