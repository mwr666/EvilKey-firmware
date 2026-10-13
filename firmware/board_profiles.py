"""Canonical host-side PCB choices, isolated builds and manifest identity."""
from pathlib import Path

REVISIONS = {"v1": 10, "v1.1": 11}


def board_define(revision: str) -> str:
    return f"-DEVILKEY_BOARD_REVISION={REVISIONS[revision]}"


def build_path(root: Path, revision: str, probe: bool = False) -> Path:
    if revision not in REVISIONS:
        raise ValueError("Unsupported PCB revision")
    return root / ("build-arduino-apps-probe" if probe else "build-arduino") / revision


def choose_revision(answer: str) -> str | None:
    return {"1": "v1", "v1": "v1", "2": "v1.1", "v1.1": "v1.1"}.get(answer.strip().lower())


def prompt_revision() -> str | None:
    print("\nWaveshare ESP32-S3-Touch-AMOLED-1.64 PCB revision:")
    print("  1. V1   (silkscreen at the top; LCD CS GPIO9)")
    print("  2. V1.1 (silkscreen on the right near headers; LCD CS GPIO46)")
    print("  Q/empty. Cancel. Check the PCB silkscreen; COM does not identify revision.")
    try:
        return choose_revision(input("PCB revision: "))
    except (EOFError, KeyboardInterrupt):
        return None


def verify_board_identity(info: dict, revision: str) -> None:
    if info.get("board_revision") != revision or info.get("board_define") != board_define(revision):
        raise RuntimeError("Build PCB revision is missing or differs from the selected PCB; upload cancelled.")
    if info.get("apps_vm_link_probe") is not False:
        raise RuntimeError("Probe/unknown build is not eligible for installation.")
