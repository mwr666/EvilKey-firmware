# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check repository documentation encoding and first-party Markdown file links.

Default scope is tracked Markdown/JSON. Explicit file arguments check text only,
so the same guard works inside an extracted component package without Git.
External URLs and heading anchors are not fetched/validated.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MOJIBAKE = re.compile(r"[\u0102\u0139\ufffd]|\u00c3[\u0080-\u00bf]|\u00c2[\u0080-\u00bf]|\u00e2\u20ac")
LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)", re.M)


def check_text(path: Path) -> list[str]:
    """Reject undecodable UTF-8 and recognizable encoding damage."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (UnicodeError, OSError) as exc:
        return [f"{path}: {type(exc).__name__}"]
    errors = []
    for match in MOJIBAKE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        errors.append(f"{path}:{line}: probable mojibake {ascii(match.group())}")
    if path.suffix.lower() == ".json":
        try:
            json.loads(text)
        except ValueError as exc:
            errors.append(f"{path}: invalid JSON: {exc}")
    return errors


def check_links(path: Path, root: Path = ROOT) -> tuple[int, list[str]]:
    text = path.read_text(encoding="utf-8-sig")
    # Code samples may contain illustrative, non-documentation links.
    text = re.sub(r"^(`{3,}|~{3,}).*?^\1\s*$", "", text, flags=re.M | re.S)
    targets = [m.group(1) for pattern in (LINK, REFERENCE) for m in pattern.finditer(text)]
    count, errors = 0, []
    for target in targets:
        target = unquote(target.strip("<>"))
        parsed = urlsplit(target)
        if parsed.scheme or target.startswith("//") or not parsed.path:
            continue
        count += 1
        destination = (root / parsed.path.lstrip("/")) if target.startswith("/") else (path.parent / parsed.path)
        if not destination.exists():
            errors.append(f"{path.relative_to(root)}: missing link target {target}")
    return count, errors


def tracked_files() -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / n.decode("utf-8") for n in raw.split(b"\0")
            if n and Path(n.decode("utf-8")).suffix.lower() in (".md", ".json")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    paths = args.files or tracked_files()
    errors = [error for path in paths for error in check_text(path)]
    links = 0
    if not args.files:
        for path in paths:
            relative = path.relative_to(ROOT).as_posix()
            # User publication drafts and imported upstream READMEs retain their
            # own references. Encoding is still checked for all tracked text.
            if path.suffix.lower() != ".md" or relative.startswith((
                "docs/publication/", "firmware/EvilKeyV1/src/engine/")):
                continue
            count, broken = check_links(path)
            links += count
            errors.extend(broken)
    for error in errors:
        print(error)
    print(f"Documentation: {len(paths)} text files, {links} local file links, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
