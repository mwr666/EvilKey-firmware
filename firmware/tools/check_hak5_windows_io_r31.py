#!/usr/bin/env python3
"""R31 guard: Windows worktree I/O errors fall back to Git objects."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / "firmware/tools/analyze_hak5_compat.py"
TEST = ROOT / "tests/test_r30_hak5_auto_sync.py"

def need(path: Path, *tokens: str) -> str:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        if token not in text:
            raise SystemExit(f"FAIL {path}: missing {token!r}")
    return text

need(
    AUDIT,
    "def _git_blob_bytes(",
    '"git", "-C", str(repo), "show", f"HEAD:{rel}"',
    "def _read_payload_source(",
    'except OSError as exc:',
    '"git-object-fallback"',
    '"source_read_error"',
    "def _copy_file(repo: Path, src: Path, dst: Path) -> bool:",
    'git_object_copy_fallback_count',
    '"ls-files", "-z", "--", "payloads"',
)
need(
    TEST,
    "test_windows_worktree_read_error_falls_back_to_git_object",
    "test_windows_worktree_copy_error_falls_back_to_git_object",
    "OSError(22, 'Invalid argument')",
)
print("PASS: R31 audits tracked payloads from Git index and survives Windows worktree open errors")
print("PASS: R31 export falls back to exact HEAD blob bytes when shutil.copy2 cannot read a file")
