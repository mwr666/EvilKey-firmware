#!/usr/bin/env python3
"""Parser-backed compatibility audit and microSD export for Hak5 payloads.

Every payload is executed in three isolated dry-run scenarios by the exact
patched, pinned DuckyScript runtime used by PicoFido. All HID, storage and delay
callbacks are side-effect-free. A small lexical policy gate remains only for
features that explicitly require approval (exfiltration and payload hiding).
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from collections import Counter

# Snapshot used while implementing R29.  R30 intentionally follows current
# upstream master; a different observed HEAD is recorded, not treated as error.
REFERENCE_HAK5_MASTER = "4fa639fd06972cd7efd9c48cc73136443f9cffb1"
PINNED_HAK5_MASTER = "4fa639fd06972cd7efd9c48cc73136443f9cffb1"  # R29 guard/backward-compat alias

POLICY_BLOCKED_COMMANDS = {
    "HIDE_PAYLOAD": "payload_snapshot_hiding",
    "RESTORE_PAYLOAD": "payload_snapshot_hiding",
    "EXFIL": "variable_exfil",
}

# Keystroke Reflection remains approval-gated even when hidden in a branch that
# a deterministic dry-run scenario does not reach.
POLICY_BLOCKED_VARIABLES = {
    "$_EXFIL_MODE_ENABLED": "keystroke_reflection",
}

# Upstream payloads occasionally enable interfaces that they never use. Keep
# these PicoFido-specific, behavior-preserving adaptations in the export step
# so a fresh Hak5 sync cannot silently restore the unwanted USB profile.
EXPORT_HID_ONLY_PAYLOADS = {
    "payloads/library/prank/the_matrix-wake_up/payload.txt",
}


def git_head(root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def add_reason(reasons: set[str], value: str) -> None:
    if value:
        reasons.add(value)


def policy_audit_text(text: str, *, allow_variable_exfil: bool = False,
                      allow_keystroke_reflection: bool = False) -> list[str]:
    """Reject only functionality that requires explicit approval before use."""
    reasons: set[str] = set()
    rem_block = False
    string_block: str | None = None
    for raw in text.lstrip("\ufeff").replace("\r", "").split("\n"):
        line = raw.strip()
        if rem_block:
            if re.match(r"^END_REM\b", line, re.I):
                rem_block = False
            continue
        if re.match(r"^REM_BLOCK\b", line, re.I):
            rem_block = True
            continue
        if (not line or re.match(r"^REM(?:\s|$|[^A-Z0-9_])", line, re.I)
                or line == "#" or line.startswith("##") or line.startswith("# ")):
            continue

        if string_block is not None:
            if re.match(rf"^END_{string_block}\b", line, re.I):
                string_block = None
            continue
        if re.match(r"^STRINGLN(?:_(?:POWERSHELL|BASH|BLOCK))?\s*$", line, re.I):
            string_block = "STRINGLN"
            continue
        if re.match(r"^STRING(?:_POWERSHELL)?\s*$", line, re.I):
            string_block = "STRING"
            continue
        command = line.split(None, 1)[0].upper()
        if command in POLICY_BLOCKED_COMMANDS:
            reason=POLICY_BLOCKED_COMMANDS[command]
            if reason != "variable_exfil" or not allow_variable_exfil:
                add_reason(reasons, reason)
        for variable, why in POLICY_BLOCKED_VARIABLES.items():
            if variable in line and not (why == "keystroke_reflection" and allow_keystroke_reflection):
                add_reason(reasons, why)
    return sorted(reasons)


def audit_text(text: str) -> list[str]:
    """Backward-compatible conservative source checks used by R29/R30 tools.

    The current compatibility verdict uses the runtime runner; these checks are
    retained for callers that intentionally do not build it.
    """
    reasons: set[str] = set()
    for raw in text.lstrip("\ufeff").replace("\r", "").split("\n"):
        line=raw.strip()
        if (not line or re.match(r"^REM(?:\s|$|[^A-Z0-9_])",line,re.I)
                or line == "#" or line.startswith("##") or line.startswith("# ")):continue
        if re.match(r"^ATTACKMODE\b",line,re.I) and re.search(
            r"\b(?:VID|PID|MAN|PROD|SERIAL)_(?!RANDOM\b)",line,re.I):
            reasons.add("attackmode_descriptor_identity_change")
        if re.match(r"^STRING(?:LN)?\s+",line,re.I) and any(ord(ch)>127 for ch in line):
            reasons.add("non_ascii_string")
    return sorted(reasons)


def build_runtime_runner(temp: Path) -> Path:
    import run_ducky_runtime_tests as runtime_build

    include = runtime_build.prepare_patched_runtime(temp)
    output = temp / ("ducky_dry_run.exe" if __import__("os").name == "nt" else "ducky_dry_run")
    runtime_build.compile_runtime(
        temp,
        include,
        output,
        Path(__file__).resolve().with_name("ducky_dry_run.c"),
    )
    return output


def runtime_audit(runner: Path, text: str) -> dict[str, object]:
    try:
        completed = subprocess.run(
            [str(runner)],
            input=text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "line": 0,
            "message": "dry-run exceeded 15 seconds",
            "reason": "runtime_timeout",
        }
    output = completed.stdout.decode("utf-8", errors="replace").strip()
    fields = output.split("\t", 2)
    status = fields[0] if fields and fields[0] else "runner-error"
    try:
        line = int(fields[1]) if len(fields) > 1 else 0
    except ValueError:
        line = 0
    message = fields[2] if len(fields) > 2 else completed.stderr.decode("utf-8", errors="replace").strip()
    if completed.returncode == 0 and status == "ok":
        reason = ""
    else:
        normalized_status = status.lower().replace("i/o", "io")
        normalized = re.sub(r"[^a-z0-9]+", "_", normalized_status).strip("_") or "error"
        reason = f"runtime_{normalized}"
    return {"status": status, "line": line, "message": message, "reason": reason}


def payload_category(path: Path, repo: Path) -> str:
    try:
        parts = path.relative_to(repo).parts
    except ValueError:
        return "unknown"
    if len(parts) >= 4 and parts[:2] == ("payloads", "library"):
        return parts[2]
    if len(parts) >= 2 and parts[0] == "payloads":
        return parts[1]
    return "other"


def _git_blob_bytes(repo: Path, path: Path) -> bytes | None:
    """Read a tracked file directly from HEAD without opening the worktree file.

    This is primarily a Windows resilience path.  Some Git worktree entries can
    be listed successfully yet fail when Python opens them (OSError/WinError).
    The Git object database still contains the exact bytes, so the audit and
    export can continue without silently dropping the payload.
    """
    try:
        rel = path.resolve(strict=False).relative_to(repo.resolve()).as_posix()
    except (OSError, ValueError):
        try:
            rel = path.relative_to(repo).as_posix()
        except ValueError:
            return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "show", f"HEAD:{rel}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return None
    return result.stdout if result.returncode == 0 else None


def _git_payload_paths(repo: Path) -> list[Path] | None:
    """Return tracked payload.txt paths from Git, or None outside a Git checkout."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z", "--", "payloads"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    paths: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode("utf-8", errors="surrogateescape")
        pp = Path(rel)
        if pp.name.lower() == "payload.txt":
            paths.append(repo / pp)
    return sorted(paths, key=lambda x: x.as_posix().lower())


def find_payloads(repo: Path) -> list[Path]:
    tracked = _git_payload_paths(repo)
    if tracked is not None:
        return tracked
    return sorted(
        p
        for p in (repo / "payloads").rglob("*")
        if p.is_file() and p.name.lower() == "payload.txt"
    )


def _decode_payload_bytes(data: bytes) -> tuple[str, bool]:
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), True


def _read_payload_source(repo: Path, path: Path) -> tuple[str | None, bool, str, str]:
    """Read payload bytes with Git-object fallback for Windows worktree I/O failures."""
    worktree_error = ""
    try:
        data = path.read_bytes()
        text, replaced = _decode_payload_bytes(data)
        return text, replaced, "worktree", ""
    except OSError as exc:
        worktree_error = f"{type(exc).__name__}: {exc}"

    data = _git_blob_bytes(repo, path)
    if data is None:
        return None, False, "unreadable", worktree_error
    text, replaced = _decode_payload_bytes(data)
    return text, replaced, "git-object-fallback", worktree_error


def build_rows(repo: Path, runner: Path | None = None, *, allow_variable_exfil: bool = False,
               allow_keystroke_reflection: bool = False) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for p in find_payloads(repo):
        text, decode_replaced, read_method, read_error = _read_payload_source(repo, p)
        if text is None:
            reasons = ["source_read_error"]
            runtime = {
                "status": "not-run",
                "line": 0,
                "message": "source could not be read",
                "reason": "",
            }
        else:
            reasons = policy_audit_text(text,allow_variable_exfil=allow_variable_exfil,
                allow_keystroke_reflection=allow_keystroke_reflection)
            if runner is None:reasons=sorted(set(reasons)|set(audit_text(text)))
            if decode_replaced:
                reasons = sorted(set(reasons) | {"invalid_utf8_source"})
                runtime = {
                    "status": "not-run",
                    "line": 0,
                    "message": "source is not valid UTF-8",
                    "reason": "",
                }
            else:
                runtime = runtime_audit(runner, text) if runner is not None else {
                    "status":"static-legacy","line":0,"message":"runtime runner not requested","reason":""}
                if runtime["reason"]:
                    reasons = sorted(set(reasons) | {str(runtime["reason"])})
        status = "incompatible" if reasons else "candidate-compatible"
        rows.append({
            "path": p.relative_to(repo).as_posix(),
            "category": payload_category(p, repo),
            "status": status,
            "reasons": reasons,
            "read_method": read_method,
            "read_error": read_error,
            "runtime_status": runtime["status"],
            "runtime_line": runtime["line"],
            "runtime_message": runtime["message"],
        })
    return rows


def _copy_file(repo: Path, src: Path, dst: Path) -> bool:
    """Copy a repository file; fall back to its HEAD blob after Windows I/O errors.

    Returns True when the Git-object fallback was used.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(src, dst)
        return False
    except OSError:
        data = _git_blob_bytes(repo, src)
        if data is None:
            raise
        dst.write_bytes(data)
        return True


def _apply_export_adaptations(rel: Path, dst: Path) -> bool:
    """Apply narrow PicoFido adaptations after copying an upstream file."""
    if rel.as_posix().lower() not in EXPORT_HID_ONLY_PAYLOADS:
        return False
    text = dst.read_text(encoding="utf-8-sig")
    adapted, count = re.subn(
        r"(?im)^ATTACKMODE[ \t]+HID[ \t]+STORAGE[ \t]*$",
        "ATTACKMODE HID",
        text,
        count=1,
    )
    if count != 1:
        raise RuntimeError(
            f"Expected one HID STORAGE profile in export adaptation: {rel.as_posix()}"
        )
    dst.write_text(adapted, encoding="utf-8", newline="")
    return True


def _payload_parent_map(repo: Path, rows: list[dict[str, object]]) -> dict[Path, bool]:
    out: dict[Path, bool] = {}
    for row in rows:
        p = (repo / str(row["path"])).resolve()
        out[p.parent] = row["status"] == "candidate-compatible"
    return out


def _belongs_to_rejected_nested_payload(
    src: Path,
    selected_root: Path,
    payload_dirs: dict[Path, bool],
) -> bool:
    """Return True if *src* lives in a nested rejected payload bundle."""
    cur = src.parent.resolve()
    stop = selected_root.resolve()
    while cur != stop and stop in cur.parents:
        if cur in payload_dirs:
            return not payload_dirs[cur]
        cur = cur.parent
    return False


def export_compatible(
    repo: Path,
    rows: list[dict[str, object]],
    export_dir: Path,
    *,
    observed_head: str | None,
) -> dict[str, object]:
    """Build a clean microSD tree containing only candidate payload.txt files.

    For every selected payload, companion files from its payload directory are
    retained.  If a selected directory contains a nested payload bundle that was
    rejected by the audit, that nested bundle is omitted.  The Hak5 language
    maps are copied wholesale because PicoFido loads them independently.
    """
    repo = repo.resolve()
    export_dir = export_dir.resolve()
    if export_dir.exists():
        shutil.rmtree(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)

    payload_dirs = _payload_parent_map(repo, rows)
    selected_rows = [r for r in rows if r["status"] == "candidate-compatible"]
    selected_payloads = {(repo / str(r["path"])).resolve() for r in selected_rows}
    copied_files: set[str] = set()
    copy_fallbacks = 0
    adapted_files: list[str] = []

    for row in selected_rows:
        payload = (repo / str(row["path"])).resolve()
        bundle = payload.parent
        for src in bundle.rglob("*"):
            if not src.is_file():
                continue
            if ".git" in src.parts:
                continue
            if _belongs_to_rejected_nested_payload(src, bundle, payload_dirs):
                continue
            if src.name.lower() == "payload.txt" and src.resolve() not in selected_payloads:
                continue
            rel = src.relative_to(repo)
            dst = export_dir / rel
            copy_fallbacks += int(_copy_file(repo, src, dst))
            if _apply_export_adaptations(rel, dst):
                adapted_files.append(rel.as_posix())
            copied_files.add(rel.as_posix())

    language_dir = repo / "languages"
    language_files = 0
    if language_dir.is_dir():
        for src in language_dir.rglob("*"):
            if src.is_file():
                rel = src.relative_to(repo)
                copy_fallbacks += int(_copy_file(repo, src, export_dir / rel))
                copied_files.add(rel.as_posix())
                language_files += 1

    # Preserve upstream legal/readme material if present, without placing it in
    # /payloads where the device scans executable source files.
    for name in ("README.md", "LICENSE", "LICENSE.md", "NOTICE", "NOTICE.md"):
        src = repo / name
        if src.is_file():
            dst_name = "HAK5_UPSTREAM_" + name
            copy_fallbacks += int(_copy_file(repo, src, export_dir / dst_name))
            copied_files.add(dst_name)

    meta_dir = export_dir / "_PicoFido_HAK5_EXPORT"
    meta_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": 1,
        "profile": "PicoFido R35 parser-backed DuckyScript 3 dry-run",
        "source_repo": "https://github.com/hak5/usbrubberducky-payloads",
        "source_commit": observed_head,
        "candidate_payload_count": len(selected_rows),
        "language_file_count": language_files,
        "copied_file_count": len(copied_files),
        "git_object_copy_fallback_count": copy_fallbacks,
        "adapted_files": adapted_files,
        "warning": (
            "Parser-backed dry-run only. Payloads are third-party sources and may type "
            "commands into the host. Review payload.txt before running it."
        ),
    }
    (meta_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (meta_dir / "SOURCE_COMMIT.txt").write_text((observed_head or "unknown") + "\n", encoding="utf-8")
    (meta_dir / "README.txt").write_text(
        "EvilKey - Hak5 candidates exported after parser dry run\n"
        "\n"
        "This directory was generated by ANALYZE_HAK5_COMPAT.cmd.\n"
        "It contains payload.txt files that passed three non-effectful DuckyScript\n"
        "runtime dry-run scenarios. This does not guarantee correct or safe behavior\n"
        "on the target system. Review every payload.txt before running it.\n"
        "\n"
        "Copy /payloads and /languages to the root of the microSD card if needed.\n",
        encoding="utf-8",
    )
    return manifest


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "path", "category", "status", "reasons", "read_method", "read_error",
                "runtime_status", "runtime_line", "runtime_message",
            ],
        )
        w.writeheader()
        for row in rows:
            w.writerow({**row, "reasons": ";".join(row["reasons"])})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", type=Path, help="Local checkout of hak5/usbrubberducky-payloads")
    ap.add_argument("--json", dest="json_path", type=Path, default=Path("hak5_compat_report.json"))
    ap.add_argument("--csv", dest="csv_path", type=Path, default=Path("hak5_compat_report.csv"))
    ap.add_argument("--incompatible-csv", type=Path)
    ap.add_argument("--compatible-csv", type=Path)
    ap.add_argument("--summary", type=Path)
    ap.add_argument("--export-dir", type=Path)
    ap.add_argument("--enable-variable-exfil", action="store_true",
                    help="Audit for a build with Stage 8A enabled; local device approval is still required")
    ap.add_argument("--enable-keystroke-reflection", action="store_true",
                    help="Audit for a build with Stage 8B enabled; local device approval is still required")
    args = ap.parse_args()

    repo = args.repo.resolve()
    if not (repo / "payloads").is_dir():
        raise SystemExit(f"Not a Hak5 payload checkout: {repo}")

    with tempfile.TemporaryDirectory(prefix="picofido-ducky-audit-") as temp_name:
        runner = build_runtime_runner(Path(temp_name))
        rows = build_rows(repo, runner,allow_variable_exfil=args.enable_variable_exfil,
            allow_keystroke_reflection=args.enable_keystroke_reflection)
    counts = Counter(str(r["status"]) for r in rows)
    reasons = Counter(
        reason
        for row in rows
        for reason in row["reasons"]
    )
    read_methods = Counter(str(r.get("read_method", "unknown")) for r in rows)
    categories: dict[str, dict[str, int]] = {}
    for row in rows:
        cat = str(row["category"])
        categories.setdefault(cat, {"candidate-compatible": 0, "incompatible": 0})
        categories[cat][str(row["status"])] += 1

    head = git_head(repo)
    report: dict[str, object] = {
        "schema": 3,
        "picofido_profile": "R35 parser-backed DuckyScript 3 dry-run",
        "reference_hak5_head_from_r29_development": REFERENCE_HAK5_MASTER,
        "observed_git_head": head,
        "payload_count": len(rows),
        "enabled_stage8_capabilities": {
            "variable_exfil": args.enable_variable_exfil,
            "keystroke_reflection": args.enable_keystroke_reflection,
            "payload_snapshot_hiding": False,
        },
        "counts": dict(counts),
        "reason_counts": dict(sorted(reasons.items())),
        "read_method_counts": dict(sorted(read_methods.items())),
        "category_counts": categories,
        "note": (
            "candidate-compatible passed the exact runtime in three side-effect-free dry-run scenarios; "
            "this is not physical target-OS validation"
        ),
        "payloads": rows,
    }

    args.json_path.parent.mkdir(parents=True, exist_ok=True)
    args.json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_csv(args.csv_path, rows)

    incompatible = [r for r in rows if r["status"] == "incompatible"]
    compatible = [r for r in rows if r["status"] == "candidate-compatible"]
    if args.incompatible_csv:
        write_csv(args.incompatible_csv, incompatible)
    if args.compatible_csv:
        write_csv(args.compatible_csv, compatible)

    export_manifest = None
    if args.export_dir:
        export_manifest = export_compatible(
            repo,
            rows,
            args.export_dir,
            observed_head=head,
        )
        report["export"] = export_manifest
        args.json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "PicoFido R35 parser-backed Hak5 compatibility summary",
            f"source_commit={head or 'unknown'}",
            f"payload_count={len(rows)}",
            f"candidate_compatible={counts.get('candidate-compatible', 0)}",
            f"incompatible={counts.get('incompatible', 0)}",
            "",
            f"git_object_read_fallbacks={read_methods.get('git-object-fallback', 0)}",
            f"unreadable_sources={read_methods.get('unreadable', 0)}",
            "",
            "Incompatibility reasons:",
        ]
        lines += [f"  {k}={v}" for k, v in sorted(reasons.items())]
        if export_manifest:
            lines += [
                "",
                f"export_candidate_payloads={export_manifest['candidate_payload_count']}",
                f"export_language_files={export_manifest['language_file_count']}",
                f"export_copied_files={export_manifest['copied_file_count']}",
                f"export_git_object_copy_fallbacks={export_manifest['git_object_copy_fallback_count']}",
            ]
        args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Hak5 commit: {head or 'unknown'}")
    print(f"Hak5 payload.txt files: {len(rows)}")
    print(f"candidate-compatible: {counts.get('candidate-compatible', 0)}")
    print(f"incompatible: {counts.get('incompatible', 0)}")
    print(f"Git-object read fallbacks: {read_methods.get('git-object-fallback', 0)}")
    print(f"Unreadable sources: {read_methods.get('unreadable', 0)}")
    print(f"JSON: {args.json_path}")
    print(f"CSV:  {args.csv_path}")
    if args.incompatible_csv:
        print(f"Rejected CSV: {args.incompatible_csv}")
    if args.compatible_csv:
        print(f"Accepted CSV: {args.compatible_csv}")
    if args.export_dir:
        print(f"microSD export: {args.export_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
