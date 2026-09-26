#!/usr/bin/env python3
"""Synchronize a managed local checkout of hak5/usbrubberducky-payloads.

The checkout is treated as a cache owned by PicoFido tooling.  On every online
run it is reset to the current upstream branch so stale/untracked payload files
cannot contaminate the compatibility report.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

DEFAULT_REMOTE = "https://github.com/hak5/usbrubberducky-payloads.git"
DEFAULT_BRANCH = "master"


class SyncError(RuntimeError):
    pass


def _git() -> str:
    exe = shutil.which("git")
    if not exe:
        raise SyncError("Git was not found in PATH. Install Git for Windows and run again.")
    return exe


def _run(args: list[str], *, cwd: Path | None = None) -> str:
    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    cp = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if cp.returncode != 0:
        command = " ".join(args)
        raise SyncError(f"Git command failed ({cp.returncode}): {command}\n{cp.stdout.strip()}")
    return cp.stdout.strip()


def git_head(repo: Path) -> str:
    return _run([_git(), "-C", str(repo), "rev-parse", "HEAD"]).splitlines()[-1].strip()


def git_origin(repo: Path) -> str | None:
    try:
        return _run([_git(), "-C", str(repo), "remote", "get-url", "origin"]).strip()
    except SyncError:
        return None


def _ensure_empty_target(repo: Path) -> None:
    if repo.exists() and not (repo / ".git").is_dir():
        if any(repo.iterdir()):
            raise SyncError(
                f"Managed checkout path exists but is not a Git repository: {repo}\n"
                "Move/delete that directory and run the command again."
            )
        repo.rmdir()


def sync_repo(
    repo: Path,
    *,
    remote: str = DEFAULT_REMOTE,
    branch: str = DEFAULT_BRANCH,
    offline: bool = False,
) -> dict[str, object]:
    """Clone/update *repo* and return synchronization metadata.

    Online mode is intentionally destructive inside the managed checkout:
    tracked files are reset to upstream and untracked files are cleaned.  This
    makes repeated compatibility reports deterministic.
    """
    repo = repo.resolve()
    git = _git()

    if offline:
        if not (repo / ".git").is_dir():
            raise SyncError(f"Offline mode requested but no cached repository exists: {repo}")
        head = git_head(repo)
        return {
            "schema": 1,
            "mode": "offline-cache",
            "repo": str(repo),
            "remote": git_origin(repo),
            "branch": branch,
            "head": head,
            "updated": False,
        }

    repo.parent.mkdir(parents=True, exist_ok=True)
    _ensure_empty_target(repo)
    cloned = False

    if not (repo / ".git").is_dir():
        _run([
            git,
            "-c", "core.longpaths=true",
            "clone",
            "--depth", "1",
            "--single-branch",
            "--branch", branch,
            remote,
            str(repo),
        ])
        cloned = True
    else:
        # The upstream payload collection contains paths that exceed the
        # traditional Win32 MAX_PATH limit.  Configure the managed checkout
        # before fetch/checkout so a previous partial clone can recover too.
        _run([git, "-C", str(repo), "config", "core.longpaths", "true"])
        # This path is explicitly a PicoFido-managed cache.  Point origin back
        # to the official source before every update and clean local residue.
        if git_origin(repo) != remote:
            _run([git, "-C", str(repo), "remote", "set-url", "origin", remote])
        _run([git, "-C", str(repo), "fetch", "--depth", "1", "--prune", "origin", branch])
        # A clone whose initial checkout was interrupted by MAX_PATH leaves
        # files untracked because no index was written.  This directory is an
        # explicitly managed cache, so clean that residue before recovery.
        _run([git, "-C", str(repo), "clean", "-ffdx"])
        _run([git, "-C", str(repo), "checkout", "-B", branch, "FETCH_HEAD"])
        _run([git, "-C", str(repo), "reset", "--hard", "FETCH_HEAD"])
        _run([git, "-C", str(repo), "clean", "-ffdx"])

    head = git_head(repo)
    return {
        "schema": 1,
        "mode": "online",
        "repo": str(repo),
        "remote": remote,
        "branch": branch,
        "head": head,
        "updated": True,
        "cloned": cloned,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo", type=Path, help="Managed checkout destination")
    ap.add_argument("--remote", default=DEFAULT_REMOTE)
    ap.add_argument("--branch", default=DEFAULT_BRANCH)
    ap.add_argument("--offline", action="store_true", help="Use existing cache without network access")
    ap.add_argument("--sha-file", type=Path)
    ap.add_argument("--json", dest="json_path", type=Path)
    args = ap.parse_args()

    try:
        result = sync_repo(
            args.repo,
            remote=args.remote,
            branch=args.branch,
            offline=args.offline,
        )
    except SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.sha_file:
        args.sha_file.parent.mkdir(parents=True, exist_ok=True)
        args.sha_file.write_text(str(result["head"]) + "\n", encoding="utf-8")
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"Hak5 repository: {result['repo']}")
    print(f"Hak5 branch:     {result['branch']}")
    print(f"Hak5 commit:     {result['head']}")
    print(f"Sync mode:       {result['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
