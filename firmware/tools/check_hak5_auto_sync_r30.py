#!/usr/bin/env python3
"""R30 source guard: automatic Hak5 sync, provenance reports and microSD export."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FW = ROOT / 'firmware'


def need(path: Path, *tokens: str) -> str:
    text = path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text:
            raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text

cmd = need(
        ROOT / 'scripts' / 'commands' / 'ANALYZE_HAK5_COMPAT.cmd',
    'sync_hak5_payloads.py',
    '_hak5_cache',
    'HAK5_COMMIT_SHA.txt',
    'hak5_incompatible.csv',
    'hak5_candidate_compatible.csv',
    'microSD_HAK5_COMPATIBLE',
    '/offline',
)
if 'Usage: ANALYZE_HAK5_COMPAT.cmd C:' in cmd:
    raise SystemExit('FAIL: R30 analyzer still requires a manually supplied checkout path')

need(
    FW / 'tools/sync_hak5_payloads.py',
    'https://github.com/hak5/usbrubberducky-payloads.git',
    '"clone"',
    '"fetch"',
    '"reset", "--hard"',
    '"clean", "-ffdx"',
    'offline-cache',
)
need(
    FW / 'tools/analyze_hak5_compat.py',
    'def export_compatible(',
    'candidate-compatible',
    '_PicoFido_HAK5_EXPORT',
    'SOURCE_COMMIT.txt',
    'hak5_compat_report',
)
need(
    ROOT / 'tests/test_r30_hak5_auto_sync.py',
    'test_managed_git_cache_clones_updates_and_cleans',
    'test_export_is_rebuilt_without_stale_files',
    'test_export_contains_only_candidate_payloads_and_companions',
)
print('PASS: R30 zero-argument Hak5 workflow owns clone/update of a managed upstream cache')
print('PASS: R30 records provenance and rebuilds a filtered microSD export with separate reports')
