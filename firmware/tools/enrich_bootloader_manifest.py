"""Bind an existing verified build to its validated generated bootloader."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from board_profiles import REVISIONS
from flash_arduino import load_verified_build_info
from tools.initialize_new_device import bootloader_fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--board-revision', choices=REVISIONS, required=True)
    args = parser.parse_args()
    info = load_verified_build_info(args.board_revision)
    info.update(bootloader_fields(info['build_path']))
    path = Path(info['build_path']) / 'evilkey-build.json'
    path.write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')
    print('PASS: verified image unchanged; validated bootloader bound to ' + str(path))


if __name__ == '__main__':
    main()
