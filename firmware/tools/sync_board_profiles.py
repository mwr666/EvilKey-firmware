"""Synchronize only PCB-profile consumers; preserve unrelated generated sources."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def sync(root=ROOT):
    manifest_path = root / 'EvilKeyV1/GENERATED_MANIFEST.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    for name in ('ws_pins.h', 'ws_panel.h', 'ws_panel.c', 'ws_board.c'):
        text = (root / 'templates/port' / name).read_text(encoding='utf-8')
        if name.endswith('.c'):
            text = '#include "../../pf_build_config.h"\n' + text
            text = text.replace('"../../EvilKeyV1/src/apps/', '"../../apps/')
            text = text.replace('"pf_engine_api.h"', '"../../pf_engine_api.h"')
            text = text.replace('"led/led.h"', '"../sdk/src/led/led.h"')
        relative = 'board/' + name
        target = root / 'EvilKeyV1/src/engine' / relative
        target.write_text(text, encoding='utf-8', newline='\n')
        manifest['generated_sha256'][relative] = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest['supported_board_revisions'] = ['v1', 'v1.1']
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print('PASS: PCB profile consumers and manifest synchronized.')


if __name__ == '__main__':
    sync()
