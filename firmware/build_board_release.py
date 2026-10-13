"""Build both PCB variants and prepare a private release candidate (no upload/publication)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from board_profiles import REVISIONS
from flash_arduino import load_verified_build_info

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_state():
    """A firmware source ZIP is also usable outside a Git checkout."""
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip())
        return commit, dirty
    except (OSError, subprocess.CalledProcessError):
        return None, None


def stage_candidate(output: Path, infos: list[dict]) -> Path:
    output = output.resolve()
    output.relative_to(ROOT)
    if {i['board_revision'] for i in infos} != set(REVISIONS) or len(infos) != 2:
        raise RuntimeError('Both unique PCB builds are required')
    if len({i['build_inputs_sha256'] for i in infos}) != 1 or len({i['partition_sha256'] for i in infos}) != 1:
        raise RuntimeError('PCB builds must share source inputs and partition layout')
    source = (ROOT / 'firmware/EvilKeyV1/src/pf_firmware_version.h').read_text()
    version = '.'.join(re.search(r'^#define\s+PF_FIRMWARE_VERSION_' + p + r'\s+(\d+)', source, re.M)[1]
                       for p in ('MAJOR', 'MINOR', 'PATCH'))
    output.mkdir(parents=True, exist_ok=True)
    existing_record = output / 'RELEASE_CANDIDATE.json'
    if existing_record.is_file() and json.loads(existing_record.read_text(encoding='utf-8')).get('release_status', '').startswith('final'):
        raise RuntimeError('Refusing to overwrite a final release record')
    variants = []
    for info in infos:
        revision = info['board_revision']
        prefix = f'EvilKey_{version}_PCB_{revision.upper()}'
        variant = {'board_revision': revision, 'version': version,
                   'device_acceptance': 'pending', 'size_bytes': info['image_size']}
        evidence = dict(info)
        for key, hash_key, source_path, extension in (
            ('artifact', 'sha256', info['image_path'], '.bin'),
            ('elf_artifact', 'elf_sha256', str(Path(info['build_path']) / 'EvilKeyV1.ino.elf'), '.elf'),
            ('partition_artifact', 'partition_sha256', info['partition_path'], '.partitions.bin'),
            ('bootloader_artifact', 'bootloader_sha256', info['bootloader_path'], '.bootloader.bin'),
        ):
            dest = output / (prefix + extension)
            shutil.copy2(source_path, dest)
            variant[key] = dest.relative_to(ROOT).as_posix()
            variant[hash_key] = sha(dest)
            dest.with_name(dest.name + '.sha256').write_text(sha(dest) + '  ' + dest.name + '\n', encoding='utf-8')
        # Portable evidence records release-relative paths, not a foreign local build.
        evidence.update(image_path=variant['artifact'], partition_path=variant['partition_artifact'],
                        bootloader_path=variant['bootloader_artifact'],
                        build_path=output.relative_to(ROOT).as_posix(), sketch_path='firmware/EvilKeyV1')
        receipt = output / (prefix + '.build.json')
        receipt.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
        variant.update(build_manifest=receipt.relative_to(ROOT).as_posix(), build_manifest_sha256=sha(receipt))
        variants.append(variant)
    evidence_path = output / 'BOARD_REVISIONS_BUILD.json'
    commit, dirty = git_state()
    evidence_path.write_text(json.dumps({'schema': 'evilkey-board-release-build-v1',
        'version': version, 'source_commit': commit, 'source_dirty': dirty,
        'build_inputs_sha256': infos[0]['build_inputs_sha256'], 'hardware_variants': variants,
        'device_tests': 'NOT RUN', 'publication': 'NOT RUN'}, indent=2) + '\n', encoding='utf-8')
    evidence_path.with_name('BOARD_REVISIONS.md').write_text(
        '# Dual PCB build candidate\n\nBoth complete builds passed linked NVS guards and fit the 4 MiB application partition.\n'
        'PCB V1 and V1.1 device acceptance is pending. No device was flashed and no release was published.\n'
        'See specs/board-revisions/spec.md for hardware qualification.\n', encoding='utf-8')
    current = json.loads((ROOT / 'RELEASE_CURRENT.json').read_text(encoding='utf-8'))
    if version == '0.8.0':
        # Durable current build metadata; never replace older accepted receipts.
        durable_evidence = ROOT / 'docs/RELEASE_0.8.0_BUILD.json'
        shutil.copy2(evidence_path, durable_evidence)
        evidence_path = durable_evidence
    first = variants[0]
    candidate = {'schema': 'evilkey-release-current-v1', 'release_name': f'EvilKey {version} dual PCB private candidate',
        'version': version, 'release_status': 'prepared private candidate; device acceptance pending',
        'spec': ('specs/release-0.8.0/spec.md' if version == '0.8.0' else 'specs/board-revisions/spec.md'),
        'release_notes': f'docs/RELEASE_{version}.md', 'publication_authorized': False,
        'firmware': {'version': version, 'runtime_abi': current['firmware']['runtime_abi'],
                     'device_acceptance': 'pending', 'artifact': first['artifact'], 'sha256': first['sha256'],
                     'build_evidence': evidence_path.relative_to(ROOT).as_posix(),
                     'build_inputs_sha256': infos[0]['build_inputs_sha256'],
                     'partition_sha256': infos[0]['partition_sha256'], 'hardware_variants': variants},
        'manager': current['manager']}
    record = output / 'RELEASE_CANDIDATE.json'
    record.write_text(json.dumps(candidate, indent=2) + '\n', encoding='utf-8')
    # Root is the current preparation entry point; RELEASE_CURRENT stays historical.
    (ROOT / 'RELEASE_CANDIDATE.json').write_text(json.dumps(candidate, indent=2) + '\n', encoding='utf-8')
    print('READY private dual-PCB candidate: ' + str(record))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--use-verified-builds', action='store_true', help='Reuse only both currently valid complete builds')
    parser.add_argument('--output', type=Path, default=ROOT / 'release/board-revisions')
    args = parser.parse_args()
    infos = []
    for revision in REVISIONS:
        if not args.use_verified_builds:
            subprocess.run([sys.executable, str(ROOT / 'firmware/build_arduino.py'), '--board-revision', revision], check=True)
        infos.append(load_verified_build_info(revision))
    stage_candidate(args.output, infos)


if __name__ == '__main__':
    main()
