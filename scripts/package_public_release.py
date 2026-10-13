"""Package public Git source with verified legacy or dual-PCB release artifacts."""
from pathlib import Path
import hashlib,json,re,subprocess,sys,zipfile
ROOT=Path(__file__).resolve().parents[1]

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def validate(root,record):
    fw=record['firmware'];version=fw['version']
    source=(root/'firmware/EvilKeyV1/src/pf_firmware_version.h').read_text(encoding='utf-8')
    source_version='.'.join(re.search(r'^#define\s+PF_FIRMWARE_VERSION_'+k+r'\s+(\d+)',source,re.M)[1] for k in ('MAJOR','MINOR','PATCH'))
    if version!=source_version:raise RuntimeError('Release version differs from canonical source.')
    artifacts=[]
    def checked(name,expected):
        p=(root/name).resolve()
        if not p.is_relative_to(root.resolve()) or not p.is_file() or digest(p)!=expected:
            raise RuntimeError('Missing, unsafe or corrupted release artifact: '+name)
        artifacts.append(p)
        return p
    variants=fw.get('hardware_variants')
    if not variants:
        image=checked(fw['artifact'],fw['sha256'])
        if image.stat().st_size!=fw['size_bytes']:raise RuntimeError('Legacy BIN size mismatch.')
        return artifacts
    if len(variants)!=2 or sorted(v['board_revision'] for v in variants)!=['v1','v1.1']:
        raise RuntimeError('Dual release requires exactly PCB V1 and V1.1.')
    for v in variants:
        if v['version']!=version or v['device_acceptance']!='functional_validation_passed':
            raise RuntimeError('PCB version or validation status differs.')
        files={}
        for key,hkey in [('artifact','sha256'),('elf_artifact','elf_sha256'),('partition_artifact','partition_sha256'),('bootloader_artifact','bootloader_sha256'),('build_manifest','build_manifest_sha256')]:
            p=checked(v[key],v[hkey]);files[key]=p
            if key!='build_manifest':
                sidecar=Path(str(p)+'.sha256')
                if not sidecar.is_file() or sidecar.read_text(encoding='utf-8').strip()!=v[hkey]+'  '+p.name:
                    raise RuntimeError('Missing or incorrect SHA256 sidecar: '+p.name)
                artifacts.append(sidecar)
        info=json.loads(files['build_manifest'].read_text(encoding='utf-8'))
        expected_define='-DEVILKEY_BOARD_REVISION='+('10' if v['board_revision']=='v1' else '11')
        if info.get('schema')!='evilkey-arduino-build-v1' or info.get('board_revision')!=v['board_revision'] or info.get('board_define')!=expected_define or info.get('apps_vm_link_probe') is not False or info.get('nvs_guard')!='link-wrap-v1' or info.get('erase_flash')!='none':
            raise RuntimeError('PCB build identity or linked storage guard is invalid.')
        for key,hkey in [('image_sha256','sha256'),('elf_sha256','elf_sha256'),('partition_sha256','partition_sha256'),('bootloader_sha256','bootloader_sha256')]:
            if info.get(key)!=v[hkey]:raise RuntimeError('PCB build hashes differ from release record.')
        if info.get('build_inputs_sha256')!=fw['build_inputs_sha256'] or v['partition_sha256']!=fw['partition_sha256'] or info.get('app_offset')!=0x500000 or info.get('app_capacity')!=0x400000:
            raise RuntimeError('PCB source or partition contract mismatch.')
        if files['artifact'].stat().st_size!=v['size_bytes'] or info.get('image_size')!=v['size_bytes'] or files['partition_artifact'].stat().st_size!=3072 or files['bootloader_artifact'].stat().st_size!=info.get('bootloader_size'):
            raise RuntimeError('PCB image size mismatch.')
    return artifacts

def main():
    subprocess.run([sys.executable,str(ROOT/'scripts/check_documentation.py')],cwd=ROOT,check=True)
    subprocess.run(['git','diff','--quiet'],cwd=ROOT,check=True)
    record=json.loads((ROOT/'RELEASE_CURRENT.json').read_text(encoding='utf-8'))
    artifacts=validate(ROOT,record);version=record['firmware']['version']
    rows=[r.decode().split('\t',1) for r in subprocess.check_output(['git','ls-files','-s','-z'],cwd=ROOT).split(b'\0') if r]
    raw=subprocess.check_output(['git','cat-file','--batch'],input=('\n'.join(m.split()[1] for m,n in rows)+'\n').encode(),cwd=ROOT)
    files={};cursor=0
    for meta,name in rows:
        end=raw.index(b'\n',cursor);size=int(raw[cursor:end].split()[2]);cursor=end+1;files[name]=raw[cursor:cursor+size];cursor+=size+1
        if any(p in Path(name).parts for p in ('.cache','.flash-backups','release','artifacts','.git','build-arduino','specs')) or Path(name).suffix.lower() in ('.ekapp','.wasm','.save','.step'):
            raise RuntimeError('Unexpected tracked public release input: '+name)
    out=ROOT/'release'/('EvilKey_'+version);out.mkdir(parents=True,exist_ok=True)
    bundle=out/('EvilKey_'+version+'_public_source.zip')
    with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as z:
        for name,b in files.items():z.writestr('EvilKey-firmware/'+name,b)
        for p in artifacts:z.write(p,'EvilKey-firmware/'+p.relative_to(ROOT).as_posix())
    for p in artifacts:(out/p.name).write_bytes(p.read_bytes())
    (out/'RELEASE_CURRENT.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    payloads=[bundle,out/'RELEASE_CURRENT.json']+[out/p.name for p in artifacts]
    (out/'SHA256SUMS.txt').write_text(''.join(digest(p)+'  '+p.name+'\n' for p in payloads),encoding='utf-8')
    print('Public source and verified PCB artifacts packaged in '+str(out))
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except RuntimeError as exc:raise SystemExit(str(exc))
