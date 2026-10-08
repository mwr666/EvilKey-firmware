"""Package public tracked source plus an exactly identified accepted image."""
from pathlib import Path
import hashlib,json,subprocess,zipfile,sys
ROOT=Path(__file__).resolve().parents[1]
subprocess.run([sys.executable,str(ROOT/'scripts/check_documentation.py')],cwd=ROOT,check=True)
subprocess.run(['git','diff','--quiet'],cwd=ROOT,check=True)
record=json.loads((ROOT/'RELEASE_CURRENT.json').read_text(encoding='utf-8'))
fw=record['firmware'];version=fw['version']
image=ROOT/fw['artifact']
if not image.is_file():raise SystemExit('Download the accepted BIN from the release and place it at '+fw['artifact'])
if hashlib.sha256(image.read_bytes()).hexdigest()!=fw['sha256']:raise SystemExit('Accepted BIN hash mismatch; no package produced.')
entries=subprocess.check_output(['git','ls-files','-s','-z'],cwd=ROOT).split(b'\0')
entries=[entry.decode('utf-8').split('\t',1) for entry in entries if entry]
paths=[path for _,path in entries]
objects=[meta.split()[1] for meta,_ in entries]
raw=subprocess.check_output(['git','cat-file','--batch'],input=('\n'.join(objects)+'\n').encode(),cwd=ROOT)
blobs={};cursor=0
for path in paths:
    end=raw.index(b'\n',cursor);size=int(raw[cursor:end].split()[2])
    cursor=end+1;blobs[path]=raw[cursor:cursor+size];cursor+=size+1
for p in paths:
    parts=Path(p).parts
    if any(x in parts for x in ['.cache','.flash-backups','release','artifacts','.git','build-arduino']) or Path(p).suffix.lower() in ['.ekapp','.wasm','.save']:
        raise SystemExit('Unexpected tracked release input: '+p)
out=ROOT/'release'/('EvilKey_'+version);out.mkdir(parents=True,exist_ok=True)
bundle=out/('EvilKey_'+version+'_public_source.zip')
with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as z:
    # Git blobs preserve canonical LF bytes and generated manifest hashes,
    # independent of the Windows checkout's CRLF conversion.
    for p in paths:z.writestr('EvilKey-firmware/'+p,blobs[p])
    z.write(image,'EvilKey-firmware/'+fw['artifact'])
(out/image.name).write_bytes(image.read_bytes())
(out/'RELEASE_CURRENT.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
(out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in [bundle,out/image.name,out/'RELEASE_CURRENT.json']),encoding='utf-8')
print('Public source and exact accepted BIN packaged in '+str(out))
