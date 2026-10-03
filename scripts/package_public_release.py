"""Package public tracked source plus an exactly identified accepted image."""
from pathlib import Path
import hashlib,json,subprocess,zipfile
ROOT=Path(__file__).resolve().parents[1]
record=json.loads((ROOT/'RELEASE_CURRENT.json').read_text(encoding='utf-8'))
fw=record['firmware'];version=fw['version']
image=ROOT/fw['artifact']
if not image.is_file():raise SystemExit('Download the accepted BIN from the release and place it at '+fw['artifact'])
if hashlib.sha256(image.read_bytes()).hexdigest()!=fw['sha256']:raise SystemExit('Accepted BIN hash mismatch; no package produced.')
paths=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().rstrip('\0').split('\0')
paths=[p for p in paths if (ROOT/p).is_file()]
for p in paths:
    parts=Path(p).parts
    if any(x in parts for x in ['.cache','.flash-backups','release','artifacts','.git','build-arduino']) or Path(p).suffix.lower() in ['.ekapp','.wasm','.save']:
        raise SystemExit('Unexpected tracked release input: '+p)
out=ROOT/'release'/('EvilKey_'+version);out.mkdir(parents=True,exist_ok=True)
bundle=out/('EvilKey_'+version+'_public_source.zip')
with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as z:
    for p in paths:z.write(ROOT/p,'EvilKey-firmware/'+p)
    z.write(image,'EvilKey-firmware/'+fw['artifact'])
(out/image.name).write_bytes(image.read_bytes())
(out/'RELEASE_CURRENT.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
(out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in [bundle,out/image.name,out/'RELEASE_CURRENT.json']),encoding='utf-8')
print('Public source and exact accepted BIN packaged in '+str(out))
