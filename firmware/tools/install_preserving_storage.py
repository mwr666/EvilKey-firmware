"""Install a reviewed application/table with protected flash readback verification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from .flash_safety import PROTECTED, parse_table, validate_command, validate_write

# Native USB readback must not rely on one uninterrupted multi-megabyte stream.
READ_CHUNK = 64 * 1024


def install(esptool, port, info, observed_table, backup_root):
    if not re.fullmatch(r'COM[1-9][0-9]*',port['address'],re.I):
        raise RuntimeError('Invalid COM port')
    image=Path(str(info['image_path']));table=Path(str(info['partition_path']))
    wanted=table.read_bytes();before_layout=parse_table(observed_table)
    app_offset,app_capacity=parse_table(wanted)
    if (app_offset,app_capacity)!=(info['app_offset'],info['app_capacity']):
        raise RuntimeError('Manifest/partition layout mismatch')
    if hashlib.sha256(image.read_bytes()).hexdigest()!=info['image_sha256']:
        raise RuntimeError('Application changed after build validation')
    if hashlib.sha256(wanted).hexdigest()!=info['partition_sha256']:
        raise RuntimeError('Partition image changed after build validation')
    migrating=observed_table!=wanted
    if migrating and not (before_layout==(0x10000,0x1F0000) and (app_offset,app_capacity)==(0x500000,0x400000)):
        raise RuntimeError('Only the reviewed 0.5.x to 0.6.x layout migration is allowed')
    validate_write(app_offset,image.stat().st_size,app_offset=app_offset,app_capacity=app_capacity)
    if migrating:validate_write(0x8000,len(wanted),app_offset=app_offset,app_capacity=app_capacity,table=True)
    # Device stays in ROM/stub until all readbacks pass. It must not run firmware
    # between before/after hashes, since ordinary firmware can legitimately save state.
    # Start each transfer in download mode with a fresh stub. Reusing the stub
    # across read commands proved unreliable on this native USB connection.
    prefix=[str(esptool),'--silent','--chip','esp32s3','--port',port['address'],'--baud','115200',
            '--before','default-reset','--after','no-reset']
    def run(args):
        command=prefix+args;validate_command(command);subprocess.run(command,check=True)
    def digest(offset,length):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name('flash_digest.py')),
                               port['address'],hex(offset),str(length)],
                              check=True,capture_output=True,text=True)
        value=result.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{32}',value):raise RuntimeError('Incomplete flash digest')
        return value
    def read(offset,length,path):
        result=bytearray()
        for at in range(0,length,READ_CHUNK):
            size=min(READ_CHUNK,length-at)
            run(['read-flash','--no-progress',hex(offset+at),str(size),str(path)])
            data=path.read_bytes()
            if len(data)!=size:raise RuntimeError('Incomplete flash readback')
            result.extend(data)
        return bytes(result)
    backup=Path(backup_root)/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup.mkdir(parents=True,exist_ok=False)
    (backup/'partition-before.bin').write_bytes(observed_table)
    (backup/'partition-after.bin').write_bytes(wanted)
    receipt={'schema':'evilkey-storage-preservation-v2','digest_algorithm':'md5-device',
             'port':port['address'],
             'old_app':before_layout,'new_app':[app_offset,app_capacity],
             'migration':migrating,'image_sha256':info['image_sha256'],
             'protected_before':{},'protected_after':{},'verified':False}
    receipt_path=backup/'preservation.json'
    def save():receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
    save()
    # Device-side digests avoid large native USB reads and never transmit key
    # bytes. SHA-256 still binds the candidate to its checked build manifest.
    with tempfile.TemporaryDirectory(prefix='evilkey-storage-check-') as tmp:
        scratch=Path(tmp)
        def hashes():
            result={}
            for name,(address,length) in PROTECTED.items():
                print(f'Checking protected storage: {name} ({length//1024} KiB)',flush=True)
                result[name]=digest(address,length)
            return result
        receipt['protected_before']=hashes();save()
        print('Writing application at '+hex(app_offset),flush=True)
        run(['write-flash','--flash-mode','keep','--flash-freq','keep','--flash-size','keep',hex(app_offset),str(image)])
        print('Verifying application readback',flush=True)
        if digest(app_offset,image.stat().st_size)!=hashlib.md5(image.read_bytes()).hexdigest():
            raise RuntimeError('Application readback mismatch; device remains in ROM')
        # Commit the new table only after the relocated image has been verified.
        if migrating:
            print('Committing verified partition table at 0x8000',flush=True)
            run(['write-flash','--flash-mode','keep','--flash-freq','keep','--flash-size','keep','0x8000',str(table)])
        if read(0x8000,len(wanted),scratch/'table.bin')!=wanted:
            raise RuntimeError('Partition readback mismatch; use the saved table for rollback')
        receipt['protected_after']=hashes();save()
        if receipt['protected_before']!=receipt['protected_after']:
            raise RuntimeError('Protected storage changed; device remains in ROM for investigation')
        receipt['verified']=True;save()
    print('PASS: application/table verified; nvs, wsdev, part0 and otadata hashes unchanged.')
    print('Preservation receipt: '+str(receipt_path))
    print('Device remains in download mode. Press RESET without BOOT to start the verified firmware.')
    return receipt_path
