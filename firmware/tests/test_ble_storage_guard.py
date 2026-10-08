"""Negative tests: altered dependencies, erase recovery and protected flash ranges."""
from pathlib import Path
import importlib.util
import unittest
import sys
import tempfile
import hashlib
import struct
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tools'/f'{name}.py')
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


guard = load('flash_safety')
check = load('check_ble_storage')
sys.path.insert(0,str(ROOT))
from tools.install_preserving_storage import install, READ_CHUNK


def table(offset,capacity,move_nvs=False):
    values=[('nvs',1,2,0x9000+(0x1000 if move_nvs else 0),0x5000),
            ('otadata',1,0,0xE000,0x2000),('factory',0,0,offset,capacity),
            ('part0',0x40,1,0x200000,0x100000),('wsdev',1,2,0x400000,0x10000)]
    data=b''.join(struct.pack('<HBBII16sI',0x50AA,kind,subtype,at,size,name.encode(),0)
                  for name,kind,subtype,at,size in values)
    data+=b'\xeb\xeb'+b'\xff'*14+hashlib.md5(data).digest()
    return data+b'\xff'*(0xC00-len(data))


class Preservation(unittest.TestCase):
    def test_reviewed_writes(self):
        for address, length in guard.APP_LAYOUTS:
            self.assertEqual(guard.validate_write(address, length, app_offset=address,
                                                 app_capacity=length), (address, address+length))
        self.assertEqual(guard.validate_write(0x8000, 0xC00, table=True), (0x8000, 0x9000))

    def test_sector_boundaries(self):
        for address, length in guard.PROTECTED.values():
            for offset, size in ((address, 1), (address-1, 2), (address+length-1, 2)):
                with self.assertRaises(RuntimeError):guard.validate_write(offset, size)
        for offset, size in ((0x10000, 0x1F0001), (0x8000, 0x1001), (0, 0), (0x1000000, 1)):
            with self.assertRaises(RuntimeError):guard.validate_write(offset, size)

    def test_commands(self):
        for token in ('erase_flash', 'erase-flash', 'erase-region', '--erase-all'):
            with self.assertRaises(RuntimeError):guard.validate_command(['esptool', token])

    def test_prepared_ble(self):
        self.assertTrue(check.verify())

    def test_tampering_rejected(self):
        path=ROOT/'.ble-libraries/NimBLE-Arduino/src/NimBLEDevice.cpp'
        original=path.read_bytes()
        try:
            path.write_bytes(original+b'\nvoid recovery(){nvs_flash_erase();}\n')
            with self.assertRaises(RuntimeError):check.verify()
        finally:path.write_bytes(original)

    def test_table_boundary(self):
        for offset,length in guard.APP_LAYOUTS:
            self.assertEqual(guard.parse_table(table(offset,length)),(offset,length))
        with self.assertRaises(RuntimeError):guard.parse_table(table(0x500000,0x400000,True))
        damaged=bytearray(table(0x500000,0x400000));damaged[21]^=1
        with self.assertRaises(RuntimeError):guard.parse_table(damaged)

    def simulate_install(self,corrupt=False,cut=False,short_read=False):
        old=table(0x10000,0x1F0000);new=table(0x500000,0x400000)
        memory=bytearray(b'\xff'*guard.FLASH_SIZE);memory[0x8000:0x8C00]=old
        originals={}
        for name,(address,size) in guard.PROTECTED.items():
            content=(name.encode()*((size+len(name)-1)//len(name)))[:size]
            memory[address:address+size]=content;originals[name]=hashlib.md5(content).hexdigest()
        app=b'\xe9'+b'candidate firmware'*12000
        writes=[];app_verified=False
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/'app.bin';image.write_bytes(app)
            partitions=root/'table.bin';partitions.write_bytes(new)
            info={'image_path':str(image),'partition_path':str(partitions),'app_offset':0x500000,
                  'app_capacity':0x400000,'image_sha256':hashlib.sha256(app).hexdigest(),
                  'partition_sha256':hashlib.sha256(new).hexdigest()}
            def fake(command,check,**kwargs):
                nonlocal app_verified
                if command[1].endswith('flash_digest.py'):
                    offset=int(command[-2],0);length=int(command[-1],0)
                    value=hashlib.md5(memory[offset:offset+length]).hexdigest()
                    if short_read and offset==0x200000:value=value[:-1]
                    if offset==0x500000:app_verified=True
                    return __import__('types').SimpleNamespace(stdout=value+'\n')
                self.assertTrue(check);guard.validate_command(command)
                self.assertEqual(command[command.index('--before')+1],'default-reset')
                self.assertEqual(command[command.index('--after')+1],'no-reset')
                if 'read-flash' in command:
                    at=command.index('read-flash');values=[v for v in command[at+1:] if v!='--no-progress']
                    offset=int(values[0],0);length=int(values[1],0)
                    self.assertLessEqual(length,READ_CHUNK)
                    content=memory[offset:offset+length]
                    if short_read and offset==0x200000:content=content[:-1]
                    Path(values[2]).write_bytes(content)
                    if offset+length==0x500000+len(app):app_verified=True
                else:
                    self.assertIn('write-flash',command)
                    offset=int(command[-2],0);data=Path(command[-1]).read_bytes()
                    if offset==0x8000:
                        self.assertTrue(app_verified)
                        if cut:raise RuntimeError('simulated power interruption before table commit')
                    guard.validate_write(offset,len(data),app_offset=0x500000,app_capacity=0x400000,table=offset==0x8000)
                    writes.append(offset);memory[offset:offset+len(data)]=data
                    if corrupt and offset==0x500000:memory[0x400000]^=1
            with patch('tools.install_preserving_storage.subprocess.run',side_effect=fake):
                if cut or corrupt or short_read:
                    with self.assertRaises(RuntimeError):install('esptool',{'address':'COM5'},info,old,root/'backups')
                    receipt=next((root/'backups').glob('*/preservation.json'))
                    self.assertFalse(__import__('json').loads(receipt.read_text())['verified'])
                    if cut:self.assertEqual(memory[0x8000:0x8C00],old)
                    if short_read:self.assertEqual(writes,[])
                else:
                    receipt=install('esptool',{'address':'COM5'},info,old,root/'backups')
                    result=__import__('json').loads(receipt.read_text())
                    self.assertTrue(result['verified']);self.assertEqual(result['protected_after'],originals)
                    self.assertEqual(writes,[0x500000,0x8000])
                    # Saved artifacts must contain only firmware/table metadata and hashes.
                    self.assertEqual({p.name for p in receipt.parent.iterdir()},
                                     {'partition-before.bin','partition-after.bin','preservation.json'})

    def test_verified_migration(self):self.simulate_install()
    def test_storage_corruption_stops_install(self):self.simulate_install(corrupt=True)
    def test_interruption_keeps_old_table(self):self.simulate_install(cut=True)
    def test_incomplete_storage_digest_prevents_every_write(self):self.simulate_install(short_read=True)


if __name__ == '__main__':unittest.main()
