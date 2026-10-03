"""Reviewed sector boundaries; whole-flash erase is never an accepted operation."""
import hashlib
import struct
SECTOR = 0x1000
FLASH_SIZE = 0x1000000
PROTECTED = {'nvs': (0x9000, 0x5000), 'otadata': (0xE000, 0x2000),
             'part0': (0x200000, 0x100000), 'wsdev': (0x400000, 0x10000)}
APP_LAYOUTS = {(0x10000, 0x1F0000), (0x500000, 0x400000)}


def parse_table(data):
    if len(data)!=0xC00:
        raise RuntimeError('Unexpected partition image length')
    entries={};valid_digest=False
    for at in range(0,len(data),32):
        record=data[at:at+32]
        magic,=struct.unpack_from('<H',record)
        if magic==0xEBEB:
            if record[16:]!=hashlib.md5(data[:at]).digest():
                raise RuntimeError('Partition table MD5 mismatch')
            valid_digest=True
            if data[at+32:]!=b'\xff'*(len(data)-at-32):
                raise RuntimeError('Unexpected trailing partition records')
            break
        if magic!=0x50AA:
            raise RuntimeError('Missing partition record/checksum')
        _,kind,subtype,address,length,label,flags=struct.unpack('<HBBII16sI',record)
        name=label.split(b'\0',1)[0].decode('ascii')
        if name in entries:raise RuntimeError('Duplicate partition label')
        entries[name]=(kind,subtype,address,length,flags)
    if not valid_digest:raise RuntimeError('Partition table is missing its checksum')
    required={'nvs':(1,2,0x9000,0x5000,0),'otadata':(1,0,0xE000,0x2000,0),
              'part0':(0x40,1,0x200000,0x100000,0),'wsdev':(1,2,0x400000,0x10000,0)}
    if set(entries)!=set(required)|{'factory'}:
        raise RuntimeError('Unreviewed partition set')
    for name,expected in required.items():
        if entries[name]!=expected:raise RuntimeError('Protected partition changed: '+name)
    app=entries['factory']
    if app[:2]!=(0,0) or app[4]!=0 or app[2:4] not in APP_LAYOUTS:
        raise RuntimeError('Unreviewed factory layout')
    return app[2:4]


def validate_write(offset, size, *, app_offset=0x10000, app_capacity=0x1F0000, table=False):
    if (app_offset, app_capacity) not in APP_LAYOUTS:
        raise RuntimeError('Unreviewed application layout')
    if not isinstance(offset, int) or not isinstance(size, int) or size <= 0 or offset < 0:
        raise RuntimeError('Invalid flash write range')
    start = offset // SECTOR * SECTOR
    end = (offset + size + SECTOR - 1) // SECTOR * SECTOR
    if end > FLASH_SIZE:
        raise RuntimeError('Write exceeds physical flash')
    for name, (address, length) in PROTECTED.items():
        if start < address + length and end > address:
            raise RuntimeError('Sector erase/write would overlap protected ' + name)
    if table:
        if offset != 0x8000 or size != 0xC00 or (start, end) != (0x8000, 0x9000):
            raise RuntimeError('Only the partition table sector may be migrated')
    elif offset != app_offset or end > app_offset + app_capacity:
        raise RuntimeError('Write must be bounded by the reviewed application partition')
    return start, end


def validate_command(command):
    if any(str(item).replace('_', '-').lower() in ('erase-flash', 'erase-region', '--erase-all') for item in command):
        raise RuntimeError('Flash erase command is forbidden')
