# SPDX-License-Identifier: MIT
"""Mandatory launcher metadata and integrity at the public SDK boundary."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest

spec=importlib.util.spec_from_file_location('pack',Path(__file__).parent/'sdk/pack_ekapp.py')
sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)

class PackageTests(unittest.TestCase):
    def encode(self,**changes):
        args=dict(program=b'\0asm\1\0\0\0',blob=b'',app_id='test.app',owner='Michał Wojciechowski',
                  license_id='MIT',version='1.2.3',name='Readable app name',image=bytes(8192),ui_profile="corner-exit-v1")
        args.update(changes);return sdk.encode_package(**args)
    def test_header_offsets_and_hashes(self):
        data=self.encode();self.assertEqual(len(data),8520)
        self.assertEqual(struct.unpack_from('<HHH',data,8),(320,5,4))
        self.assertEqual(data[192:256].split(b'\0')[0],b'Readable app name')
        self.assertEqual(data[256:288],hashlib.sha256(data[320:8512]).digest())
        self.assertEqual(data[58:90],hashlib.sha256(data[8512:]).digest())
        self.assertEqual(data[8512:8520],b'\0asm\1\0\0\0')
    def test_required_name_and_exact_icon_size(self):
        for name in ('','   ','x'*64,'bad\nname','bad\x80name'):
            with self.assertRaises(ValueError):self.encode(name=name)
        for n in (0,8191,8193,16384):
            with self.assertRaises(ValueError):self.encode(image=bytes(n))
    def test_utf8_byte_limit(self):
        with self.assertRaises(ValueError):self.encode(name='ą'*32)
        self.encode(name='ą'*31)
    def test_icon_does_not_change_guest_payload_or_save_id(self):
        a=self.encode();b=self.encode(image=b'\1'*8192,name='Different display name')
        self.assertEqual(a[22:54],b[22:54]);self.assertEqual(a[8512:],b[8512:])
        self.assertNotEqual(a[256:288],b[256:288])
    def test_explicit_corner_profile(self):
        for value in ('', 'legacy', None, 1):
            with self.assertRaises(ValueError):self.encode(ui_profile=value)
        data=self.encode()
        self.assertEqual(data[288:290],b'\1\0')
        self.assertEqual(data[290:320],bytes(30))

if __name__=='__main__':unittest.main()
