"""Reject cross-board, incomplete and stale public release input before packaging."""
import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
SPEC=importlib.util.spec_from_file_location('public_package',Path(__file__).resolve().parents[1]/'scripts/package_public_release.py')
PACKAGE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(PACKAGE)

class PublicPackage(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        p=self.root/'firmware/EvilKeyV1/src/pf_firmware_version.h';p.parent.mkdir(parents=True)
        p.write_text('#define PF_FIRMWARE_VERSION_MAJOR 0\n#define PF_FIRMWARE_VERSION_MINOR 8\n#define PF_FIRMWARE_VERSION_PATCH 0\n')
        self.record={'firmware':{'version':'0.8.0','build_inputs_sha256':'a'*64,'hardware_variants':[]}}
        for revision,number in [('v1','10'),('v1.1','11')]:
            v={'board_revision':revision,'version':'0.8.0','device_acceptance':'functional_validation_passed'}
            for key,hkey,payload in [('artifact','sha256',revision.encode()*32),('elf_artifact','elf_sha256',b'fixture ELF'),('partition_artifact','partition_sha256',b'P'*3072),('bootloader_artifact','bootloader_sha256',b'boot fixture')]:
                p=self.root/(revision+'-'+key);p.write_bytes(payload)
                v[key]=p.name;v[hkey]=hashlib.sha256(payload).hexdigest()
                Path(str(p)+'.sha256').write_text(v[hkey]+'  '+p.name+'\n')
            v['size_bytes']=(self.root/v['artifact']).stat().st_size
            self.record['firmware']['partition_sha256']=v['partition_sha256']
            info={'schema':'evilkey-arduino-build-v1','board_revision':revision,'board_define':'-DEVILKEY_BOARD_REVISION='+number,'apps_vm_link_probe':False,'nvs_guard':'link-wrap-v1','erase_flash':'none','build_inputs_sha256':'a'*64,'app_offset':0x500000,'app_capacity':0x400000,'image_size':v['size_bytes'],'bootloader_size':len(b'boot fixture')}
            info.update({a:v[b] for a,b in [('image_sha256','sha256'),('elf_sha256','elf_sha256'),('partition_sha256','partition_sha256'),('bootloader_sha256','bootloader_sha256')]})
            p=self.root/(revision+'.build.json');p.write_text(json.dumps(info));v['build_manifest']=p.name;v['build_manifest_sha256']=PACKAGE.digest(p)
            self.record['firmware']['hardware_variants'].append(v)
    def test_both_profile_sets(self):
        self.assertEqual(len(PACKAGE.validate(self.root,self.record)),18)
    def test_missing_new_board(self):
        (self.root/self.record['firmware']['hardware_variants'][1]['artifact']).unlink()
        with self.assertRaises(RuntimeError):PACKAGE.validate(self.root,self.record)
    def test_corrupted_old_board(self):
        (self.root/self.record['firmware']['hardware_variants'][0]['artifact']).write_bytes(b'corrupt')
        with self.assertRaises(RuntimeError):PACKAGE.validate(self.root,self.record)
    def test_wrong_board_build_record(self):
        v=self.record['firmware']['hardware_variants'][1];p=self.root/v['build_manifest'];m=json.loads(p.read_text());m['board_define']='-DEVILKEY_BOARD_REVISION=10';p.write_text(json.dumps(m));v['build_manifest_sha256']=PACKAGE.digest(p)
        with self.assertRaises(RuntimeError):PACKAGE.validate(self.root,self.record)
    def test_duplicate_board(self):
        self.record['firmware']['hardware_variants'][1]['board_revision']='v1'
        with self.assertRaises(RuntimeError):PACKAGE.validate(self.root,self.record)
    def test_source_version_mismatch(self):
        self.record['firmware']['version']='0.7.6'
        with self.assertRaises(RuntimeError):PACKAGE.validate(self.root,self.record)
    def test_bad_sidecar(self):
        v=self.record['firmware']['hardware_variants'][0];Path(str(self.root/v['artifact'])+'.sha256').write_text('bad')
        with self.assertRaises(RuntimeError):PACKAGE.validate(self.root,self.record)
    def test_legacy_single_image(self):
        v=self.record['firmware']['hardware_variants'][0];self.record['firmware']={'version':'0.8.0','artifact':v['artifact'],'sha256':v['sha256'],'size_bytes':v['size_bytes']}
        self.assertEqual(len(PACKAGE.validate(self.root,self.record)),1)

if __name__=='__main__':unittest.main()
