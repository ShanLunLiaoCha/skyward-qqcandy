import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TOOLS))
import repack_only as repack
import vendor_boot as vb

class PackagingPolicy(unittest.TestCase):
    def test_strip_versions_retains_adb_policy_and_sdk(self):
        raw=b'ro.build.version.release=12\nro.vendor.build.security_patch=2022-09-05\nro.build.version.sdk=31\nro.adb.secure=1\nro.debuggable=0\n'
        after=repack.strip_versions(raw)
        self.assertNotIn(b'ro.build.version.release=',after)
        self.assertNotIn(b'ro.vendor.build.security_patch=',after)
        self.assertIn(b'ro.build.version.sdk=31',after)
        self.assertIn(b'ro.adb.secure=1',after)
        self.assertIn(b'ro.debuggable=0',after)
    def test_existing_packaging_helper_uses_max_legacy_lz4(self):
        from unittest.mock import patch
        calls=[]
        def capture(command,**kwargs):
            calls.append(command)
            kwargs['stdout'].write(bytes.fromhex('02214c18')+b'compressed')
        with patch.object(vb.subprocess,'run',side_effect=capture):
            vb.compress_ramdisk(b'archive','lz4-legacy')
        command=calls[0]
        self.assertIn('-12',command)
        self.assertIn('-l',command)
    def test_no_compiler_or_device_tools_in_command_execution_path(self):
        text=(TOOLS/'repack_only.py').read_text(encoding='utf-8')
        self.assertNotIn('subprocess.run(',text)
        self.assertNotIn('os.system(',text)
        self.assertNotIn('eval(',text)
    def test_payload_donor_hashes_are_checked_and_extra_files_not_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);files={}
            for name in ('system/bin/recovery',)+repack.ASSETS:
                data=('fixture:'+name).encode();p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
                files[name]=hashlib.sha256(data).hexdigest()
            (root/'manifest.json').write_text(json.dumps({'files':files}))
            (root/'not-an-injected-key').write_text('not selected')
            source,name,info=repack.load_donor(root,'unused-lz4')
            self.assertEqual(set(source),set(files));self.assertEqual(name,'system/bin/recovery')
            (root/'skyward/device.toml').write_bytes(b'changed')
            with self.assertRaisesRegex(vb.FormatError,'hash/size'):repack.load_donor(root,'unused-lz4')
    def test_output_collision_fails_before_reading_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);target=root/'stock.img';target.write_bytes(b'original')
            report=root/'report.json';out=root/'out.img';out.write_bytes(b'keep me')
            result=repack.main(['--target',str(target),'--donor',str(root/'no-donor.img'),'--out',str(out),'--report',str(report),'--same-device-pgz110'])
            self.assertEqual(result,2);self.assertEqual(target.read_bytes(),b'original');self.assertEqual(out.read_bytes(),b'keep me')

if __name__=='__main__':unittest.main()
