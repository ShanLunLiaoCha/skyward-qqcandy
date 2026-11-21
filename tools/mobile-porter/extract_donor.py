"""Extract the pinned 1600 Fix64 Recovery resources, not target-specific hardware."""
from pathlib import Path
import hashlib
import sys

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / 'skyward-pgz110/tools'))
from vendor_boot import VendorBoot, CpioArchive, decompress_ramdisk

DONOR = root / 'skyward-pgz110/prebuilt/vendor_boot-OP5911-1600-FIX64.img'
EXPECTED = 'b7eacc755be3418485b3f9c93c5eca5435baf160c94212e8c60aaa8cc960c086'
ELF = '5fa9bfcc7ffb05796fceadcd65b6f3ff482655280ebe18778b62df5955a421c6'
NAMES = ('system/bin/recovery', 'skyward/device.toml', 'skyward/MiSansVF.ttf',
         'skyward/KirkMono-Regular.ttf', 'skyward/KirkMono-OFL.txt', 'system/etc/init/skyward-mtp.rc',
         'skyward/my_company.img', 'skyward/my_preload.img')

def sha(data):
    return hashlib.sha256(data).hexdigest()

if __name__ == '__main__':
    destination = Path(sys.argv[1]); destination.mkdir(parents=True, exist_ok=False)
    image = DONOR.read_bytes()
    if sha(image) != EXPECTED:
        raise SystemExit('Wrong donor image SHA-256')
    boot = VendorBoot(image)
    if len(boot.fragments) != 1:
        raise SystemExit('Expected one donor ramdisk')
    paths = CpioArchive(decompress_ramdisk(boot.fragments[0].data)).validate_paths()
    if sha(paths[NAMES[0]].data) != ELF:
        raise SystemExit('Wrong Recovery ELF SHA-256')
    for name in NAMES:
        payload = paths[name].data
        if not payload:
            raise SystemExit(f'Empty donor resource: {name}')
        out = destination / 'donor' / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(payload)
        print(sha(payload), name)
    (destination / 'LICENSE-Skyward.txt').write_bytes((root / 'skyward-source/LICENSE').read_bytes())
    (destination / 'LICENSE-MiSans.txt').write_bytes((Path(__file__).parent / 'LICENSE-MiSans.txt').read_bytes())
