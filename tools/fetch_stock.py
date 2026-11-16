import argparse,json,pathlib,shutil,sys
from inspect_ota import OUT,main as inspect
from extract_ota import main as extract

def run():
 ap=argparse.ArgumentParser(description='Extract fixed official PGZ110 OTA, verified by payload operation and partition SHA256.')
 ap.add_argument('--out',type=pathlib.Path,required=True)
 ap.add_argument('--with-vendor',action='store_true',help='also extract vendor/odm/vendor_dlkm for offline analysis (large)')
 a=ap.parse_args()
 if not (OUT/'payload-summary.json').exists():inspect()
 summary=json.loads((OUT/'payload-summary.json').read_text())
 metadata=(OUT/'META-INF_com_android_metadata').read_text()
 if 'pre-device=OP5911' not in metadata or 'product_name=PGZ110' not in metadata:raise ValueError('wrong OTA identity')
 names=['boot','vendor_boot','dtbo']+(['vendor','odm','vendor_dlkm'] if a.with_vendor else [])
 sys.argv=['extract_ota.py',*names];extract();a.out.mkdir(parents=True,exist_ok=True)
 for name in names:
  dest=a.out/f'{name}.img'
  if dest.exists():raise FileExistsError(f'Refuse to overwrite {dest}')
  shutil.copyfile(OUT/'images'/f'{name}.img',dest)
 for name in ['payload-summary.json','vendor_boot-layout.json','META-INF_com_android_metadata','payload_properties.txt']:
  if (OUT/name).exists():shutil.copyfile(OUT/name,a.out/name)
 print('Verified extraction complete; no device was flashed.')
if __name__=='__main__':run()
