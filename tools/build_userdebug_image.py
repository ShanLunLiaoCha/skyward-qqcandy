#!/usr/bin/env python3
"""Build PGZ110 userdebug instrumentation on a clean stock vendor_boot.
Preserves full Recovery; uses an explicitly supplied public ADB host key.
Never reads a private key or writes any attached device.
"""
import argparse,base64,hashlib,json,pathlib,struct,sys
import vendor_boot as vb

USERDEBUG={'ro.build.type':'userdebug','ro.system.build.type':'userdebug',
 'ro.build.tags':'test-keys','ro.system.build.tags':'test-keys',
 'ro.secure':'0','ro.adb.secure':'0','ro.debuggable':'1',
 'persist.sys.usb.config':'adb','sys.usb.config':'adb',
 'persist.adb.trace_mask':'auth,transport,usb','log.tag.adbd':'VERBOSE',
 'log.tag.init':'DEBUG','persist.logd.size':'4M'}

def properties(data):
 text=data.decode('utf-8');lines=[]
 for line in text.splitlines():
  name=line.split('=',1)[0].strip()
  if name not in USERDEBUG:lines.append(line)
 return ('\n'.join(lines)+'\n'+''.join(k+'='+v+'\n' for k,v in USERDEBUG.items())).encode()

def public_key(data):
 text=data.decode('ascii').strip();words=text.split()
 if len(words)<1 or '\n' in text or 'PRIVATE KEY' in text:raise vb.FormatError('requires one public adbkey.pub line, never a private key')
 try:raw=base64.b64decode(words[0],validate=True)
 except Exception as e:raise vb.FormatError('invalid public ADB key encoding') from e
 if len(raw)!=524 or struct.unpack_from('<I',raw)[0]!=64:raise vb.FormatError('expected Android RSA2048 public key format')
 return (text+'\n').encode(),hashlib.sha256(raw).hexdigest()

def instrument(raw,binary,key,logd_runtime=None):
 image=vb.VendorBoot(raw);rd=vb.CpioArchive(vb.decompress_ramdisk(image.fragments[0].data));paths=rd.validate_paths()
 keyline,fingerprint=public_key(key)
 # Public-key preauthorization is effective even on OEM adbd compiled with
 # authentication always required. The stock daemon reads /adb_keys.
 rd.replace('adb_keys',keyline,0o644)
 updated_props=[]
 for name,entry in list(paths.items()):
  if name=='prop.default' or name.endswith('/prop.default') or name.endswith('/build.prop') or name.endswith('/default.prop'):
   if entry.mode & 0o170000 == 0o100000:
    rd.replace(name,properties(entry.data));updated_props.append(name)
 init='system/etc/init/hw/init.rc';text=paths[init].data.decode('utf-8')
 old='service recovery /system/bin/recovery\n'
 if text.count(old)!=1:raise vb.FormatError('unrecognised recovery service template')
 text=text.replace(old,'service recovery /system/bin/sh /system/bin/skyward-userdebug-recovery.sh\n',1)
 # Keep stock USB and all normal services. Start logd/collector independently
 # before boot's class_start default starts the Recovery service.
 text+='\n# PGZ110 userdebug: early logs independent of Recovery/DRM\non post-fs\n    start logd\n    start adbd\n    start skyward-userdebug-logger\n\nservice skyward-userdebug-logger /system/bin/sh /system/bin/skyward-userdebug-logger.sh\n    class core\n    user root\n    group root system log shell readproc\n    disabled\n    seclabel u:r:recovery:s0\n'
 tools=pathlib.Path(__file__).resolve().parent
 logd_status='not supplied'
 if logd_runtime is not None:
  manifest=json.loads((tools/'logd-runtime-manifest.json').read_text(encoding='utf-8'))
  for record in manifest['files']:
   relative=pathlib.PurePosixPath(record['path'])
   if relative.is_absolute() or '..' in relative.parts:raise vb.FormatError('unsafe logd runtime manifest path')
   source=pathlib.Path(logd_runtime).joinpath(*relative.parts)
   if source.is_symlink():raise vb.FormatError('logd runtime must use dereferenced fixed files')
   data=source.read_bytes()
   if len(data)!=record['bytes'] or hashlib.sha256(data).hexdigest()!=record['sha256']:raise vb.FormatError('logd runtime hash mismatch: '+record['path'])
   rd.replace('skyward/logd-runtime/'+record['path'],data,int(record['mode'],8))
  oldlog='service logd /system/bin/logd\n'
  if text.count(oldlog)!=1:raise vb.FormatError('unrecognised original logd service')
  text=text.replace(oldlog,'service logd /skyward/logd-runtime/bin/linker64 /skyward/logd-runtime/bin/logd\n    setenv LD_LIBRARY_PATH /skyward/logd-runtime/lib64\n',1)
  # Keep the service's original socket/group/SELinux options unchanged.
  if 'system/etc/task_profiles.json' not in paths:
   profiles=(tools/'task_profiles.json').read_bytes();json.loads(profiles)
   rd.replace('system/etc/task_profiles.json',profiles,0o644)
  logd_status='isolated matched logd+linker+bionic runtime, hash/version checked; original log sockets retained'
 rd.replace(init,text.encode())
 rd.replace('system/bin/skyward-userdebug-recovery.sh',(tools/'userdebug-recovery.sh').read_bytes(),0o755)
 rd.replace('system/bin/skyward-userdebug-logger.sh',(tools/'userdebug-logger.sh').read_bytes(),0o755)
 out=image.repack(0,vb.compress_ramdisk(rd.encode(),vb.compression(image.fragments[0].data)))
 return out,{'public_key_sha256':fingerprint,'private_key_read':False,'properties_patched':updated_props,
 'recovery_service':'stock init -> sh wrapper -> /system/bin/recovery (basename dispatch)',
 'log_directory':'/tmp/skyward-userdebug','normal_recovery_workflow_retained':True,'logd_runtime':logd_status,
 'auth_policy':'ro.adb.secure=0 plus explicit /adb_keys public-key preauthorization; OEM compile-time auth may remain enabled'}

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for name in ['stock','binary','config','font','mono','mono-license','adb-public-key','avbtool','out','report']:ap.add_argument('--'+name,required=True,type=pathlib.Path)
 ap.add_argument('--logd-runtime',type=pathlib.Path)
 a=ap.parse_args();stock=vb.VendorBoot(a.stock.read_bytes());binary=a.binary.read_bytes()
 raw,report=vb.patch_recovery(stock,binary,a.config.read_bytes(),a.font.read_bytes(),a.mono.read_bytes(),a.mono_license.read_bytes(),allow_unified_platform_fragment=True)
 raw,debug=instrument(raw,binary,a.adb_public_key.read_bytes(),a.logd_runtime);report.update(debug)
 report.update(vb.finalize_image(raw,stock,a.out,a.avbtool))
 report['image_sha256']=hashlib.sha256(a.out.read_bytes()).hexdigest();report['binary_sha256']=hashlib.sha256(binary).hexdigest()
 a.report.write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
