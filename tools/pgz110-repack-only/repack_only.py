#!/usr/bin/env python3
"""PGZ110 repack-only: target stock vendor_boot + a working Skyward donor.
Never invokes a compiler, cargo, NDK, fastboot or adb. Python3.11+, lz4 and
avbtool are packaging dependencies, not build toolchains.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import tomllib
import vendor_boot as vb
import repack_init

ASSETS = ('skyward/device.toml','skyward/MiSansVF.ttf',
          'skyward/KirkMono-Regular.ttf','skyward/KirkMono-OFL.txt')
RELEASE_KEYS = ('ro.build.version.release','ro.build.version.release_or_codename',
                'ro.build.version.security_patch','ro.vendor.build.security_patch')

def digest(data): return hashlib.sha256(data).hexdigest()

def recovery_archive(image, lz4):
    matches=[]
    for fragment in image.fragments:
        if not fragment.size: continue
        archive=vb.CpioArchive(vb.decompress_ramdisk(fragment.data,lz4))
        paths=archive.validate_paths()
        for name in ('system/bin/recovery','sbin/recovery'):
            if name in paths: matches.append((fragment,archive,paths,name))
    if len(matches)!=1: raise vb.FormatError('expected exactly one Recovery ramdisk/program')
    fragment,archive,paths,name=matches[0]
    if name!='system/bin/recovery' or not stat.S_ISREG(paths[name].mode): raise vb.FormatError('unsupported/non-regular Recovery program layout')
    if image.version!=4 or len(image.fragments)!=1 or fragment.type not in (1,2):
        raise vb.FormatError('only audited v4 single PLATFORM/RECOVERY fragment layouts are supported')
    if vb.compression(fragment.data)!='lz4-legacy':
        raise vb.FormatError('only legacy LZ4 ramdisks are supported by this profile')
    return matches[0]

def strip_versions(data):
    # Deliberately NOT vb.patch_properties: retain target ADB/security policy.
    text=data.decode('utf-8')
    lines=[]
    for line in text.splitlines():
        key=line.split('=',1)[0].strip()
        if key.startswith('ro.') and (key.endswith('build.version.release') or
            key.endswith('build.version.release_or_codename') or
            key.endswith('build.version.security_patch') or key.endswith('build.security_patch')):
            continue
        lines.append(line)
    return ('\n'.join(lines)+'\n').encode()

def properties(paths):
    result={}
    for name in ('prop.default','system/build.prop','vendor/build.prop'):
        if name in paths:
            for line in paths[name].data.decode('utf-8').splitlines():
                if line.strip().startswith('#') or '=' not in line:continue
                key,value=line.split('=',1);result[key.strip()]=value.strip()
    return result

def load_donor(path,lz4):
    if path.is_dir():
        from types import SimpleNamespace
        manifest_path=path/'manifest.json'
        manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
        source={}
        for name in ('system/bin/recovery',)+ASSETS:
            file=path.joinpath(*name.split('/'))
            for ancestor in (file,)+tuple(file.parents):
                if ancestor==path.parent:break
                if ancestor.is_symlink():raise vb.FormatError('donor payload contains a symlink')
            data=file.read_bytes()
            if len(data)>128*1024*1024 or digest(data)!=manifest.get('files',{}).get(name):
                raise vb.FormatError('donor payload hash/size mismatch: '+name)
            source[name]=SimpleNamespace(data=data,mode=0o100755 if name=='system/bin/recovery' else 0o100644)
        return source,'system/bin/recovery',dict(path=str(path),payload_manifest_sha256=digest(manifest_path.read_bytes()),origin=manifest.get('origin'))
    image=vb.VendorBoot(path.read_bytes())
    _,_,source,name=recovery_archive(image,lz4)
    return source,name,dict(path=str(path),sha256=digest(image.data))

def prepare(target,source,donor_program,lz4):
    tf,archive,original,program=recovery_archive(target,lz4)
    props=properties(original)
    if props.get('ro.product.board') not in ('k6895v1_64','mgvi_64_armv82'):
        raise vb.FormatError('target does not identify the audited MT6895 board family')
    # Board family alone is not proof of PGZ110. Require the caller's explicit
    # same-model acknowledgement as well, and preserve target hardware bytes.
    for asset in ASSETS:
        if asset not in source or not stat.S_ISREG(source[asset].mode):
            raise vb.FormatError('donor lacks a regular required asset: '+asset)
    cfg=tomllib.loads(source['skyward/device.toml'].data.decode('utf-8'))
    if cfg.get('device',{}).get('codename')!='OP5911':
        raise vb.FormatError('donor is not the OP5911 profile')
    vb.validate_port_config(source['skyward/device.toml'].data)
    elf=vb.validate_arm64_elf(source[donor_program].data)
    changes,audit=repack_init.adapt(original)
    for name,data in changes.items():archive.replace(name,data)
    archive.replace(program,source[donor_program].data,0o755)
    for asset in ASSETS:archive.replace(asset,source[asset].data,source[asset].mode)
    mtp='system/etc/init/skyward-mtp.rc'
    if mtp in original:raise vb.FormatError('target is already patched; use a clean stock image')
    archive.replace(mtp,Path(__file__).with_name('skyward-mtp.rc').read_bytes(),0o644)
    changed_props=[]
    for name,entry in original.items():
        if stat.S_ISREG(entry.mode) and (name=='prop.default' or name.endswith(('/build.prop','/default.prop','/prop.default'))):
            updated=strip_versions(entry.data)
            if updated!=entry.data:archive.replace(name,updated);changed_props.append(name)
    notes=[
      'Packaging only is NOT runtime compatibility certification.',
      'Use matching target boot/dtbo/vendor/odm/modules; do not mix donor kernel or modules.',
      'Vendor_boot alone cannot validate installed VNDK/APEX identity, TEE HAL ABI or calibration protocol.',
      'Target security/ADB properties are retained; donor adb_keys/private keys and debug authentication policy are NOT copied.',
      'No donor libraries, modules, DTB, firmware or logd runtime are transplanted.',
      'Stock init may write persist and run repair actions; this is not a read-only Recovery.',
      'Destructive wipe behavior comes from donor executable; review donor documentation before use.',
    ]
    runtime_gates=[]
    if 'service mobicore ' in original['system/etc/init/hw/init.rc'].data.decode('utf-8'):
        runtime_gates.append('Legacy FBE/TEE/WLAN init family detected: existing donor has not been validated on this family. A09 installed system uses vndk.current and system/bin hwservicemanager; this repacker cannot add support to an executable.')
    if 'system/bin/logd' not in original:
        notes.append('Target has no stock logd binary; retained as absent. Provide a separately audited target-matched runtime if full logcat is required; not silently copied from donor.')
    else:notes.append('Stock target logd is retained, not replaced by donor runtime.')
    return tf,archive,original,dict(target_properties=props,donor_binary_elf=elf,
        donor_binary_sha256=digest(source[donor_program].data),init_actions=audit,
        properties_cleaned=changed_props,notes=notes,runtime_gates=runtime_gates)

def verify_output(target,output,old_paths,lz4,report):
    _,_,new_paths,_=recovery_archive(output,lz4)
    if output.dtb!=target.dtb or output.bootconfig!=target.bootconfig:
        raise vb.FormatError('hardware DTB/bootconfig changed unexpectedly')
    if output.fragments[0].table_entry[8:]!=target.fragments[0].table_entry[8:]:
        raise vb.FormatError('fragment type/name/board IDs changed')
    modules=[n for n in old_paths if n.startswith('lib/modules/')]
    for n in modules:
        if n not in new_paths or new_paths[n].raw!=old_paths[n].raw:
            raise vb.FormatError('original module/metadata record altered: '+n)
    for n in old_paths:
        if n not in new_paths:raise vb.FormatError('original ramdisk entry removed: '+n)
    expected={'system/etc/init/hw/init.rc','system/bin/recovery'}|set(report['properties_cleaned'])
    for n in old_paths:
        if n not in expected and n not in ASSETS and old_paths[n].raw!=new_paths[n].raw:
            raise vb.FormatError('unplanned stock record change: '+n)
    if digest(new_paths['system/bin/recovery'].data)!=report['donor_binary_sha256']:
        raise vb.FormatError('output does not contain the exact donor executable')
    vb.verify_unsigned_avb(output.data,output.footer)
    return dict(dtb_preserved=True,bootconfig_preserved=True,fragment_identity_preserved=True,
        stock_module_records_unchanged=len(modules),stock_records_retained=len(old_paths),
        exact_donor_executable=True,unplanned_changes=False,new_unsigned_avb_verified=True)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',required=True,type=Path,help='clean matching STOCK vendor_boot.img')
    p.add_argument('--donor',required=True,type=Path,help='existing Skyward vendor_boot.img or verified donor payload directory; no compilation')
    p.add_argument('--out',type=Path)
    p.add_argument('--report',required=True,type=Path)
    p.add_argument('--avbtool',type=Path)
    p.add_argument('--lz4',default='lz4')
    p.add_argument('--inspect-only',action='store_true')
    p.add_argument('--same-device-pgz110',action='store_true',help='explicitly confirm target belongs to the SAME PGZ110')
    p.add_argument('--allow-unverified-runtime',action='store_true',help='output a clearly UNTESTED candidate despite known runtime gates')
    args=p.parse_args(argv)
    report={'schema':1,'operation':'REPACK ONLY','compiler_invoked':False,'flash_invoked':False,
        'compression':{'format':'lz4-legacy','level':12,'command':'lz4 -12 -l -c'},'status':'FAILED'}
    try:
        if not args.same_device_pgz110:raise vb.FormatError('--same-device-pgz110 required; board name is not model verification')
        if args.report.exists():raise vb.FormatError('report exists; refuse overwrite')
        if args.out and args.out.exists():raise vb.FormatError('output exists; refuse overwrite')
        inputs=(args.target.resolve(),args.donor.resolve())
        if args.report.resolve() in inputs or (args.out and args.report.resolve()==args.out.resolve()):
            raise vb.FormatError('report must be distinct from inputs and image output')
        if args.out and args.out.resolve() in inputs:raise vb.FormatError('output aliases input')
        target=vb.VendorBoot(args.target.read_bytes())
        source,donor_program,donor_info=load_donor(args.donor,args.lz4)
        report.update(target={'path':str(args.target),'sha256':digest(target.data),'layout':target.inspect()},donor=donor_info)
        fragment,archive,original,detail=prepare(target,source,donor_program,args.lz4);report.update(detail)
        if args.inspect_only:
            report['status']='ANALYZED; NO IMAGE WRITTEN'
        else:
            if not args.out or not args.avbtool:raise vb.FormatError('build requires --out and --avbtool')
            if report['runtime_gates'] and not args.allow_unverified_runtime:
                raise vb.FormatError('known runtime gate; read report. Repacking cannot implement missing runtime support. Use --allow-unverified-runtime ONLY for an offline candidate.')
            # vendor_boot.compress_ramdisk pins legacy LZ4 to -12 -l. Never use
            # ordinary fast compression or remove essential assets to fit.
            compressed=vb.compress_ramdisk(archive.encode(),'lz4-legacy',args.lz4)
            raw=target.repack(fragment.index,compressed)
            with tempfile.TemporaryDirectory(prefix='skyward-repack-') as tmp:
                final=Path(tmp)/'vendor_boot.img'
                finalized=vb.finalize_image(raw,target,final,args.avbtool)
                output=vb.VendorBoot(final.read_bytes())
                report['verification']=verify_output(target,output,original,args.lz4,report)
                report['finalized']=finalized
                report['output_sha256']=digest(output.data)
                report['output_bytes']=len(output.data)
                report['payload_bytes']=output.payload_end
                report['remaining_bytes_in_partition']=len(output.data)-output.payload_end
                vb.safe_write(args.out,output.data)
            report['status']='PACKED; UNTESTED RUNTIME CANDIDATE'
        vb.safe_write(args.report,(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
        print(json.dumps({key:report[key] for key in ('status','compression','runtime_gates','output_bytes','payload_bytes','output_sha256','verification') if key in report},ensure_ascii=False,indent=2));return 0
    except (ValueError,OSError,KeyError) as error:
        report['error']=str(error)
        if not args.report.exists():
            try:vb.safe_write(args.report,(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
            except (ValueError,OSError):pass
        print('ERROR: '+str(error),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
