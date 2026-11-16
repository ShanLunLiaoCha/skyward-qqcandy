#!/usr/bin/env python3
"""Conservative experimental vendor_boot v3/v4 editor (Python standard library).

This is packaging scaffolding, NOT an Android 17 decryption implementation.
Untouched image sections, table extensions and CPIO records are retained byte for
byte. Modified images never retain the stock AVB signature/footer. lz4 is optional
and external; install it yourself. No extraction of archive-controlled paths.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass


class FormatError(ValueError):
    """Unsupported, ambiguous or corrupt input: refuse rather than guess."""


def align(value, page):
    return (value + page - 1) // page * page


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def safe_name(name):
    # CPIO paths are POSIX; backslashes and Windows drive names are never paths.
    while name.startswith('./'):
        name = name[2:]
    if name == '.':
        return ''
    if not name or name.startswith('/') or '\\' in name or ':' in name:
        raise FormatError('unsafe archive path: ' + repr(name))
    if any(part in ('', '.', '..') for part in name.split('/')):
        raise FormatError('unsafe archive path: ' + repr(name))
    return name


@dataclass
class CpioEntry:
    name: str
    fields: list
    data: bytes
    raw: bytes = b''
    magic: bytes = b'070701'
    changed: bool = False

    @property
    def mode(self):
        return self.fields[1]

    @property
    def hardlink_key(self):
        return (self.fields[0], self.fields[7], self.fields[8])

    def encode(self):
        if self.raw and not self.changed:
            return self.raw
        fields = list(self.fields)
        name = self.name.encode('utf-8', 'surrogateescape') + b'\0'
        fields[6], fields[11] = len(self.data), len(name)
        fields[12] = sum(self.data) & 0xffffffff if self.magic == b'070702' else 0
        header = self.magic + b''.join(('%08x' % n).encode() for n in fields)
        result = header + name
        result += b'\0' * (-len(result) % 4)
        result += self.data
        return result + b'\0' * (-len(result) % 4)


class CpioArchive:
    def __init__(self, data):
        self.entries = []
        pos = 0
        while True:
            start = pos
            if pos + 110 > len(data) or data[pos:pos+6] not in (b'070701', b'070702'):
                raise FormatError('expected newc/crc CPIO header at %d' % pos)
            magic = data[pos:pos+6]
            try:
                fields = [int(data[pos+6+i*8:pos+14+i*8], 16) for i in range(13)]
            except ValueError as exc:
                raise FormatError('invalid CPIO numeric header') from exc
            size, namesize = fields[6], fields[11]
            pos += 110
            if namesize < 1 or pos + namesize > len(data):
                raise FormatError('invalid CPIO name length')
            rawname = data[pos:pos+namesize]
            if rawname[-1:] != b'\0' or b'\0' in rawname[:-1]:
                raise FormatError('invalid CPIO name termination')
            name = rawname[:-1].decode('utf-8', 'surrogateescape')
            pos = align(pos + namesize, 4)
            if pos + size > len(data):
                raise FormatError('truncated CPIO data')
            payload = data[pos:pos+size]
            pos = align(pos + size, 4)
            if pos > len(data):
                raise FormatError('truncated CPIO alignment')
            if magic == b'070702' and fields[12] != sum(payload) & 0xffffffff:
                raise FormatError('CPIO CRC mismatch')
            entry = CpioEntry(name, fields, payload, data[start:pos], magic)
            if name == 'TRAILER!!!':
                if size:
                    raise FormatError('nonempty CPIO trailer')
                self.trailer, self.suffix = entry, data[pos:]
                if any(self.suffix):
                    raise FormatError('multiple archives/nonzero CPIO trailer unsupported')
                break
            self.entries.append(entry)

    def validate_paths(self):
        seen = {}
        for entry in self.entries:
            name = safe_name(entry.name)
            if name in seen:
                raise FormatError('duplicate CPIO path: ' + name)
            seen[name] = entry
        for name in seen:
            for parent in PurePosixPath(name).parents:
                key = str(parent)
                if key != '.' and key in seen and not stat.S_ISDIR(seen[key].mode):
                    raise FormatError('archive parent is not a directory: ' + key)
        return seen

    def replace(self, name, data, mode=None):
        name = safe_name(name)
        if not name:
            raise FormatError('cannot replace archive root')
        seen = self.validate_paths()
        entry = seen.get(name)
        if entry:
            if not stat.S_ISREG(entry.mode):
                raise FormatError('replacement is not a regular file: ' + name)
            if entry.fields[4] > 1 or any(e is not entry and e.hardlink_key == entry.hardlink_key
                                          and stat.S_ISREG(e.mode) for e in self.entries):
                raise FormatError('refusing replacement of hardlinked file: ' + name)
            entry.data, entry.changed = data, True
            # Replacement preserves original permissions/ownership; mode for new files only.
            return
        for parent in reversed(list(PurePosixPath(name).parents)):
            directory = str(parent)
            if directory == '.':
                continue
            if directory not in seen:
                created = self._new(directory, b'', stat.S_IFDIR | 0o755)
                self.entries.append(created)
                seen[directory] = created
            elif not stat.S_ISDIR(seen[directory].mode):
                raise FormatError('unsafe replacement parent: ' + directory)
        self.entries.append(self._new(name, data, stat.S_IFREG | (mode or 0o644)))

    def _new(self, name, data, mode):
        ino = max([e.fields[0] for e in self.entries] + [0]) + 1
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, 0, 0]
        return CpioEntry(name, fields, data, changed=True)

    def encode(self):
        return b''.join(e.encode() for e in self.entries) + self.trailer.encode() + self.suffix

    def listing(self):
        return [dict(name=e.name, mode=oct(e.mode), uid=e.fields[2], gid=e.fields[3],
                     nlink=e.fields[4], ino=e.fields[0], size=len(e.data),
                     sha256=hashlib.sha256(e.data).hexdigest(),
                     symlink=e.data.decode('utf-8', 'replace') if stat.S_ISLNK(e.mode) else None)
                for e in self.entries]


def compression(data):
    if data.startswith((b'070701', b'070702')):
        return 'raw'
    if data.startswith(b'\x1f\x8b'):
        return 'gzip'
    if data.startswith(b'\x02\x21\x4c\x18'):
        return 'lz4-legacy'
    if data.startswith(b'\x04\x22\x4d\x18'):
        return 'lz4'
    raise FormatError('unsupported ramdisk compression')


def run_lz4(data, kind, decompress=False, executable='lz4'):
    # Real temporary file stdio avoids named-pipe failures in Windows sandboxes.
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        source.write(data)
        source.seek(0)
        cmd = [str(executable), '-d' if decompress else '-z', '-c']
        if not decompress:
            # Recovery shares a fixed-size partition with platform resources.
            # High compression changes encoder effort, not kernel framing/ABI.
            cmd.append('-12')
            if kind == 'lz4-legacy':
                cmd.append('-l')
        try:
            subprocess.run(cmd, stdin=source, stdout=output, stderr=errors, check=True)
        except FileNotFoundError as exc:
            raise FormatError('external lz4 required; specify --lz4 (nothing is downloaded)') from exc
        except subprocess.CalledProcessError as exc:
            errors.seek(0)
            raise FormatError('lz4 failed: ' + errors.read().decode('utf-8', 'replace')) from exc
        output.seek(0)
        result = output.read()
    if not decompress and compression(result) != kind:
        raise FormatError('lz4 changed compression format')
    return result


def decompress_ramdisk(data, lz4='lz4'):
    kind = compression(data)
    if kind == 'raw':
        return data
    if kind == 'gzip':
        try:
            return gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise FormatError('invalid gzip ramdisk') from exc
    return run_lz4(data, kind, True, lz4)


def compress_ramdisk(data, kind, lz4='lz4'):
    if kind == 'raw':
        return data
    if kind == 'gzip':
        return gzip.compress(data, mtime=0)
    return run_lz4(data, kind, False, lz4)


@dataclass
class Fragment:
    index: int
    size: int
    offset: int
    type: int
    name: bytes
    board_ids: tuple
    table_entry: bytes
    data: bytes


class VendorBoot:
    def __init__(self, data):
        self.data = data
        if len(data) < 2112 or data[:8] != b'VNDRBOOT':
            raise FormatError('not a vendor_boot image')
        self.version, self.page = u32(data, 8), u32(data, 12)
        if self.version not in (3, 4):
            raise FormatError('only vendor_boot header v3/v4 is supported')
        if self.page < 512 or self.page > 65536 or self.page & (self.page - 1):
            raise FormatError('unsupported page size')
        self.header_size = u32(data, 2096)
        minimum = 2128 if self.version == 4 else 2112
        if not minimum <= self.header_size <= self.page:
            raise FormatError('invalid header size')
        self.ramdisk_size, self.dtb_size = u32(data, 24), u32(data, 2100)
        self.ramdisk_start = align(self.header_size, self.page)
        self.dtb_start = self.ramdisk_start + align(self.ramdisk_size, self.page)
        self.table_start = self.dtb_start + align(self.dtb_size, self.page)
        self.table_size = self.entry_count = self.entry_size = self.bootconfig_size = 0
        if self.version == 4:
            self.table_size, self.entry_count, self.entry_size, self.bootconfig_size = struct.unpack_from('<4I', data, 2112)
            if self.entry_count and self.entry_size < 108:
                raise FormatError('short vendor ramdisk table entry')
            if self.entry_count * self.entry_size > self.table_size:
                raise FormatError('truncated vendor ramdisk table')
        self.bootconfig_start = self.table_start + align(self.table_size, self.page)
        self.payload_end = self.bootconfig_start + align(self.bootconfig_size, self.page)
        if self.payload_end > len(data):
            raise FormatError('truncated vendor_boot sections')
        self.dtb = data[self.dtb_start:self.dtb_start+self.dtb_size]
        self.table = data[self.table_start:self.table_start+self.table_size]
        self.bootconfig = data[self.bootconfig_start:self.bootconfig_start+self.bootconfig_size]
        self.ramdisk = data[self.ramdisk_start:self.ramdisk_start+self.ramdisk_size]
        self.footer = None
        if len(data) >= 64 and data[-64:-60] == b'AVBf':
            _, major, minor, original, offset, size, _ = struct.unpack('>4sIIQQQ28s', data[-64:])
            if major != 1 or original < self.payload_end or original > offset or offset + size > len(data)-64:
                raise FormatError('invalid AVB footer geometry')
            self.footer = dict(major=major, minor=minor, original_image_size=original,
                               vbmeta_offset=offset, vbmeta_size=size, partition_size=len(data))
        self.fragments = []
        if self.version == 3:
            self.fragments.append(Fragment(0, self.ramdisk_size, 0, 0, b'', (), b'', self.ramdisk))
        else:
            for index in range(self.entry_count):
                raw = self.table[index*self.entry_size:(index+1)*self.entry_size]
                size, offset, typ = struct.unpack_from('<3I', raw)
                if offset + size > self.ramdisk_size:
                    raise FormatError('fragment outside vendor ramdisk')
                self.fragments.append(Fragment(index, size, offset, typ, raw[12:44],
                                               struct.unpack_from('<16I', raw, 44), raw,
                                               self.ramdisk[offset:offset+size]))
            spans = sorted((f.offset, f.offset+f.size) for f in self.fragments if f.size)
            if any(b[0] < a[1] for a, b in zip(spans, spans[1:])):
                raise FormatError('overlapping vendor ramdisk fragments')

    def inspect(self):
        return dict(header_version=self.version, page_size=self.page, header_size=self.header_size,
                    ramdisk_size=self.ramdisk_size, dtb_size=self.dtb_size, table_size=self.table_size,
                    table_entry_size=self.entry_size, bootconfig_size=self.bootconfig_size,
                    payload_end=self.payload_end, file_size=len(self.data), avb_footer=self.footer,
                    sha256=hashlib.sha256(self.data).hexdigest(),
                    fragments=[dict(index=f.index, size=f.size, offset=f.offset, type=f.type,
                                    name=f.name.rstrip(b'\0').decode('utf-8', 'replace'),
                                    name_hex=f.name.hex(), board_ids=list(f.board_ids),
                                    table_extension_hex=f.table_entry[108:].hex(),
                                    sha256=hashlib.sha256(f.data).hexdigest(),
                                    compression=self._compression(f.data)) for f in self.fragments])

    @staticmethod
    def _compression(data):
        try:
            return compression(data)
        except FormatError:
            return 'unknown'

    def _section(self, content, old_start, old_size):
        oldpad = self.data[old_start+old_size:old_start+align(old_size, self.page)]
        needed = -len(content) % self.page
        if len(oldpad) == needed:
            padding = oldpad
        elif any(oldpad):
            raise FormatError('cannot resize section with nonzero page padding')
        else:
            padding = b'\0' * needed
        return content + padding

    def repack(self, selected, replacement, ack_v3_unified=False):
        if not 0 <= selected < len(self.fragments):
            raise FormatError('invalid fragment index')
        fragment = self.fragments[selected]
        if replacement == fragment.data:
            return self.data  # exact roundtrip, including authentic stock footer
        if self.version == 3 and not ack_v3_unified:
            raise FormatError('v3 unified ramdisk: --ack-v3-unified required to modify experimentally')
        if not fragment.size:
            raise FormatError('cannot replace zero-sized fragment')
        if not self.footer and any(self.data[self.payload_end:]):
            raise FormatError('unknown trailing signatures/data; refusing modified image')
        delta = len(replacement) - fragment.size
        ramdisk = self.ramdisk[:fragment.offset] + replacement + self.ramdisk[fragment.offset+fragment.size:]
        if len(ramdisk) > 0xffffffff:
            raise FormatError('ramdisk size overflows header')
        header = bytearray(self.data[:self.ramdisk_start])
        struct.pack_into('<I', header, 24, len(ramdisk))
        table = bytearray(self.table)
        if self.version == 4:
            for other in self.fragments:
                offset = other.offset
                if other.index != selected and other.offset >= fragment.offset+fragment.size:
                    offset += delta
                elif other.index != selected and other.size == 0 and fragment.offset < other.offset < fragment.offset+fragment.size:
                    raise FormatError('zero fragment offset inside selected span')
                size = len(replacement) if other.index == selected else other.size
                struct.pack_into('<2I', table, other.index*self.entry_size, size, offset)
        result = bytes(header) + self._section(ramdisk, self.ramdisk_start, self.ramdisk_size)
        result += self._section(self.dtb, self.dtb_start, self.dtb_size)
        if self.version == 4:
            result += self._section(bytes(table), self.table_start, self.table_size)
            result += self._section(self.bootconfig, self.bootconfig_start, self.bootconfig_size)
        # Never copy bytes beyond the described sections: stock vbmeta/footer removed.
        if self.footer and len(result) > self.footer['partition_size']:
            raise FormatError('modified image exceeds stock partition capacity')
        return result


def patch_properties(data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise FormatError('property file is not UTF-8') from exc
    adb = {'ro.secure': '0', 'ro.adb.secure': '0', 'ro.debuggable': '1',
           'persist.sys.usb.config': 'adb', 'sys.usb.config': 'adb'}
    kept = []
    for line in text.splitlines():
        key = line.split('=', 1)[0].strip()
        release_or_patch = key.startswith('ro.') and (key.endswith('build.version.release')
                            or key.endswith('build.version.release_or_codename')
                            or key.endswith('build.version.security_patch') or key.endswith('build.security_patch'))
        if key not in adb and not release_or_patch:
            kept.append(line)
    return ('\n'.join(kept) + '\n' + ''.join(k+'='+v+'\n' for k, v in adb.items())).encode()


def validate_arm64_elf(binary):
    """Structural ELF validation only; not a linker, ABI or runtime guarantee."""
    if len(binary) < 64 or binary[:7] != b'\x7fELF\x02\x01\x01':
        raise FormatError('binary must be ELF64 little-endian, not placeholder text')
    typ, machine, version = struct.unpack_from('<HHI', binary, 16)
    entry, phoff = struct.unpack_from('<QQ', binary, 24)
    ehsize, phentsize, phnum = struct.unpack_from('<HHH', binary, 52)
    if typ not in (2, 3) or machine != 183 or version != 1:
        raise FormatError('binary must be AArch64 ELF EXEC or DYN')
    if ehsize != 64 or phentsize != 56 or not 0 < phnum < 65535 or phoff < 64:
        raise FormatError('unsupported ELF program header geometry')
    if phoff + phnum * phentsize > len(binary):
        raise FormatError('truncated ELF program headers')
    executable = []
    for i in range(phnum):
        ptype, flags, offset, vaddr, _, filesz, memsz, alignment = struct.unpack_from('<II6Q', binary, phoff+i*56)
        if ptype != 1:
            continue
        if filesz > memsz or offset + filesz > len(binary):
            raise FormatError('invalid ELF PT_LOAD bounds')
        if alignment not in (0, 1) and (alignment & (alignment-1) or offset % alignment != vaddr % alignment):
            raise FormatError('invalid ELF PT_LOAD alignment')
        if flags & 1 and filesz:
            executable.append((vaddr, vaddr + filesz))
    if not executable or not any(start <= entry < end for start, end in executable):
        raise FormatError('ELF requires executable PT_LOAD containing its entry point')
    return dict(class_bits=64, endian='little', machine='AArch64', type='EXEC' if typ == 2 else 'DYN',
                warning='Structural validation only; dynamic dependencies and device compatibility unverified')


DIAGNOSTIC_INIT_HASHES = {
    'system/etc/init/hw/init.rc': 'bbab24ec54bcecd64fbf0df7cb06c23561b3dd1e8302fb7d89a8f8343c73312c',
    'init.recovery.mt6895.rc': '4c1f9acf6e233ffb59f7cfd2b1c9b33bcfd6d0565ea0255a04bdc200b7e6a971',
}


def diagnostic_init_patches(paths):
    """Only the audited PGZ110 stock template is accepted, including all bytes.

    Removes several known recovery-only automatic writes. Touch services, TEE,
    crypto, other init rules and first-stage boot remain unchanged and may write.
    This deliberately is NOT a read-only recovery or a generic rc sanitizer.
    """
    modified = {}
    for name, expected in DIAGNOSTIC_INIT_HASHES.items():
        if name not in paths or not stat.S_ISREG(paths[name].mode):
            raise FormatError('diagnostic init missing regular stock file: ' + name)
        data = paths[name].data
        if hashlib.sha256(data).hexdigest() != expected:
            raise FormatError('diagnostic init unknown stock template: ' + name)
        try:
            modified[name] = data.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise FormatError('diagnostic init requires UTF-8 stock template') from exc
    main = 'system/etc/init/hw/init.rc'
    platform = 'init.recovery.mt6895.rc'
    actions = [
        (main, 'import /system/etc/init.aging.rc\n', ''),
        (main, '    exec /sbin/e2fsck -y /dev/block/platform/mtk-msdc.0/by-name/cache\n', ''),
        (main, '    exec /sbin/e2fsck -y /dev/block/platform/mtk-msdc.0/by-name/userdata\n', ''),
        (main, '    start phoenix_recovery\n', ''),
        (main, 'service phoenix_recovery /system/bin/phoenix_recovery\n    critical\n    seclabel u:r:recovery:s0\n', ''),
        (main, '    exec u:r:recovery:s0 root root -- /system/bin/cp -arf /vendor/app/mcRegistry/. /odm/vendor/app/mcRegistry/\n', ''),
        (main, '    mount ext4 /dev/block/by-name/persist /mnt/vendor/persist rw\n',
               '    mount ext4 /dev/block/by-name/persist /mnt/vendor/persist ro\n'),
        (platform, '    exec u:r:update_engine:s0 root root -- /system/bin/mtk_plpath_utils\n', ''),
    ]
    for name, old, new in actions:
        if modified[name].count(old) != 1:
            raise FormatError('diagnostic init expected action not exactly once: ' + old.strip())
        modified[name] = modified[name].replace(old, new, 1)
    return {name: text.encode('utf-8') for name, text in modified.items()}


def validate_port_config(config, diagnostic_init=False):
    """Fail before unpacking/spawning tools on invalid or contradictory modes."""
    try:
        parsed = tomllib.loads(config.decode('utf-8'))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise FormatError('device config must be valid UTF-8 TOML') from exc
    device = parsed.get('device')
    if not isinstance(device, dict) or not isinstance(device.get('codename'), str) or not device['codename'].strip():
        raise FormatError('device config requires a nonempty device.codename')
    if device.get('recovery_partition') != 'vendor_boot':
        raise FormatError('vendor_boot build requires device.recovery_partition = "vendor_boot" safety guards')
    if 'boot' in parsed:
        raise FormatError('UI-only boot configuration withdrawn: preserve the normal Recovery workflow')
    trustonic = parsed.get('trustonic')
    if trustonic is not None:
        if not isinstance(trustonic, dict) or trustonic.get('allow_persistent_writes') is not True:
            raise FormatError('Trustonic requires explicit allow_persistent_writes = true')
        if set(trustonic) - {'allow_persistent_writes', 'libraries'}:
            raise FormatError('unknown Trustonic configuration fields')
        if device['codename'] != 'OP5911':
            raise FormatError('researched Trustonic startup is restricted to OP5911')
        if diagnostic_init:
            raise FormatError('Trustonic persistent-write mode conflicts with diagnostic init (persist read-only)')
        libraries = trustonic.get('libraries', [])
        if not isinstance(libraries, list) or any(not isinstance(p, str) or not p.startswith('/') or '..' in PurePosixPath(p).parts for p in libraries):
            raise FormatError('Trustonic libraries must be plain absolute directories')
    return dict(codename=device['codename'], recovery_partition='vendor_boot',
                trustonic_enabled=trustonic is not None, diagnostic_init=diagnostic_init)


def patch_recovery(image, binary, config, font, mono, mono_license, lz4='lz4', ack_v3_unified=False,
                   allow_unified_platform_fragment=False, diagnostic_init=False):
    config_report = validate_port_config(config, diagnostic_init)
    elf_report = validate_arm64_elf(binary)
    archives, matches = {}, []
    for fragment in image.fragments:
        if not fragment.size:
            continue
        # Fail closed if an uninspectable fragment could hide a second recovery.
        archive = CpioArchive(decompress_ramdisk(fragment.data, lz4))
        paths = archive.validate_paths()
        archives[fragment.index] = archive
        for name in ('system/bin/recovery', 'sbin/recovery'):
            if name in paths:
                matches.append((fragment.index, name))
    if len(matches) != 1:
        raise FormatError('expected exactly one stock recovery program, found %d' % len(matches))
    selected, program = matches[0]
    chosen = image.fragments[selected]
    if image.version == 4 and chosen.type != 2:
        if not (allow_unified_platform_fragment and len(image.fragments) == 1 and chosen.type == 1):
            raise FormatError('recovery is not in TYPE_RECOVERY; unified PLATFORM requires --allow-unified-platform-fragment')
    archive = archives[selected]
    paths = archive.validate_paths()
    property_paths = [p for p in ('prop.default', 'system/etc/prop.default') if p in paths]
    if len(property_paths) != 1:
        raise FormatError('expected exactly one stock prop.default path in recovery fragment')
    prop = property_paths[0]
    init_changes = diagnostic_init_patches(paths) if diagnostic_init else {}
    if config_report['codename'] == 'OP5911':
        name = 'system/etc/init/hw/init.rc'
        if name not in paths or hashlib.sha256(paths[name].data).hexdigest() != DIAGNOSTIC_INIT_HASHES[name]:
            raise FormatError('managed PGZ110 services require the audited stock init template')
        text = init_changes.get(name, paths[name].data).decode('utf-8')
        # One owner per binder manager/HAL. Skyward discovers and starts the
        # installed system's HIDL manager after publishing its descriptions.
        # The stock ramdisk's manager must not race for /dev/hwbinder.
        for old, new in [
            ('service hwservicemanager /system/bin/hwservicemanager\n',
             'service hwservicemanager /system/bin/hwservicemanager\n    disabled\n'),
            ('service vendor.boot-hal-1-2 /vendor/bin/hw/android.hardware.boot@1.2-service\n',
             'service vendor.boot-hal-1-2 /vendor/bin/hw/android.hardware.boot@1.2-service\n    disabled\n'),
            ('    start vendor.boot-hal-1-2\n', ''),
        ]:
            if text.count(old) != 1:
                raise FormatError('managed init action not exactly once: ' + old.strip())
            text = text.replace(old, new, 1)
        # `disabled` only suppresses class_start. HIDL GET still sends
        # ctl.interface_start and races our managed BootControl child. Keep
        # the stock service for explicit fastboot startup, but do not expose
        # it as a second lazy owner of the normal Recovery interfaces.
        for version in ('1.0', '1.1', '1.2'):
            interface = f'    interface android.hardware.boot@{version}::IBootControl default\n'
            if text.count(interface) != 1:
                raise FormatError('stock BootControl lazy interface not exactly once: ' + version)
            text = text.replace(interface, '', 1)
        init_changes[name] = text.encode('utf-8')
    mtp_status = 'Not installed: this device has no audited USB/init template'
    if config_report['codename'] == 'OP5911':
        # LoadBootScripts scans this directory after init/hw/init.rc. Adding
        # another explicit import would parse the file twice on stock init.
        mtp_path = 'system/etc/init/skyward-mtp.rc'
        if mtp_path in paths:
            raise FormatError('stock input already contains Skyward MTP rules; require clean official ramdisk')
        rc = Path(__file__).with_name('skyward-mtp.rc').read_bytes()
        if b'sys.usb.config_disable' in b'\n'.join(line for line in rc.splitlines() if not line.lstrip().startswith(b'#')):
            raise FormatError('MTP rules must not depend on undefined config_disable')
        archive.replace(mtp_path, rc, 0o644)
        mtp_status = 'Installed PGZ110 FunctionFS MTP rules via standard init directory scan; existing ADB/fastboot rules preserved'
    for name, contents in init_changes.items():
        archive.replace(name, contents)
    archive.replace(program, binary, 0o755)
    for name, contents in (('skyward/device.toml', config), ('skyward/MiSansVF.ttf', font),
                           ('skyward/KirkMono-Regular.ttf', mono), ('skyward/KirkMono-OFL.txt', mono_license)):
        archive.replace(name, contents)
    property_copies = []
    for name, entry in paths.items():
        if (name == prop or name.endswith('/build.prop') or name.endswith('/default.prop') or name.endswith('/prop.default')) and entry.mode & 0o170000 == 0o100000:
            # Android init reads system/build.prop after prop.default. Leaving
            # ro.build.version.release=12 there permanently locks the property
            # before Skyward adopts the actual installed system's version.
            archive.replace(name, patch_properties(entry.data))
            property_copies.append(name)
    kind = compression(image.fragments[selected].data)
    result = image.repack(selected, compress_ramdisk(archive.encode(), kind, lz4), ack_v3_unified)
    # A build must remove stock authentication even if replacements happened to
    # be identical; repack's inspection-only exact roundtrip deliberately does not.
    result = result[:VendorBoot(result).payload_end]
    return result, dict(selected_fragment=selected, recovery_path=program, property_path=prop, property_copies_patched=property_copies,
                        binary_elf=elf_report, config_policy=config_report, diagnostic_init=diagnostic_init,
                        init_modified_paths=list(init_changes),
                        init_policy=('Audited PGZ110 recovery automatic e2fsck/phoenix/mcRegistry/aging/plpath removed; persist mount ro. '
                                     'NOT read-only: touch/TEE/crypto/other init may still write.' if diagnostic_init else
                                     'Stock init retained: mounts/e2fsck/phoenix may write partitions; NOT read-only.'),
                        mtp_rc=mtp_status,
                        warning='Experimental; stock SELinux/fstab and first-stage boot retained; decryption and boot are unverified')


def safe_write(path, data):
    path = Path(path).absolute()
    # Refuse links in every existing ancestor, including a pre-created output dir.
    for part in [path] + list(path.parents):
        if part.is_symlink():
            raise FormatError('refusing output symlink: ' + str(part))
        # Windows junctions/reparse points are traversal too.
        if part.exists() and getattr(part.lstat(), 'st_file_attributes', 0) & 0x400:
            raise FormatError('refusing output reparse point: ' + str(part))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)


def unpack(image, out, lz4='lz4'):
    out = Path(out)
    safe_write(out / 'inspect.json', (json.dumps(image.inspect(), indent=2)+'\n').encode())
    safe_write(out / 'dtb.bin', image.dtb)
    safe_write(out / 'bootconfig.bin', image.bootconfig)
    safe_write(out / 'ramdisk-table.bin', image.table)
    for fragment in image.fragments:
        stem = 'fragment-%03d' % fragment.index
        safe_write(out / (stem+'.compressed'), fragment.data)
        if not fragment.size:
            continue
        try:
            raw = decompress_ramdisk(fragment.data, lz4)
            archive = CpioArchive(raw)
            safe_write(out / (stem+'.cpio'), raw)
            safe_write(out / (stem+'.listing.json'), (json.dumps(archive.listing(), indent=2)+'\n').encode())
            # Archive names are metadata only; fixed numeric filenames prevent traversal.
            for i, entry in enumerate(archive.entries):
                if stat.S_ISREG(entry.mode) and (entry.name.endswith(('.rc', '.fstab', '.prop'))
                   or 'fstab' in entry.name or entry.name.endswith('prop.default')):
                    safe_write(out / (stem+'-text-%05d.txt' % i), entry.data)
        except FormatError as exc:
            safe_write(out / (stem+'.error.txt'), (str(exc)+'\n').encode())


def finalize_image(raw, stock, out, avbtool=None, partition_size=None, raw_bin=False):
    parsed_raw = VendorBoot(raw)
    if not parsed_raw.footer and any(raw[parsed_raw.payload_end:]):
        raise FormatError('unknown trailing data in build output')
    raw = raw[:parsed_raw.payload_end]  # never reuse any stock authentication
    out = Path(out)
    capacity = partition_size or (stock.footer['partition_size'] if stock.footer else None)
    if capacity is not None and (capacity <= 0 or len(raw) > capacity):
        raise FormatError('partition-size overflow')
    if raw_bin:
        if out.suffix.lower() != '.bin' or avbtool:
            raise FormatError('--raw-bin requires .bin output and no --avbtool')
        safe_write(out, raw)
        return dict(format='UNSIGNED RAW BIN, NOT FLASHABLE', size=len(raw), partition_size=capacity)
    if out.suffix.lower() != '.img' or not avbtool:
        raise FormatError('flashable .img requires --avbtool; alternatively explicitly use --raw-bin with .bin')
    if capacity is None:
        raise FormatError('--partition-size required when stock has no AVB footer')
    if capacity % 4096:
        raise FormatError('AVB partition-size must be a multiple of 4096')
    # Use a new temp image. avbtool independently checks footer/vbmeta capacity.
    with tempfile.TemporaryDirectory() as tmp:
        image_path = Path(tmp) / 'vendor_boot.img'
        image_path.write_bytes(raw)
        command = [str(avbtool)]
        if str(avbtool).lower().endswith('.py'):
            command.insert(0, sys.executable)
        command += ['add_hash_footer', '--image', str(image_path), '--partition_name', 'vendor_boot',
                    '--partition_size', str(capacity), '--algorithm', 'NONE', '--hash_algorithm', 'sha256']
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                subprocess.run(command, stdout=stdout, stderr=stderr, check=True)
            except (OSError, subprocess.CalledProcessError) as exc:
                stderr.seek(0)
                raise FormatError('avbtool failed: ' + stderr.read().decode('utf-8', 'replace')) from exc
        result = image_path.read_bytes()
    parsed = VendorBoot(result)
    if len(result) != capacity or not parsed.footer or parsed.data[:len(raw)] != raw:
        raise FormatError('avbtool returned inconsistent image')
    verify_unsigned_avb(result, parsed.footer)
    safe_write(out, result)
    return dict(format='AVB HASH FOOTER, UNSIGNED (algorithm NONE)', size=len(result), partition_size=capacity,
                warning='Requires unlocked bootloader/appropriate AVB policy. No signing key or old signature reused.')


def verify_unsigned_avb(data, footer):
    """Validate new vbmeta algorithm NONE and its sole vendor_boot hash descriptor."""
    start = footer['vbmeta_offset']
    vbmeta = data[start:start+footer['vbmeta_size']]
    if len(vbmeta) < 256 or vbmeta[:4] != b'AVB0':
        raise FormatError('missing new AVB vbmeta header')
    auth, auxiliary = struct.unpack_from('>QQ', vbmeta, 12)
    algorithm = struct.unpack_from('>I', vbmeta, 28)[0]
    desc_offset, desc_size = struct.unpack_from('>QQ', vbmeta, 96)
    if algorithm != 0 or auth != 0 or 256 + auxiliary > len(vbmeta):
        raise FormatError('new vbmeta is not unsigned algorithm NONE')
    begin = 256 + desc_offset
    end = begin + desc_size
    if end > 256 + auxiliary:
        raise FormatError('invalid AVB descriptor bounds')
    descriptors = vbmeta[begin:end]
    if len(descriptors) < 132:
        raise FormatError('missing AVB hash descriptor')
    tag, following = struct.unpack_from('>QQ', descriptors)
    if tag != 2 or following + 16 != len(descriptors):
        raise FormatError('expected exactly one AVB hash descriptor')
    size = struct.unpack_from('>Q', descriptors, 16)[0]
    algorithm = descriptors[24:56].rstrip(b'\0')
    name_len, salt_len, digest_len, flags = struct.unpack_from('>4I', descriptors, 56)
    body = descriptors[132:]
    if name_len + salt_len + digest_len > len(body):
        raise FormatError('short AVB hash descriptor')
    name = body[:name_len]
    salt = body[name_len:name_len+salt_len]
    digest = body[name_len+salt_len:name_len+salt_len+digest_len]
    if name != b'vendor_boot' or algorithm != b'sha256' or digest_len != 32 or size != footer['original_image_size']:
        raise FormatError('wrong vendor_boot AVB hash descriptor')
    if hashlib.sha256(salt + data[:size]).digest() != digest:
        raise FormatError('new AVB descriptor digest mismatch')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('inspect', 'unpack', 'build'):
        command = sub.add_parser(name)
        command.add_argument('--stock', required=True, type=Path)
        command.add_argument('--lz4', default='lz4')
        if name == 'unpack':
            command.add_argument('--out', required=True, type=Path)
        if name == 'build':
            for item in ('binary', 'config', 'font', 'mono', 'mono-license', 'out'):
                command.add_argument('--'+item, required=True, type=Path)
            command.add_argument('--avbtool', type=Path)
            command.add_argument('--partition-size', type=int)
            command.add_argument('--raw-bin', action='store_true')
            command.add_argument('--ack-experimental', action='store_true')
            command.add_argument('--ack-stock-init-writes', action='store_true')
            command.add_argument('--diagnostic-init', action='store_true',
                                 help='opt-in audited PGZ110 recovery write reduction; NOT read-only')
            command.add_argument('--ack-v3-unified', action='store_true')
            command.add_argument('--allow-unified-platform-fragment', action='store_true')
    args = parser.parse_args(argv)
    try:
        image = VendorBoot(args.stock.read_bytes())
        if args.command == 'inspect':
            print(json.dumps(image.inspect(), indent=2))
        elif args.command == 'unpack':
            unpack(image, args.out, args.lz4)
        else:
            if not args.ack_experimental:
                raise FormatError('--ack-experimental required: boot, root ADB, SELinux and decryption unverified')
            if not args.ack_stock_init_writes and not args.diagnostic_init:
                raise FormatError('--ack-stock-init-writes or --diagnostic-init required: stock init may mount/write partitions, run e2fsck/phoenix; NOT read-only')
            raw, report = patch_recovery(image, args.binary.read_bytes(), args.config.read_bytes(),
                                        args.font.read_bytes(), args.mono.read_bytes(), args.mono_license.read_bytes(),
                                        args.lz4, args.ack_v3_unified, args.allow_unified_platform_fragment,
                                        args.diagnostic_init)
            report.update(finalize_image(raw, image, args.out, args.avbtool, args.partition_size, args.raw_bin))
            print(json.dumps(report, indent=2))
    except (FormatError, OSError) as exc:
        parser.exit(2, 'ERROR: %s\n' % exc)


if __name__ == '__main__':
    main()
