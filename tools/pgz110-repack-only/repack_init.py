"""Structural PGZ110 init adapter; no filesystem writes or image generation.

adapt(paths) accepts a CPIO path -> bytes / object-with-.data mapping and returns
(changed_path_bytes, audit_records). It does not inject MTP or validate vendor
ABI/firmware. The caller must independently validate the target MT6895 hardware.
Unknown or ambiguous ownership is an error, never a best-effort patch.
"""
import re
import shlex

MAIN = 'system/etc/init/hw/init.rc'
MAX_FILES = 256
MAX_BYTES = 2 * 1024 * 1024
MAX_LINES = 50000
# Names are identities, not fuzzy filename guesses.
MANAGED = {
    'hwservicemanager': '/system/bin/hwservicemanager',
    'vendor.boot-hal-1-2': '/vendor/bin/hw/android.hardware.boot@1.2-service',
    'vendor.gatekeeper-1-0': '/vendor/bin/hw/android.hardware.gatekeeper@1.0-service',
    'gatekeeperd': '/system/bin/gatekeeperd',
    'hal_cryptoeng_oppo': '/system/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service',
    'keymaster-4-0': '/system/bin/android.hardware.keymaster@4.0-service.trustonic',
    'keymaster-4-1': '/system/bin/android.hardware.keymaster@4.1-service.trustonic',
    'mobicore': '/vendor/bin/mcDriverDaemon',
    'wmt_loader': '/vendor/bin/wmt_loader',
    'wmt_launcher': '/vendor/bin/wmt_launcher',
    'conninfra_loader': '/vendor/bin/conninfra_loader',
    'wlan_assistant': '/vendor/bin/wlan_assistant',
    'wpa_supplicant': '/vendor/bin/hw/wpa_supplicant',
    'netd': '/system/bin/netd',
}
CORE = {'recovery': '/system/bin/recovery',
        'servicemanager': '/system/bin/servicemanager',
        'vndservicemanager': '/vendor/bin/vndservicemanager'}
REQUIRED = {'recovery', 'hwservicemanager', 'vendor.boot-hal-1-2'}
BOOT_INTERFACES = {f'android.hardware.boot@1.{v}::IBootControl' for v in range(3)}
CONNECTIVITY_MODULES = {f'/vendor/lib/modules/{name}.ko' for name in (
    'conninfra', 'connfem', 'bt_drv', 'bt_drv_6895', 'wmt_chrdev_wifi',
    'wmt_chrdev_wifi_connac2', 'wlan_drv_gen4m', 'wlan_drv_gen4m_6895')}
CONNECTIVITY_NAMES = {path.rsplit('/', 1)[-1] for path in CONNECTIVITY_MODULES}


def _data(value):
    value = value if isinstance(value, bytes) else getattr(value, 'data', None)
    if not isinstance(value, bytes):
        raise ValueError('CPIO entry must contain bytes')
    return value


def _tokens(text, path, line):
    if '\\' in text:
        raise ValueError(f'{path}:{line}: escapes other than line continuation are unsupported')
    try:
        return shlex.split(text, comments=True, posix=True)
    except ValueError as error:
        raise ValueError(f'{path}:{line}: invalid init quoting') from error


def _parse(path, raw):
    if len(raw) > MAX_BYTES or b'\0' in raw:
        raise ValueError(f'{path}: oversized/binary init script')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValueError(f'{path}: init is not UTF-8') from error
    lines = text.splitlines(keepends=True)
    if len(lines) > MAX_LINES:
        raise ValueError(f'{path}: too many init lines')
    records = []
    i = 0
    while i < len(lines):
        start = i
        first = lines[i]
        if not first.strip() or first.lstrip().startswith('#'):
            i += 1
            continue
        joined = ''
        while True:
            part = lines[i].rstrip('\r\n')
            # Android init continuation is a trailing backslash. Comments that
            # end in one were skipped above and are not executable records.
            continued = part.endswith('\\')
            joined += part[:-1] + ' ' if continued else part
            i += 1
            if not continued:
                break
            if i >= len(lines):
                raise ValueError(f'{path}:{start + 1}: unfinished continuation')
        tokens = _tokens(joined, path, start + 1)
        if tokens:
            records.append({'start': start, 'end': i, 'tokens': tokens,
                            'top': not first[0].isspace(), 'owner': None})
    owner = None
    services = []
    for record in records:
        t = record['tokens']
        if record['top']:
            if t[0] == 'service':
                if len(t) < 3 or not re.fullmatch(r'[A-Za-z0-9_.-]+', t[1]):
                    raise ValueError(f'{path}:{record["start"] + 1}: malformed service')
                owner = ('service', t[1], record)
                services.append(record)
            elif t[0] == 'on':
                if len(t) < 2:
                    raise ValueError(f'{path}: empty action trigger')
                owner = ('action', ' '.join(t[1:]), record)
            elif t[0] == 'import':
                if len(t) != 2:
                    raise ValueError(f'{path}: malformed import')
                owner = None
            else:
                raise ValueError(f'{path}:{record["start"] + 1}: unsupported top-level directive {t[0]}')
        else:
            if owner is None:
                raise ValueError(f'{path}:{record["start"] + 1}: command outside a section')
            record['owner'] = owner
    return text, lines, records, services


def adapt(paths):
    """Return (modified dict[path, bytes], audit list[dict]); raise ValueError.

    Only MAIN is patched. Other .rc scripts are parsed and scanned for
    duplicate services or managed ownership/control that needs an unreviewed
    cross-file patch. Inputs are not modified. No version hash is required.
    """
    if MAIN not in paths:
        raise ValueError('missing required main init script')
    for name in paths:
        if not isinstance(name, str) or name.startswith('/') or any(part in ('', '.', '..') for part in name.split('/')):
            raise ValueError('CPIO paths must be canonical relative names')
    # ueventd .rc files use a different grammar (device ownership and firmware
    # directories), not Android init service/actions. Never reinterpret them.
    rc_names = sorted(name for name in paths if name.endswith('.rc') and
                      not name.rsplit('/', 1)[-1].startswith('ueventd'))
    if sum(len(_data(paths[name])) for name in rc_names) > MAX_BYTES * 4:
        raise ValueError('total init text exceeds bounded scan limit')
    if len(rc_names) > MAX_FILES:
        raise ValueError('too many init scripts')
    parsed = {name: _parse(name, _data(paths[name])) for name in rc_names}
    seen = {}
    all_identities = dict(MANAGED, **CORE)
    basenames = {path.rsplit('/', 1)[-1] for path in all_identities.values()}
    for path, (_, _, _, services) in parsed.items():
        for service in services:
            t = service['tokens']; name, executable = t[1:3]
            if name in seen:
                raise ValueError(f'duplicate service name {name}: {seen[name][0]} and {path}')
            seen[name] = (path, service)
            if name in all_identities:
                if executable != all_identities[name]:
                    raise ValueError(f'{path}: unexpected executable for {name}: {executable}')
                if path != MAIN:
                    raise ValueError(f'{path}: recognised service {name} outside reviewed main script')
                if name in ('hwservicemanager', 'vendor.boot-hal-1-2') and len(t) != 3:
                    raise ValueError(f'{path}: unreviewed core service arguments for {name}')
            elif executable.rsplit('/', 1)[-1] in basenames:
                raise ValueError(f'{path}: unknown alias/path for managed executable: {name}')
    for name in REQUIRED:
        if name not in seen or seen[name][0] != MAIN:
            raise ValueError(f'missing required service {name}')
    if seen['recovery'][1]['tokens'] != ['service', 'recovery', '/system/bin/recovery']:
        raise ValueError('recovery must execute /system/bin/recovery without wrapper or arguments')
    audit = []
    # Imports are not resolved through the host filesystem. All CPIO scripts
    # are scanned above; optional/property imports remain explicit audit items.
    for path, (_, _, records, _) in parsed.items():
        for record in records:
            t = record['tokens']
            if record['top'] and t[0] == 'import':
                target = t[1]
                if not target.startswith('/') or '..' in target.split('/') or '\\' in target or any(c in target for c in '*?['):
                    raise ValueError(f'{path}: unbounded or unsafe init import')
                if '$' in target and target != '/init.recovery.${ro.board.platform}.rc':
                    raise ValueError(f'{path}: unreviewed property-expanded import')
                if target.lstrip('/') not in parsed:
                    audit.append({'path': path, 'line': record['start'] + 1,
                                  'operation': 'unresolved_import_review_required', 'import': target,
                                  'reason': 'not present in supplied CPIO; no external files read or assumed safe'})
    remove = set()
    additions = {}
    for path, (_, lines, records, services) in parsed.items():
        for service in services:
            name = service['tokens'][1]
            if name not in MANAGED:
                continue
            options = [r for r in records if r['owner'] and r['owner'][0:2] == ('service', name)]
            if name in ('hwservicemanager', 'vendor.boot-hal-1-2'):
                users = [r['tokens'] for r in options if r['tokens'][0] == 'user']
                if len(users) > 1 or any(t != ['user', 'root'] for t in users):
                    raise ValueError(f'{path}: stock {name} must retain UID0; installed-directory compatibility is caller-owned')
            disabled = [r for r in options if r['tokens'][0] == 'disabled']
            if len(disabled) > 1 or any(r['tokens'] != ['disabled'] for r in disabled):
                raise ValueError(f'{path}: malformed/duplicate disabled option for {name}')
            if not disabled:
                additions[service['end']] = additions.get(service['end'], '') + '    disabled\n'
                audit.append({'path': path, 'line': service['start'] + 1,
                              'operation': 'disable_class_start', 'service': name,
                              'reason': 'normal Skyward owns this function; definition/arguments retained'})
            for r in options:
                t = r['tokens']
                if t[0] != 'interface':
                    continue
                if len(t) != 3 or any('$' in x for x in t):
                    raise ValueError(f'{path}: ambiguous lazy interface for {name}')
                if name == 'vendor.boot-hal-1-2' and (t[1] not in BOOT_INTERFACES or t[2] != 'default'):
                    raise ValueError(f'{path}: unrecognised BootControl interface')
                if name == 'vendor.gatekeeper-1-0' and t[1:] != ['android.hardware.gatekeeper@1.0::IGatekeeper', 'default']:
                    raise ValueError(f'{path}: unrecognised Gatekeeper interface')
                if name not in ('vendor.boot-hal-1-2', 'vendor.gatekeeper-1-0'):
                    allowed = set()
                    if name == 'wpa_supplicant':
                        allowed = {f'android.hardware.wifi.supplicant@1.{v}::ISupplicant' for v in range(5)}
                        allowed.add('vendor.oplus.hardware.wifi.supplicant@2.0::IOplusSupplicant')
                    if t[1] not in allowed or t[2] != 'default':
                        raise ValueError(f'{path}: unreviewed lazy interface for {name}')
                remove.update(range(r['start'], r['end']))
                audit.append({'path': path, 'line': r['start'] + 1,
                              'operation': 'remove_lazy_interface', 'service': name,
                              'interface': t[1], 'instance': t[2],
                              'reason': 'prevent duplicate init lazy owner; explicit service definition retained'})
        for r in records:
            owner = r['owner']
            if not owner:
                continue
            t = r['tokens']
            command = t[1:] if owner[0] == 'service' and t[0] == 'onrestart' else t
            if not command:
                continue
            control = None
            if command[0] in ('start', 'restart', 'stop', 'enable', 'exec_start'):
                if len(command) != 2 or '$' in command[1]:
                    raise ValueError(f'{path}:{r["start"] + 1}: ambiguous service control')
                control = (command[0], command[1])
            elif command[0] == 'setprop' and len(command) >= 2 and command[1].startswith('ctl.'):
                raise ValueError(f'{path}:{r["start"] + 1}: property-based service control unsupported')
            elif command[0] in ('exec', 'exec_background'):
                if any(token.rsplit('/', 1)[-1] in basenames for token in command[1:]):
                    raise ValueError(f'{path}:{r["start"] + 1}: managed executable launched through exec')
            if control:
                verb, target = control
                fbe_stop = owner[0] == 'action' and 'property:enable.fbe.service=0' in owner[1].split()
                if fbe_stop and target not in MANAGED and target not in ('servicemanager', 'vndservicemanager'):
                    raise ValueError(f'{path}: unreviewed control in legacy FBE action: {target}')
                must_remove = target in MANAGED and verb in ('start', 'restart', 'enable', 'exec_start')
                must_remove |= fbe_stop and verb == 'stop'
                if target in MANAGED and verb == 'stop' and not fbe_stop:
                    raise ValueError(f'{path}: unreviewed stop of managed service {target}')
                if must_remove:
                    if path != MAIN:
                        raise ValueError(f'{path}: managed service control outside reviewed main script')
                    remove.update(range(r['start'], r['end']))
                    audit.append({'path': path, 'line': r['start'] + 1,
                                  'operation': 'remove_service_control', 'command': command,
                                  'reason': 'remove duplicate starter or legacy FBE shared-manager stop'})
            if command[0] == 'insmod' and len(command) > 1 and command[1].rsplit('/', 1)[-1] in CONNECTIVITY_NAMES:
                allowed_trigger = owner[0] == 'action' and owner[1] in ('boot', 'property:vendor.connsys.driver.ready=yes')
                if path != MAIN or not allowed_trigger or len(command) != 2 or command[1] not in CONNECTIVITY_MODULES:
                    raise ValueError(f'{path}: unreviewed connectivity insmod path/arguments/trigger')
                remove.update(range(r['start'], r['end']))
                audit.append({'path': path, 'line': r['start'] + 1,
                              'operation': 'remove_duplicate_connectivity_insmod', 'command': command,
                              'reason': 'Skyward WLAN owns conninfra/driver/calibration ordering; module file retained'})
            # Keep potentially persistent OEM behaviour intact and visible.
            if any('mcRegistry' in token for token in command) and command[0] in ('exec', 'exec_background', 'copy', 'mkdir', 'mount', 'write'):
                audit.append({'path': path, 'line': r['start'] + 1,
                              'operation': 'preserved_review_required', 'command': command,
                              'reason': 'OEM registry/persistent action preserved, not made read-only by this adapter'})
    _, lines, _, _ = parsed[MAIN]
    output = []
    for i, line in enumerate(lines):
        if i in additions:
            if output and not output[-1].endswith(('\n', '\r')):
                output.append('\n')
            output.append(additions[i])
        if i not in remove:
            output.append(line)
    if len(lines) in additions:
        if output and not output[-1].endswith(('\n', '\r')):
            output.append('\n')
        output.append(additions[len(lines)])
    modified = ''.join(output).encode('utf-8')
    audit.append({'path': MAIN, 'operation': 'scope',
                  'reason': 'init ownership only; target MT6895 validation, installed HIDL UID policy, runtime/TEE/library compatibility and MTP injection remain caller responsibilities'})
    changes = {} if modified == _data(paths[MAIN]) else {MAIN: modified}
    return changes, audit
