"""Synthetic structural init tests; no images, devices, downloads or runtime claims."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('repack_init', Path(__file__).resolve().parents[1] / 'repack_init.py')
ri = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ri)
BASE = '''# Preserve OEM comments
on boot
    start vendor.boot-hal-1-2
    start untouched
    write /proc/sys/kernel/panic_on_oops 1

service recovery /system/bin/recovery
    seclabel u:r:recovery:s0
service hwservicemanager /system/bin/hwservicemanager
    onrestart setprop hwservicemanager.ready false
service vendor.boot-hal-1-2 /vendor/bin/hw/android.hardware.boot@1.2-service
    interface android.hardware.boot@1.0::IBootControl default
    interface android.hardware.boot@1.1::IBootControl default
    interface android.hardware.boot@1.2::IBootControl default
service logd /system/bin/logd
    socket logd stream 0666 logd logd
service untouched /system/bin/other
    disabled
'''
OLD = '''
service vendor.gatekeeper-1-0 /vendor/bin/hw/android.hardware.gatekeeper@1.0-service
    interface android.hardware.gatekeeper@1.0::IGatekeeper default
service gatekeeperd /system/bin/gatekeeperd /data/misc/gatekeeper
service keymaster-4-0 /system/bin/android.hardware.keymaster@4.0-service.trustonic
service keymaster-4-1 /system/bin/android.hardware.keymaster@4.1-service.trustonic
service hal_cryptoeng_oppo /system/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service
service mobicore /vendor/bin/mcDriverDaemon --P1 /mnt/vendor/persist/mcRegistry \\
    -r /vendor/app/mcRegistry/a.drbin \\
    -r /odm/vendor/app/mcRegistry/b.drbin
    seclabel u:r:recovery:s0
service conninfra_loader /vendor/bin/conninfra_loader
    class core
    user system
service wlan_assistant /vendor/bin/wlan_assistant
    class main
service wmt_loader /vendor/bin/wmt_loader
service wmt_launcher /vendor/bin/wmt_launcher -p /vendor/firmware/
service wpa_supplicant /vendor/bin/hw/wpa_supplicant \\
    -Dnl80211 -iwlan0 -dd -O/data/misc/wifi/sockets \\
    -c/data/misc/wifi/wpa_supplicant.conf
    disabled
    oneshot
service netd /system/bin/netd
on property:enable.fbe.service=0
    stop mobicore
    stop servicemanager
    stop hwservicemanager
    stop gatekeeperd
    stop vendor.gatekeeper-1-0
    stop keymaster-4-0
on boot
    exec u:r:recovery:s0 root root -- /system/bin/cp -arf /vendor/app/mcRegistry/. /odm/vendor/app/mcRegistry/
on property:vendor.connsys.driver.ready=yes
    start conninfra_loader
    restart wlan_assistant
    insmod /vendor/lib/modules/conninfra.ko
'''

class AdapterTests(unittest.TestCase):
    def apply(self, text, extra=None):
        paths = {ri.MAIN: SimpleNamespace(data=text.encode())}
        paths.update(extra or {})
        original = paths[ri.MAIN].data
        changed, report = ri.adapt(paths)
        self.assertEqual(paths[ri.MAIN].data, original)
        return changed.get(ri.MAIN, original).decode(), report

    def test_current_required_services_and_explicit_fastboot_definition_survive(self):
        text, report = self.apply(BASE)
        self.assertIn('service vendor.boot-hal-1-2 /vendor/bin/hw/android.hardware.boot@1.2-service\n    disabled\n', text)
        self.assertIn('service hwservicemanager /system/bin/hwservicemanager\n    disabled\n', text)
        self.assertNotIn('interface android.hardware.boot@', text)
        self.assertNotIn('    start vendor.boot-hal-1-2', text)
        self.assertIn('    start untouched', text)
        self.assertIn('    write /proc/sys/kernel/panic_on_oops 1', text)
        self.assertIn('service logd /system/bin/logd\n    socket logd stream 0666 logd logd', text)
        self.assertEqual(sum(r['operation'] == 'remove_lazy_interface' for r in report), 3)

    def test_a09_continued_arguments_and_registry_copy_are_not_rewritten(self):
        text, report = self.apply(BASE + OLD)
        original = OLD[OLD.index('service mobicore'):OLD.index('    seclabel u:r:recovery:s0', OLD.index('service mobicore'))]
        self.assertIn(original + '    disabled\n', text)
        self.assertIn('    -c/data/misc/wifi/wpa_supplicant.conf\n', text)
        self.assertEqual(text.count('service wpa_supplicant'), 1)
        self.assertNotIn('    stop servicemanager', text)
        self.assertNotIn('    restart wlan_assistant', text)
        self.assertNotIn('    insmod /vendor/lib/modules/conninfra.ko', text)
        self.assertTrue(any(r['operation']=='remove_duplicate_connectivity_insmod' for r in report))
        self.assertIn('/system/bin/cp -arf /vendor/app/mcRegistry/. /odm/vendor/app/mcRegistry/', text)
        self.assertTrue(any(r['operation'] == 'preserved_review_required' for r in report))
        self.assertNotIn('interface android.hardware.gatekeeper', text)

    def test_idempotent_after_structural_adapter(self):
        text, _ = self.apply(BASE + OLD)
        changed, report = ri.adapt({ri.MAIN: text.encode()})
        self.assertEqual(changed, {})
        self.assertTrue(report)

    def test_all_managed_names_disable_without_deleting_definitions(self):
        text, _ = self.apply(BASE + OLD)
        for name in ri.MANAGED:
            self.assertIn('service ' + name + ' ', text)
        _, _, records, services = ri._parse(ri.MAIN, text.encode())
        for service in services:
            name = service['tokens'][1]
            if name in ri.MANAGED:
                options = [r['tokens'] for r in records if r['owner'] and r['owner'][:2] == ('service', name)]
                self.assertEqual(options.count(['disabled']), 1)

    def test_wrong_known_executable_and_alias_fail_closed(self):
        for text in [BASE.replace('/system/bin/hwservicemanager', '/vendor/bin/hwservicemanager'),
                     BASE + '\nservice alias /vendor/bin/mcDriverDaemon\n',
                     BASE.replace('/system/bin/recovery\n', '/system/bin/recovery --unknown\n')]:
            with self.assertRaises(ValueError): self.apply(text)

    def test_duplicate_across_all_rc_scripts_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate service'):
            self.apply(BASE, {'init.other.rc': b'service logd /other/program\n'})
        with self.assertRaisesRegex(ValueError, 'outside reviewed'):
            self.apply(BASE, {'init.other.rc': b'service mobicore /vendor/bin/mcDriverDaemon\n'})
        with self.assertRaisesRegex(ValueError, 'outside reviewed'):
            self.apply(BASE, {'init.other.rc': b'on boot\n    start hwservicemanager\n'})

    def test_ambiguous_control_and_unknown_fbe_target_rejected(self):
        for suffix in ['on boot\n    start ${service.name}\n',
                       'on boot\n    setprop ctl.start mobicore\n',
                       'on property:enable.fbe.service=0\n    stop unknown-secret-service\n',
                       'on boot\n    stop hwservicemanager\n',
                       'on boot\n    exec -- /vendor/bin/mcDriverDaemon\n']:
            with self.assertRaises(ValueError): self.apply(BASE + '\n' + suffix)

    def test_nonroot_stock_context_and_unknown_lazy_interfaces_rejected(self):
        with self.assertRaises(ValueError): self.apply(BASE.replace('service hwservicemanager /system/bin/hwservicemanager\n', 'service hwservicemanager /system/bin/hwservicemanager\n    user system\n'))
        with self.assertRaises(ValueError): self.apply(BASE.replace('android.hardware.boot@1.2::IBootControl', 'android.hardware.boot@9.9::IBootControl'))

    def test_comments_and_unrelated_sections_preserved(self):
        suffix = '\n# start mobicore\\\non property:anything=1\n    stop unrelated\n    copy /source /target\n'
        text, _ = self.apply(BASE + suffix)
        self.assertTrue(text.endswith(suffix))

    def test_ueventd_grammar_is_preserved_not_misparsed(self):
        extra={'system/etc/ueventd.rc': b'firmware_directories /vendor/firmware\n/dev/binder 0666 root root\n'}
        paths={ri.MAIN:BASE.encode(), **extra}
        changed, _=ri.adapt(paths)
        self.assertNotIn('system/etc/ueventd.rc',changed)
        self.assertEqual(paths['system/etc/ueventd.rc'],extra['system/etc/ueventd.rc'])

    def test_import_boundaries_are_audited_and_unsafe_expansion_rejected(self):
        _, report=self.apply('import /init.recovery.${ro.board.platform}.rc\nimport /init.recovery.project.rc\n'+BASE)
        self.assertEqual(sum(r['operation']=='unresolved_import_review_required' for r in report),2)
        for target in ['relative.rc','/../escape.rc','/init.${arbitrary}.rc','/vendor/etc/init/*.rc']:
            with self.assertRaises(ValueError): self.apply('import '+target+'\n'+BASE)

    def test_canonical_paths_required_and_last_line_without_newline_works(self):
        for path in ['/bad.rc','../bad.rc','a//b.rc','./bad.rc']:
            with self.assertRaises(ValueError): self.apply(BASE,{path:b'# comment\n'})
        text,_=self.apply(BASE+'\nservice mobicore /vendor/bin/mcDriverDaemon')
        self.assertTrue(text.endswith('service mobicore /vendor/bin/mcDriverDaemon\n    disabled\n'))

    def test_connectivity_modules_removed_only_for_audited_paths_and_actions(self):
        commands=''.join('    insmod '+path+'\n' for path in sorted(ri.CONNECTIVITY_MODULES))
        text,report=self.apply(BASE+'\non boot\n'+commands+'    insmod /lib/modules/oplus_omrg.ko\n')
        for path in ri.CONNECTIVITY_MODULES:self.assertNotIn('    insmod '+path+'\n',text)
        self.assertIn('    insmod /lib/modules/oplus_omrg.ko\n',text)
        self.assertEqual(sum(r['operation']=='remove_duplicate_connectivity_insmod' for r in report),len(ri.CONNECTIVITY_MODULES))
        for suffix in ['on boot\n    insmod /vendor/lib/modules/conninfra.ko unknown=1\n',
                       'on property:other=1\n    insmod /vendor/lib/modules/conninfra.ko\n',
                       'on boot\n    insmod /other/path/conninfra.ko\n']:
            with self.assertRaises(ValueError):self.apply(BASE+'\n'+suffix)
        with self.assertRaises(ValueError):self.apply(BASE,{'init.other.rc':b'on boot\n    insmod /vendor/lib/modules/conninfra.ko\n'})

    def test_unknown_lazy_mapping_not_silently_removed(self):
        with self.assertRaises(ValueError):self.apply(BASE+'\nservice mobicore /vendor/bin/mcDriverDaemon\n    interface vendor.unknown@1.0::IFoo default\n')

    def test_malformed_or_bounded_input_rejected(self):
        for value in [b'\xff', b'\0', b'on boot\n    start x\\', b'unknown thing\n', b'    start x\n', b'#' * (ri.MAX_BYTES+1)]:
            with self.assertRaises(ValueError): ri.adapt({ri.MAIN: value})
        with self.assertRaises(ValueError): ri.adapt({})

if __name__ == '__main__': unittest.main()
