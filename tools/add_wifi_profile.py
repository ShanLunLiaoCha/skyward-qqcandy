"""Developer helper: append the current audited profile, never mutate an existing table."""
from pathlib import Path
PROFILE='''

[wlan]
protocol = "hidl"
modules = ["wmt_chrdev_wifi_connac2", "wlan_drv_gen4m_6895"]
calibration_modules = ["bt_drv_6895"]
interface = "wlan0"
supplicant = "/vendor/bin/hw/wpa_supplicant"
libraries = ["/system/lib64", "/vendor/lib64", "/vendor/lib64/hw"]
service = "android.hardware.wifi.supplicant@1.4::ISupplicant/default"
probe = "http://connectivitycheck.gstatic.com/generate_204"

[wlan.bootstrap]
modules = ["conninfra"]
program = "/vendor/bin/conninfra_loader"
ready_property = "vendor.connsys.driver.ready"
ready_value = "yes"
libraries = ["/system/lib64", "/vendor/lib64"]

[wlan.power]
path = "/dev/wmtWifi"
on = "1"
off = "0"

[wlan.nvram]
partition = "nvdata"
directory = "APCFG/APRDEB"
file = "WIFI"
selector = "/data/vendor/nvramwifi"
device = "/dev/wmtWifi"
'''
if __name__=='__main__':
 root=Path(__file__).resolve().parents[1]
 targets=[root/'devices'/name for name in ['OP5911.toml','OP5911-decrypt.experimental.toml']]
 texts=[p.read_text(encoding='utf-8') for p in targets]
 for p,s in zip(targets,texts):
  if any(line.strip()=='[wlan]' for line in s.splitlines()):raise ValueError('WLAN already configured; refusing to overwrite stages: '+p.name)
 for p,s in zip(targets,texts):p.write_text(s+PROFILE,encoding='utf-8')
