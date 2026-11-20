"""Insert DEX and the executable ARM64 helper before zipalign and signing."""
from pathlib import Path
from zipfile import ZipFile, ZIP_STORED
import sys

d = Path(sys.argv[1])
# Windows aapt2 can retain backslashes in asset entry names. Android's
# AssetManager expects slash-separated paths; normalize before signing.
source = d / 'unsigned.apk'
normalized = d / 'normalized.apk'
with ZipFile(source) as incoming, ZipFile(normalized, 'w', ZIP_STORED) as out:
    seen = set()
    for entry in incoming.infolist():
        name = entry.filename.replace('\\', '/')
        if name in seen or name.startswith('/') or '..' in name.split('/'):
            raise ValueError(f'unsafe or duplicate APK entry: {name}')
        seen.add(name)
        entry.filename = name
        out.writestr(entry, incoming.read(entry.orig_filename))
    out.write(d / 'dex/classes.dex', 'classes.dex')
    out.write(d / 'libmobile_porter.so', 'lib/arm64-v8a/libmobile_porter.so')
normalized.replace(source)
