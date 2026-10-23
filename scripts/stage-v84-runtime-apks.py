#!/usr/bin/python3 -I
"""Stage only the six fixed Alpine runtime security updates; never install them."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

MANIFEST_SHA = '8d29c2b3ad0c809e18e3e87b751d5656a35826c801dabd491b5030cb576e5fd8'
PACKAGES = {'ca-certificates-bundle': '20261020-r0', 'libcrypto3': '3.5.9-r0',
            'libssl3': '3.5.9-r0', 'musl': '1.2.6-r3', 'musl-utils': '1.2.6-r3',
            'zlib': '1.3.2-r1'}


def checked(path, digest, size):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
        raise ValueError('fixed APK material size or type differs')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('fixed APK material digest differs')
    return data


def stage(source, destination):
    record = Path(__file__).resolve().parent.parent / 'inputs/teleagent/runtime-apk-v84.json'
    raw = record.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != MANIFEST_SHA:
        raise ValueError('runtime APK manifest differs')
    manifest = json.loads(raw)
    rows = manifest['packages']
    if len(rows) != 6 or {r['name']: r['version'] for r in rows} != PACKAGES:
        raise ValueError('runtime APK package selection differs')
    checked(source / 'APKINDEX.tar.gz', manifest['indexSha256'], manifest['indexBytes'])
    for row in rows:
        if row['filename'] != row['name'] + '-' + row['version'] + '.apk':
            raise ValueError('runtime APK filename differs')
        checked(source / row['filename'], row['sha256'], row['bytes'])
    destination.mkdir(mode=0o700)
    target = destination / 'apk/main/x86_64'
    target.mkdir(parents=True)
    for name in ['APKINDEX.tar.gz', *(r['filename'] for r in rows)]:
        shutil.copyfile(source / name, target / name)
        (target / name).chmod(0o444)
    (destination / 'apk/repositories').write_text('/materials/apk/main\n')
    return {'manifestSha256': MANIFEST_SHA, 'packages': PACKAGES, 'installed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.source, args.destination), sort_keys=True))
