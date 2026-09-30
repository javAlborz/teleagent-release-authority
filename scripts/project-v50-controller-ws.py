#!/usr/bin/python3 -I
"""Project the exact pure-JavaScript ws addition into retained controller deps.

Native dependencies remain the independently compared retained input. No npm,
package lifecycle script, native addon, or dependency resolution is executed.
"""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import urllib.request

URL = 'https://registry.npmjs.org/ws/-/ws-8.21.3.tgz'
INTEGRITY = '201TZ/kPWxoPr/OKWjquZR1SWKXcvxdH+e1xrx89b3YbmzLMFCLfnaG1HFIgWzJOEWZ7MvpK++odZufgYR50Rw=='
MAXIMUM = 1024 * 1024


def need(value):
    if not value:
        raise ValueError('fixed controller ws projection refused')


def verified_files(body, integrity=INTEGRITY):
    need(0 < len(body) <= MAXIMUM and
         base64.b64encode(hashlib.sha512(body).digest()).decode() == integrity)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        members = archive.getmembers()
        need(1 <= len(members) <= 64)
        for member in members:
            need(re.fullmatch(r'package/(?:lib/)?[A-Za-z0-9._-]+', member.name) and
                 member.isfile() and not member.issparse() and 0 < member.size <= 256 * 1024 and
                 member.name not in files)
            data = archive.extractfile(member).read(256 * 1024 + 1)
            need(len(data) == member.size)
            files[member.name] = data
    need(sum(map(len, files.values())) <= MAXIMUM)
    metadata = json.loads(files['package/package.json'])
    need(metadata['name'] == 'ws' and metadata['version'] == '8.21.3' and
         not metadata.get('dependencies') and
         not set(metadata.get('scripts', {})).intersection({'preinstall', 'install', 'postinstall'}))
    need({'package/index.js', 'package/lib/websocket.js', 'package/lib/websocket-server.js'} <= files.keys())
    return files


def project(archive, root):
    files = verified_files(archive.read_bytes())
    target = root / 'claude-api-server/node_modules/ws'
    need(target.parent.is_dir() and target.parent.resolve() == target.parent and
         not target.exists() and not target.is_symlink())
    target.mkdir(mode=0o755)
    for name, body in files.items():
        path = target / name.removeprefix('package/')
        path.parent.mkdir(mode=0o755, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(body)
        path.chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--acquire', action='store_true')
    args = parser.parse_args()
    need(args.acquire != bool(args.root))
    if args.acquire:
        need(not args.archive.exists() and not args.archive.is_symlink())
        with urllib.request.urlopen(URL, timeout=30) as response:
            body = response.read(MAXIMUM + 1)
        verified_files(body)
        with args.archive.open('xb') as stream:
            stream.write(body)
    else:
        project(args.archive, args.root)
    print('V50_CONTROLLER_WS_VERIFIED')


if __name__ == '__main__':
    main()
