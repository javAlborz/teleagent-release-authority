#!/usr/bin/python3 -I
"""Replace only proxy-addr in a disposable hosted dependency tree with fixed bytes.

No npm, package lifecycle scripts, native builds, or dependency resolution run.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import urllib.request

URL = 'https://registry.npmjs.org/proxy-addr/-/proxy-addr-2.0.8.tgz'
INTEGRITY = '5nnx0yGyVUcY6t9RnWcARWtwT9F1D8O9rt08htPvnd49W1IgZtmLkhu9WfMzQj1cFxjHIO6connUNVW5k7AVyQ=='
MAXIMUM = 262144
DEPENDENCIES = {'forwarded': '0.2.0', 'ipaddr.js': '1.9.1'}


def need(value):
    if not value:
        raise ValueError('fixed proxy-addr projection refused')


def verified_files(body, integrity=INTEGRITY):
    need(0 < len(body) <= MAXIMUM and
         base64.b64encode(hashlib.sha512(body).digest()).decode() == integrity)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            need(2 <= len(parts) <= 6 and parts[0] == 'package' and
                 all(part not in ('', '.', '..') for part in parts) and
                 '/'.join(parts) == member.name and member.isfile() and
                 not member.issparse() and 0 < member.size <= 512 * 1024 and
                 member.name not in files and len(files) < 100)
            data = archive.extractfile(member).read(512 * 1024 + 1)
            need(len(data) == member.size)
            files[member.name] = data
            need(sum(map(len, files.values())) <= MAXIMUM)
    metadata = json.loads(files['package/package.json'])
    need(metadata['name'] == 'proxy-addr' and metadata['version'] == '2.0.8' and
         metadata.get('dependencies') == DEPENDENCIES and
         not set(metadata.get('scripts', {})).intersection({'preinstall', 'install', 'postinstall'}))
    need({'package/index.js', 'package/package.json'} <= files.keys())
    return files


def project(archive, root, app, component):
    need(component in ('voice-app', 'claude-api-server'))
    files = verified_files(archive.read_bytes())
    need(root.is_absolute() and root.resolve() == root and
         not root.is_relative_to('/opt') and root.stat().st_uid == os.getuid())
    target = root / component / 'node_modules/proxy-addr'
    need(target.is_dir() and target.resolve() == target and
         json.loads((target / 'package.json').read_bytes())['version'] == '2.0.7')
    locked = json.loads((app / component / 'package-lock.json').read_bytes())['packages']['node_modules/proxy-addr']
    need(locked['version'] == '2.0.8' and locked['resolved'] == URL and
         locked['integrity'] == 'sha512-' + INTEGRITY and locked['dependencies'] == DEPENDENCIES)
    for path in target.rglob('*'):
        need(not path.is_symlink() and (path.is_dir() or stat.S_ISREG(path.stat().st_mode)))
    target.parent.chmod(0o755)
    target.chmod(0o755)
    for path in target.rglob('*'):
        if path.is_dir(): path.chmod(0o755)
    shutil.rmtree(target)
    target.mkdir(mode=0o755)
    for name, body in files.items():
        path = target / name.removeprefix('package/')
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(body)
        path.chmod(0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--component', choices=['voice-app', 'claude-api-server'])
    parser.add_argument('--acquire', action='store_true')
    args = parser.parse_args()
    need(args.acquire != bool(args.root) and (args.acquire or args.app is not None))
    if args.acquire:
        need(not args.archive.exists() and not args.archive.is_symlink())
        with urllib.request.urlopen(URL, timeout=30) as response:
            need(response.url == URL)
            body = response.read(MAXIMUM + 1)
        verified_files(body)
        with args.archive.open('xb') as stream: stream.write(body)
    else:
        need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted')
        temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        need(args.root.is_relative_to(temporary))
        project(args.archive, args.root, args.app, args.component)
    print('V66_PROXY_ADDR_VERIFIED')


if __name__ == '__main__': main()
