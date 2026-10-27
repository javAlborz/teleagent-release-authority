#!/usr/bin/python3 -I
"""Replace only body-parser in a disposable hosted dependency tree with fixed bytes.

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

URL = 'https://registry.npmjs.org/body-parser/-/body-parser-1.20.9.tgz'
INTEGRITY = 'FISIQxV5u91Y9gvuFq3q/tA/qTqLJn3AhRcEvyozyhJTh5OBFFtv827AdHU7Rbyct4r+Ba1/99oFa1Y3yuFsdw=='
MAXIMUM = 262144
DEPENDENCIES = {'bytes': '~3.1.2', 'content-type': '~1.0.5', 'debug': '2.6.9', 'depd': '2.0.0', 'destroy': '~1.2.0', 'http-errors': '~2.0.1', 'iconv-lite': '~0.4.24', 'on-finished': '~2.4.1', 'qs': '~6.16.0', 'raw-body': '~2.5.3', 'type-is': '~1.6.18', 'unpipe': '~1.0.0'}


def need(value):
    if not value:
        raise ValueError('fixed body-parser projection refused')


def verified_files(body, integrity=INTEGRITY):
    need(0 < len(body) <= MAXIMUM and
         base64.b64encode(hashlib.sha512(body).digest()).decode() == integrity)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            need(2 <= len(parts) <= 6 and parts[0] == 'package' and
                 all(part not in ('', '.', '..', 'node_modules') for part in parts) and
                 '/'.join(parts) == member.name and member.isfile() and
                 not member.issparse() and 0 < member.size <= 512 * 1024 and
                 member.name not in files and len(files) < 100)
            data = archive.extractfile(member).read(512 * 1024 + 1)
            need(len(data) == member.size)
            files[member.name] = data
            need(sum(map(len, files.values())) <= MAXIMUM)
    metadata = json.loads(files['package/package.json'])
    need(metadata['name'] == 'body-parser' and metadata['version'] == '1.20.9' and
         metadata.get('dependencies') == DEPENDENCIES and
         not set(metadata.get('scripts', {})).intersection({'preinstall', 'install', 'postinstall'}))
    need({'package/index.js', 'package/package.json', 'package/lib/read.js',
          'package/lib/types/json.js'} <= files.keys())
    return files


def project(archive, root, app, component):
    need(component in ('voice-app', 'claude-api-server'))
    info = archive.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAXIMUM)
    files = verified_files(archive.read_bytes())
    need(root.is_absolute() and root.resolve() == root and
         not root.is_relative_to('/opt') and root.stat().st_uid == os.getuid())
    target = root / component / 'node_modules/body-parser'
    need(target.is_dir() and target.resolve() == target)
    locked = json.loads((app / component / 'package-lock.json').read_bytes())['packages']['node_modules/body-parser']
    need(locked['version'] == '1.20.9' and locked['resolved'] == URL and
         locked['integrity'] == 'sha512-' + INTEGRITY and locked['dependencies'] == DEPENDENCIES)
    paths = list(target.rglob('*'))
    need(len(paths) <= 1000)
    total = 0
    for path in [target, *paths]:
        info = path.lstat()
        need(info.st_uid == os.getuid() and not path.is_symlink() and
             (stat.S_ISDIR(info.st_mode) or
              (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)))
        if path.is_file():
            total += info.st_size
        need(total <= 8 * 1024 * 1024)
    need(json.loads((target / 'package.json').read_bytes())['version'] == '1.20.6')
    nested = target / 'node_modules'
    need(not nested.exists() or nested.is_dir())
    target.parent.chmod(0o755)
    target.chmod(0o755)
    for path in target.rglob('*'):
        if path.is_dir(): path.chmod(0o755)
    # The voice lock has nested debug/ms packages. Their exact bytes remain
    # intact and the subsequent full inventory check validates their versions.
    # The authenticated npm archive is forbidden from supplying node_modules.
    for path in target.iterdir():
        if path.name == 'node_modules':
            need(path.is_dir())
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
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
        need(os.environ.get('GITHUB_ACTIONS') == 'true' and
             os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
             os.uname().nodename.split('.')[0].lower() != 'hermes')
        temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        need(args.root.is_relative_to(temporary))
        project(args.archive, args.root, args.app, args.component)
    print('V85_BODY_PARSER_VERIFIED')


if __name__ == '__main__': main()
