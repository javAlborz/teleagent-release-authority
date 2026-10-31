#!/usr/bin/python3 -I
"""Replace only the two V86 security packages in a disposable hosted dependency tree with fixed bytes.

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

MANIFEST_SHA256 = 'af0970c0f9f4ac6c585cad4825333a9684415ec82fe3bc9c2d3125a480471496'
MAXIMUM = 1024 * 1024


def package_record(name):
    manifest = Path(__file__).resolve().parents[1] / 'inputs/teleagent/security-packages-v86.json'
    body = manifest.read_bytes()
    need(hashlib.sha256(body).hexdigest() == MANIFEST_SHA256)
    rows = json.loads(body)
    need(name in ('qs', 'follow-redirects') and len(rows) == 2)
    matches = [row for row in rows if row['name'] == name]
    need(len(matches) == 1)
    return matches[0]


def need(value):
    if not value:
        raise ValueError('fixed V86 security package projection refused')


def verified_files(body, record, integrity=None):
    integrity = integrity or record['integrity'].removeprefix('sha512-')
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
    need(metadata['name'] == record['name'] and metadata['version'] == record['version'] and
         metadata.get('dependencies', {}) == record['dependencies'] and
         not set(metadata.get('scripts', {})).intersection({'preinstall', 'install', 'postinstall'}))
    need('package/package.json' in files and
         ('package/lib/index.js' if record['name'] == 'qs' else 'package/index.js') in files)
    return files


def project(archive, root, app, component, record):
    need(component in record['components'])
    info = archive.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAXIMUM)
    body = archive.read_bytes()
    need(hashlib.sha256(body).hexdigest() == record['sha256'])
    files = verified_files(body, record)
    need(root.is_absolute() and root.resolve() == root and
         not root.is_relative_to('/opt') and root.stat().st_uid == os.getuid())
    target = root / component / 'node_modules' / record['name']
    need(target.is_dir() and target.resolve() == target)
    locked = json.loads((app / component / 'package-lock.json').read_bytes())['packages']['node_modules/' + record['name']]
    need(locked['version'] == record['version'] and locked['resolved'] == record['url'] and
         locked['integrity'] == record['integrity'] and
         locked.get('dependencies', {}) == record['dependencies'])
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
    need(json.loads((target / 'package.json').read_bytes())['version'] == record['previousVersion'])
    nested = target / 'node_modules'
    need(not nested.exists() or nested.is_dir())
    target.parent.chmod(0o755)
    target.chmod(0o755)
    for path in target.rglob('*'):
        if path.is_dir(): path.chmod(0o755)
    # Preserve any pre-existing nested dependencies; the complete inventory
    # check still verifies them. The archive cannot supply node_modules.
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
    parser.add_argument('--package', required=True, choices=['qs', 'follow-redirects'])
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--component', choices=['voice-app', 'claude-api-server'])
    parser.add_argument('--acquire', action='store_true')
    args = parser.parse_args()
    record = package_record(args.package)
    need(args.acquire != bool(args.root) and (args.acquire or args.app is not None))
    if args.acquire:
        need(not args.archive.exists() and not args.archive.is_symlink())
        with urllib.request.urlopen(record['url'], timeout=30) as response:
            need(response.url == record['url'])
            body = response.read(MAXIMUM + 1)
        need(hashlib.sha256(body).hexdigest() == record['sha256'])
        verified_files(body, record)
        with args.archive.open('xb') as stream: stream.write(body)
    else:
        need(os.environ.get('GITHUB_ACTIONS') == 'true' and
             os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
             os.uname().nodename.split('.')[0].lower() != 'hermes')
        temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        need(args.root.is_relative_to(temporary))
        project(args.archive, args.root, args.app, args.component, record)
    print('V86_SECURITY_PACKAGE_VERIFIED')


if __name__ == '__main__': main()
