#!/usr/bin/python3 -I
"""Project exact N-API SQLite inputs into an already verified unsigned build tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import urllib.request

INPUTS = {
    'better-sqlite3': ('13.0.3', '77e0513dc1a469fb3bceec4c7fb5ad3f403109787eda05be047ec17fd56868cb', 11402131),
    'node-addon-api': ('8.9.2', '4cd65698541b19a33f798f1dc25c02c6ed1c9d7749b8824b1a1ccecdd197c8ea', 62490),
}
TARGETS = {'glibc': ('claude-api-server', 'privileged-action-broker'), 'musl': ('voice-app',)}


def need(value, message):
    if not value:
        raise ValueError(message)


def archive_path(directory, name):
    return directory / (name + '-' + INPUTS[name][0] + '.tgz')


def verified_archive(directory, name):
    path = archive_path(directory, name)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == INPUTS[name][2],
         'N-API archive metadata differs')
    data = path.read_bytes()
    need(hashlib.sha256(data).hexdigest() == INPUTS[name][1], 'N-API archive digest differs')
    return path


def acquire(directory):
    need(not directory.exists(), 'N-API input destination already exists')
    directory.mkdir(mode=0o700)
    for name, (version, digest, size) in INPUTS.items():
        url = f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz'
        with urllib.request.urlopen(url, timeout=30) as response:
            need(response.url == url, 'N-API acquisition redirected')
            body = response.read(size + 1)
        need(len(body) == size and hashlib.sha256(body).hexdigest() == digest,
             'N-API acquired bytes differ')
        archive_path(directory, name).write_bytes(body)
    print('FIXED_NAPI_INPUTS_VERIFIED')


def extract(directory, name, destination, target):
    need(not destination.exists(), 'N-API package destination already exists')
    destination.mkdir(parents=True)
    seen = set()
    with tarfile.open(verified_archive(directory, name), 'r:gz') as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            need(member.isfile() and len(parts) >= 2 and parts[0] == 'package' and
                 all(part not in ('', '.', '..') for part in parts) and
                 member.name not in seen and 0 <= member.size <= 20000000,
                 'N-API package member differs')
            seen.add(member.name)
            relative = '/'.join(parts[1:])
            if relative.startswith('prebuilds/'):
                wanted = 'linux-x64.node' if target == 'glibc' else 'linuxmusl-x64.node'
                if relative != 'prebuilds/' + wanted:
                    continue
            path = destination.joinpath(*parts[1:])
            path.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            need(stream is not None, 'N-API package member is unreadable')
            with stream, path.open('xb') as output:
                shutil.copyfileobj(stream, output, 1024 * 1024)
            need(path.stat().st_size == member.size, 'N-API extracted size differs')
            path.chmod(0o444)
    need(json.loads((destination / 'package.json').read_text())['version'] == INPUTS[name][0],
         'N-API package version differs')


def package_paths(node_modules, prefix='node_modules'):
    """List package roots without interpreting package code or following links."""
    result = {}
    for child in sorted(node_modules.iterdir()):
        need(not child.is_symlink(), 'dependency link is forbidden')
        if child.name.startswith('.'):
            continue
        candidates = sorted(child.iterdir()) if child.name.startswith('@') else [child]
        for package in candidates:
            need(package.is_dir() and not package.is_symlink(), 'dependency package shape differs')
            name = (child.name + '/' + package.name) if child.name.startswith('@') else package.name
            relative = prefix + '/' + name
            result[relative] = package
            nested = package / 'node_modules'
            if nested.exists():
                result.update(package_paths(nested, relative + '/node_modules'))
    return result


def project(root, app, inputs, target):
    root = root.resolve(strict=True)
    app = app.resolve(strict=True)
    need(target in TARGETS and root != app and not str(root).startswith('/opt/') and
         root.stat().st_uid == os.getuid(), 'unsigned projection destination differs')
    for name in INPUTS:
        verified_archive(inputs, name)
    for component in TARGETS[target]:
        package_root = root / component
        modules = package_root / 'node_modules'
        need(modules.is_dir() and not modules.is_symlink(), 'verified dependency tree absent')
        modules.chmod(0o755)
        lock = json.loads((app / component / 'package-lock.json').read_text())['packages']
        locked = {name: value for name, value in lock.items() if name.startswith('node_modules/')}
        sqlite = modules / 'better-sqlite3'
        need(json.loads((sqlite / 'package.json').read_text())['version'] == '12.11.1',
             'baseline SQLite package differs')
        # Inputs were authenticated before any removals. These are disposable,
        # unsigned dependency trees, never a selected or installed release.
        for path in modules.rglob('*'):
            need(not path.is_symlink(), 'dependency tree contains a link')
            if path.is_dir():
                path.chmod(0o755)
        for relative, package in sorted(package_paths(modules).items(),
                                        key=lambda pair: pair[0].count('/'), reverse=True):
            if relative not in locked or relative == 'node_modules/better-sqlite3':
                if package.exists():
                    shutil.rmtree(package)
        for special in (modules / '.package-lock.json', modules / '.bin'):
            if special.is_dir():
                shutil.rmtree(special)
            elif special.exists():
                special.unlink()
        extract(inputs, 'better-sqlite3', sqlite, target)
        sqlite_lock = locked['node_modules/better-sqlite3']
        need(sqlite_lock['version'] == '13.0.3' and
             sqlite_lock['resolved'].endswith('/better-sqlite3-13.0.3.tgz'),
             'application SQLite lock differs')
        for relative, record in locked.items():
            destination = package_root / relative
            if not destination.exists():
                need(relative.endswith('/node-addon-api') and record['version'] == '8.9.2',
                     'unreviewed missing dependency')
                extract(inputs, 'node-addon-api', destination, target)
        observed = package_paths(modules)
        need(set(observed) == set(locked), 'projected package set differs from application lock')
        for relative, package in observed.items():
            need(json.loads((package / 'package.json').read_text())['version'] == locked[relative]['version'],
                 'projected dependency version differs')
    print('NAPI_DEPENDENCY_PROJECTION_VERIFIED ' + target, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acquire', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--target', choices=TARGETS)
    args = parser.parse_args()
    if args.acquire:
        need(not any((args.root, args.app, args.inputs, args.target)), 'acquire arguments differ')
        acquire(args.acquire)
    else:
        need(all((args.root, args.app, args.inputs, args.target)), 'projection arguments missing')
        project(args.root, args.app, args.inputs, args.target)


if __name__ == '__main__':
    main()
