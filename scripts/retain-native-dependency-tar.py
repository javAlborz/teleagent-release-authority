#!/usr/bin/python3 -I
"""Retain a bounded deterministic dependency tar after an isolated build exits.

This is a source-only candidate. Its caller must first prove whole-engine/cgroup
quiescence and must still require the surrounding quota cleanup before upload.
It copies only the export inventory's dependency subject; receipt and logs stay
outside the deterministic artifact.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time

EXPORT_SHA256 = '944f425f95adb5a3ddd8a7149f7a7c43b069cbf649cd172023ea8834d030daca'
MAX_TAR_BYTES = 512 * 1024 ** 2
MAX_SECONDS = 180
SHA = re.compile(r'[a-f0-9]{64}\Z')
ROOTS = {'glibc': {'root', 'cli', 'claude-api-server', 'privileged-action-broker',
                   'realtime-sip-gateway'}, 'musl': {'voice-app'}}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def components(name):
    need(type(name) is str and 0 < len(name.encode('utf-8')) <= 2048 and
         all(part not in ('', '.', '..') and len(part.encode('utf-8')) <= 255 and
             '\\' not in part and all(32 <= ord(char) != 127 for char in part)
             for part in name.split('/')), 'unsafe dependency path')
    return name.split('/')


def open_child(root_fd, parts, *, directory):
    held = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            newer = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
            os.close(held)
            held = newer
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        if directory:
            flags |= os.O_DIRECTORY
        child = os.open(parts[-1], flags, dir_fd=held)
        return child
    finally:
        os.close(held)


class DigestReader:
    def __init__(self, fd):
        self.fd = fd
        self.count = 0
        self.digest = hashlib.sha256()

    def read(self, size):
        data = os.read(self.fd, size)
        self.count += len(data)
        self.digest.update(data)
        return data


def retain(root, target, source, destination, expected_subject, epoch):
    need(target in ROOTS and type(expected_subject) is str and
         SHA.fullmatch(expected_subject) and type(epoch) is int and
         0 <= epoch <= 2 ** 32 - 1, 'artifact identity differs')
    need(root.is_absolute() and root.is_dir() and not root.is_symlink() and
         root.resolve() == root and source.is_absolute() and
         destination.is_absolute() and destination.parent.is_dir() and
         destination.parent.resolve() == destination.parent and
         not destination.parent.is_symlink() and
         stat.S_IMODE(destination.parent.stat().st_mode) == 0o700 and
         not destination.exists(),
         'artifact path differs')
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        source_info = os.fstat(source_fd)
        source_bytes = os.read(source_fd, 1024 * 1024 + 1)
        need(stat.S_ISREG(source_info.st_mode) and source_info.st_nlink == 1 and
             source_info.st_size <= 1024 * 1024 and
             len(source_bytes) == source_info.st_size and
             hashlib.sha256(source_bytes).hexdigest() ==
             EXPORT_SHA256 and identity(os.fstat(source_fd)) == identity(source_info),
             'export inventory source differs')
    finally:
        os.close(source_fd)
    export = {'__name__': 'retained_native_export_inventory',
              '__file__': str(source)}
    exec(compile(source_bytes, str(source), 'exec'), export)
    observed = export['inventory'](root, target)
    need(observed['subjectSha256'] == expected_subject and
         observed['logReferencesVerified'] is True and
         observed['logsExported'] is True and
         observed['releaseApproved'] is False and
         observed['independentRebuild'] is False and
         0 < observed['dependencyBytes'] <= MAX_TAR_BYTES,
         'dependency inventory or prior subject differs')
    entries = observed['subject']['entries']
    need(type(entries) is list and 0 < len(entries) <= 50000,
         'dependency inventory entries differ')
    deadline = time.monotonic() + MAX_SECONDS
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                      os.O_NOFOLLOW | os.O_CLOEXEC)
    output_fd = None
    try:
        need(stat.S_ISDIR(os.fstat(root_fd).st_mode), 'dependency root differs')
        output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                            os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(output_fd, 'wb', closefd=False) as stream:
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
                previous = ''
                for row in entries:
                    need(time.monotonic() < deadline and type(row) is dict and
                         set(row) == ({'path', 'type', 'mode'} if row.get('type') == 'directory'
                                      else {'path', 'type', 'mode', 'bytes', 'sha256'}),
                         'dependency row or deadline differs')
                    name = row['path']
                    parts = components(name)
                    need(parts[0] in ROOTS[target] and name > previous,
                         'dependency row order or root differs')
                    previous = name
                    mode = int(row['mode'], 8)
                    need(0 <= mode <= 0o777 and not mode & 0o7000,
                         'dependency mode differs')
                    is_directory = row['type'] == 'directory'
                    need(is_directory or row['type'] == 'file',
                         'dependency entry type differs')
                    fd = open_child(root_fd, parts, directory=is_directory)
                    try:
                        before = os.fstat(fd)
                        need((stat.S_ISDIR(before.st_mode) if is_directory else
                              stat.S_ISREG(before.st_mode) and before.st_nlink == 1) and
                             stat.S_IMODE(before.st_mode) == mode,
                             'dependency entry metadata differs')
                        item = tarfile.TarInfo(target + '/' + name + ('/' if is_directory else ''))
                        item.uid = item.gid = 0
                        item.uname = item.gname = ''
                        item.mtime = epoch
                        item.mode = mode
                        if is_directory:
                            item.type = tarfile.DIRTYPE
                            item.size = 0
                            archive.addfile(item)
                        else:
                            need(type(row['bytes']) is int and
                                 0 <= row['bytes'] <= 256 * 1024 ** 2 and
                                 before.st_size == row['bytes'] and
                                 type(row['sha256']) is str and SHA.fullmatch(row['sha256']),
                                 'dependency file size or digest differs')
                            item.type = tarfile.REGTYPE
                            item.size = row['bytes']
                            reader = DigestReader(fd)
                            archive.addfile(item, reader)
                            need(reader.count == row['bytes'] and
                                 reader.digest.hexdigest() == row['sha256'],
                                 'dependency file changed during archive')
                        need(identity(os.fstat(fd)) == identity(before),
                             'dependency entry changed during archive')
                    finally:
                        os.close(fd)
        os.fsync(output_fd)
        info = os.fstat(output_fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             0 < info.st_size <= MAX_TAR_BYTES and
             time.monotonic() < deadline,
             'retained dependency tar exceeds bound')
    except Exception:
        if output_fd is not None:
            os.close(output_fd)
            destination.unlink(missing_ok=True)
            output_fd = None
        raise
    finally:
        os.close(root_fd)
        if output_fd is not None:
            os.close(output_fd)
    try:
        digest_fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(digest_fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 < before.st_size <= MAX_TAR_BYTES,
                 'retained dependency tar metadata differs')
            with os.fdopen(os.dup(digest_fd), 'rb') as stream:
                archive_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            need(identity(os.fstat(digest_fd)) == identity(before) and
                 identity(os.stat(destination, follow_symlinks=False)) == identity(before),
                 'retained dependency tar changed after hashing')
        finally:
            os.close(digest_fd)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return {'schema': 'teleagent.unsigned-native-tar.v1',
            'authorization': 'candidate-data-only-no-release-authority',
            'target': target, 'sourceEpoch': epoch,
            'dependencySubjectSha256': expected_subject,
            'dependencyBytes': observed['dependencyBytes'],
            'dependencyEntries': len(entries),
            'tarSha256': archive_digest, 'tarBytes': destination.stat().st_size,
            'receiptIncluded': False, 'logsIncluded': False,
            'signatureVerified': False, 'releaseApproved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--target', required=True, choices=tuple(ROOTS))
    parser.add_argument('--inventory-source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--subject-sha256', required=True)
    parser.add_argument('--epoch', required=True, type=int)
    args = parser.parse_args()
    print(json.dumps(retain(args.root, args.target, args.inventory_source,
                            args.output, args.subject_sha256, args.epoch), sort_keys=True))


if __name__ == '__main__':
    main()
