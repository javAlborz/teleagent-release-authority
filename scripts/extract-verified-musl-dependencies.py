#!/usr/bin/python3 -I
"""Materialize one pinned unsigned musl candidate for a later isolated image build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import tarfile
import time
import uuid

HERE = Path(__file__).resolve().parent
checker = runpy.run_path(str(HERE / 'compare-retained-native-candidates.py'),
                         run_name='musl_candidate_checker')
base = checker['base']
PLAN_SHA = '877bf9b1e00cbf627d322a6f3ec6f9a7fb1fa9f47f0aab843e4407536d6dc904'
SUBJECT_SHA = 'd5645fa7e268a92f5e9c2442d9c68f70a1ace456e44e81190047b028fe8ce7cb'
TAR_SHA = '7f5f674aa3c1fb890747e9f8b3dc3c68e9e80633b969dc8f1636303655cfc925'
EPOCH = 1790204008


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def accepted_record(observation):
    summary = base['subject'](observation, 'musl', PLAN_SHA)
    need(summary['dependencySubjectSha256'] == SUBJECT_SHA and
         summary['sourceEpoch'] == EPOCH, 'musl observation subject differs')
    record = observation['projectedCallbackResult'].get('retainedCandidate')
    need(type(record) is dict and set(record) == checker['RECORD_KEYS'] and
         record['schema'] == 'teleagent.unsigned-native-tar.v1' and
         record['authorization'] == 'candidate-data-only-no-release-authority' and
         record['target'] == 'musl' and record['sourceEpoch'] == EPOCH and
         record['dependencySubjectSha256'] == SUBJECT_SHA and
         record['tarSha256'] == TAR_SHA and
         record['dependencyBytes'] == summary['dependencyBytes'] and
         record['dependencyEntries'] == summary['dependencyEntries'] and
         record['receiptIncluded'] is False and record['logsIncluded'] is False and
         record['signatureVerified'] is False and record['releaseApproved'] is False,
         'musl candidate record differs')
    return record


def extract(tar_path, observation_path, destination):
    need(isinstance(destination, Path) and destination.is_absolute() and
         destination.parent.is_dir() and not destination.parent.is_symlink() and
         destination.parent.resolve() == destination.parent and
         not destination.exists() and not destination.is_symlink(),
         'fresh absolute candidate destination required')
    observation = base['load'](observation_path)
    record = accepted_record(observation)
    checked = checker['check_tar'](tar_path, 'musl', record, EPOCH)
    need(checked['tarSha256'] == TAR_SHA and
         checked['dependencySubjectSha256'] == SUBJECT_SHA,
         'musl candidate verification differs')
    stage = destination.parent / ('.' + destination.name + '.partial-' + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    try:
        rows, total, previous = [], 0, ''
        deadline = time.monotonic() + checker['MAX_SECONDS']
        descriptor = os.open(tar_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 before.st_size == record['tarBytes'], 'candidate tar changed before extraction')
            modes = {}
            with os.fdopen(os.dup(descriptor), 'rb') as stream:
                with tarfile.open(fileobj=stream, mode='r:') as archive:
                    for member in archive:
                        need(time.monotonic() < deadline and len(rows) < 50000 and
                             set(member.pax_headers) <= {'path'} and
                             member.uid == member.gid == 0 and
                             member.uname == member.gname == '' and
                             member.mtime == EPOCH and
                             not member.mode & 0o7000 and
                             (member.isdir() or member.isfile()),
                             'candidate tar member changed')
                        name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
                        relative = checker['safe_name'](name, 'musl')
                        need(relative > previous, 'candidate tar order differs')
                        previous = relative
                        output = stage / relative
                        need(output.parent.is_dir() and not output.parent.is_symlink(),
                             'candidate tar parent is absent')
                        row = {'path': relative, 'type': 'directory' if member.isdir() else 'file',
                               'mode': f'{member.mode:04o}'}
                        modes[relative] = (0o555 if member.isdir() or member.mode & 0o111
                                           else 0o444)
                        if member.isdir():
                            need(member.size == 0, 'candidate directory size differs')
                            output.mkdir(mode=0o700)
                        else:
                            need(0 <= member.size <= 256 * 1024 ** 2,
                                 'candidate file size exceeds bound')
                            source = archive.extractfile(member)
                            need(source is not None, 'candidate file unreadable')
                            digest, count = hashlib.sha256(), 0
                            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                            with source, os.fdopen(fd, 'wb') as target:
                                while count < member.size:
                                    need(time.monotonic() < deadline,
                                         'candidate extraction deadline exceeded')
                                    chunk = source.read(min(1024 * 1024, member.size - count))
                                    need(chunk, 'candidate file is short')
                                    target.write(chunk)
                                    digest.update(chunk)
                                    count += len(chunk)
                                target.flush()
                                os.fsync(target.fileno())
                            total += count
                            need(total <= checker['MAX_TAR'], 'candidate dependency bytes exceed bound')
                            row.update({'bytes': count, 'sha256': digest.hexdigest()})
                        rows.append(row)
            after = os.fstat(descriptor)
            need(checker['identity'](before) == checker['identity'](after) ==
                 checker['identity'](os.stat(tar_path, follow_symlinks=False)),
                 'candidate tar changed during extraction')
        finally:
            os.close(descriptor)
        subject = {'schema': 'teleagent.native-export-subject.v1',
                   'target': 'musl', 'entries': rows}
        need(hashlib.sha256(canonical(subject)).hexdigest() == SUBJECT_SHA and
             total == record['dependencyBytes'] and len(rows) == record['dependencyEntries'],
             'extracted dependency subject differs')
        for root, directories, files in os.walk(stage, topdown=False, followlinks=False):
            for name in files:
                item = Path(root) / name
                item.chmod(modes[str(item.relative_to(stage))])
            for name in directories:
                item = Path(root) / name
                item.chmod(modes[str(item.relative_to(stage))])
        stage.chmod(0o555)
        os.rename(stage, destination)
        return {'schema': 'teleagent.extracted-musl-candidate.v1',
                'dependencySubjectSha256': SUBJECT_SHA, 'tarSha256': TAR_SHA,
                'dependencyEntries': len(rows), 'dependencyBytes': total,
                'releaseApproved': False}
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tar', required=True, type=Path)
    parser.add_argument('--observation', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(extract(args.tar, args.observation, args.destination), sort_keys=True))


if __name__ == '__main__':
    main()
