#!/usr/bin/python3 -I
"""Reconstruct four unsigned dependency tars; never grant release authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import tarfile
import time

HERE = Path(__file__).resolve().parent
base = runpy.run_path(str(HERE / 'compare-native-diagnostic-observations.py'),
                      run_name='retained_native_observation_comparison')
SHA = re.compile(r'[a-f0-9]{64}\Z')
MAX_TAR = 512 * 1024 ** 2
MAX_SECONDS = 180
ROOTS = {'glibc': {'root', 'cli', 'claude-api-server', 'privileged-action-broker',
                   'realtime-sip-gateway'}, 'musl': {'voice-app'}}
RECORD_KEYS = {'schema', 'authorization', 'target', 'sourceEpoch',
               'dependencySubjectSha256', 'dependencyBytes', 'dependencyEntries',
               'tarSha256', 'tarBytes', 'receiptIncluded', 'logsIncluded',
               'signatureVerified', 'releaseApproved'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def safe_name(name, target):
    need(type(name) is str and name.startswith(target + '/') and
         not name.startswith('/') and len(name.encode('utf-8')) <= 2054,
         'candidate tar path differs')
    relative = name[len(target) + 1:]
    parts = relative.split('/')
    need(parts[0] in ROOTS[target] and all(
         part not in ('', '.', '..') and len(part.encode('utf-8')) <= 255 and
         '\\' not in part and all(32 <= ord(char) != 127 for char in part)
         for part in parts), 'candidate tar member name differs')
    return relative


def check_tar(path, target, record, epoch):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    deadline = time.monotonic() + MAX_SECONDS
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= MAX_TAR and before.st_size == record['tarBytes'],
             'candidate tar metadata differs')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            tar_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            need(tar_digest == record['tarSha256'], 'candidate tar digest differs')
            stream.seek(0)
            rows = []
            total = 0
            previous = ''
            with tarfile.open(fileobj=stream, mode='r:') as archive:
                for member in archive:
                    need(time.monotonic() < deadline and len(rows) < 50000 and
                         type(member.name) is str and
                         set(member.pax_headers) <= {'path'} and
                         member.uid == member.gid == 0 and
                         member.uname == member.gname == '' and
                         member.mtime == epoch and
                         0 <= member.mode <= 0o777 and
                         not member.mode & 0o7000,
                         'candidate tar header differs')
                    is_directory = member.isdir()
                    need(is_directory or member.isfile(),
                         'candidate tar contains a non-file member')
                    name = member.name[:-1] if is_directory and member.name.endswith('/') else member.name
                    relative = safe_name(name, target)
                    need(relative > previous, 'candidate tar order or duplicate differs')
                    previous = relative
                    row = {'path': relative,
                           'type': 'directory' if is_directory else 'file',
                           'mode': f'{member.mode:04o}'}
                    if is_directory:
                        need(member.size == 0, 'candidate tar directory size differs')
                    else:
                        need(0 <= member.size <= 256 * 1024 ** 2,
                             'candidate tar file exceeds bound')
                        total += member.size
                        need(total <= MAX_TAR, 'candidate tar dependency bytes exceed bound')
                        digest = hashlib.sha256()
                        count = 0
                        selected = archive.extractfile(member)
                        need(selected is not None, 'candidate tar file is unreadable')
                        with selected:
                            while True:
                                need(time.monotonic() < deadline,
                                     'candidate tar verification deadline exceeded')
                                chunk = selected.read(min(1024 * 1024,
                                                          member.size + 1 - count))
                                if not chunk:
                                    break
                                count += len(chunk)
                                need(count <= member.size,
                                     'candidate tar file grew while reading')
                                digest.update(chunk)
                        need(count == member.size, 'candidate tar file is short')
                        row.update({'bytes': count, 'sha256': digest.hexdigest()})
                    rows.append(row)
        subject = {'schema': 'teleagent.native-export-subject.v1',
                   'target': target, 'entries': rows}
        subject_digest = hashlib.sha256(
            (json.dumps(subject, sort_keys=True, separators=(',', ':')) + '\n').encode()
        ).hexdigest()
        need(subject_digest == record['dependencySubjectSha256'] and
             len(rows) == record['dependencyEntries'] and
             total == record['dependencyBytes'],
             'candidate tar reconstructed subject differs')
        need(identity(os.fstat(descriptor)) == identity(before) and
             identity(os.stat(path, follow_symlinks=False)) == identity(before),
             'candidate tar changed while verifying')
        return {'tarSha256': tar_digest, 'tarBytes': before.st_size,
                'dependencySubjectSha256': subject_digest,
                'dependencyEntries': len(rows), 'dependencyBytes': total}
    finally:
        os.close(descriptor)


def compare(observations, tars, plan_sha):
    baseline = base['compare'](observations, plan_sha)
    need(tars.is_absolute() and tars.is_dir() and not tars.is_symlink() and
         tars.resolve() == tars and
         {item.name for item in tars.iterdir()} ==
         {f'{target}-{replica}.tar' for target in ROOTS for replica in ('1', '2')},
         'candidate tar set differs')
    subjects = {}
    for target in ROOTS:
        verified = []
        for replica in ('1', '2'):
            observation = base['load'](observations / f'{target}-{replica}.json')
            callback = observation['projectedCallbackResult']
            record = callback.get('retainedCandidate')
            need(type(record) is dict and set(record) == RECORD_KEYS and
                 record['schema'] == 'teleagent.unsigned-native-tar.v1' and
                 record['authorization'] == 'candidate-data-only-no-release-authority' and
                 record['target'] == target and
                 record['sourceEpoch'] == observation['sourceEpoch'] and
                 record['dependencySubjectSha256'] == callback['dependencySubjectSha256'] and
                 record['dependencyBytes'] == callback['dependencyBytes'] and
                 record['dependencyEntries'] == callback['dependencyEntries'] and
                 type(record['tarSha256']) is str and SHA.fullmatch(record['tarSha256']) and
                 type(record['tarBytes']) is int and 0 < record['tarBytes'] <= MAX_TAR and
                 record['receiptIncluded'] is False and record['logsIncluded'] is False and
                 record['signatureVerified'] is False and record['releaseApproved'] is False,
                 'candidate tar observation differs')
            verified.append(check_tar(tars / f'{target}-{replica}.tar',
                                      target, record, observation['sourceEpoch']))
        need(verified[0] == verified[1],
             'independent ' + target + ' retained candidate differs')
        subjects[target] = verified[0]
    return {'schema': 'teleagent.unsigned-retained-native-comparison.v1',
            'authorization': 'candidate-data-only-no-release-authority',
            'unsignedBuildPlanSha256': plan_sha,
            'matchingDependencySubjects': baseline['matchingDependencySubjects'],
            'matchingRetainedTars': subjects,
            'artifactRetained': True, 'signatureVerified': False,
            'releaseApproved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observations', required=True, type=Path)
    parser.add_argument('--tars', required=True, type=Path)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(compare(args.observations, args.tars, args.plan_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
