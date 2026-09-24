#!/usr/bin/python3 -I
"""Compare two fresh hosted unsigned voice images and every complete image blob.

The Docker export envelope can differ by RepoTag. This check rehashes every
blob and requires the OCI image subject, config and ordered layers to match.
It grants no scan, signature, release or installation authority.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

MAX_ARCHIVE = 100 * 1024 * 1024
EXPECTED = {
    'first': ('9098953337ff923718b75c42ae9d3a48a8cb35a69ddbaa52f72f69c295b3526e',
              70074368, ['teleagent-voice-diagnostic:20260924']),
    'second': ('9098953337ff923718b75c42ae9d3a48a8cb35a69ddbaa52f72f69c295b3526e',
               70074368, ['teleagent-voice-diagnostic:20260924']),
}
EXPECTED_IMAGE_MANIFEST = '239bca5a6afa34ce9c0c6dbc6be39b33e6fb420a3452bd8e36f1bebd2820a7f5'
EXPECTED_CONFIG = '40afbf94961c7501f215fefcc4c77477b75f605f0cc5885d6270a1c50127bab3'
EXPECTED_APP = 'fd254f37a3017ad3475449987197706bbdbe7be7'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def exact_file(path, label):
    info = path.lstat()
    sha, count, _ = EXPECTED[label]
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         info.st_size == count and count <= MAX_ARCHIVE,
         'unsigned archive metadata differs')
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    after = path.lstat()
    need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
          after.st_ctime_ns) and digest == sha,
         'unsigned archive bytes differ from exact run')


def bounded_json(archive, members, name, maximum):
    row = members[name]
    need(row.isfile() and 0 < row.size <= maximum, 'Docker archive JSON size differs')
    source = archive.extractfile(row)
    need(source is not None, 'Docker archive JSON unreadable')
    data = source.read(maximum + 1)
    need(len(data) == row.size, 'Docker archive JSON read differs')
    return json.loads(data)


def subject(path, label):
    exact_file(path, label)
    with tarfile.open(path, 'r:') as archive:
        members = {}
        for row in archive:
            need(len(members) < 32 and row.name not in members and
                 (row.name in ('blobs', 'blobs/sha256', 'index.json',
                               'manifest.json', 'oci-layout') or
                  re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', row.name)),
                 'Docker archive member name or count differs')
            need(row.type in (tarfile.REGTYPE, tarfile.DIRTYPE) and
                 row.mtime == 0 and row.uid == 0 and row.gid == 0 and
                 row.size <= MAX_ARCHIVE and not row.pax_headers,
                 'Docker archive member metadata differs')
            members[row.name] = row
        need({'blobs', 'blobs/sha256', 'index.json', 'manifest.json', 'oci-layout'} <=
             set(members), 'Docker archive structure differs')
        blobs = {}
        for name, row in members.items():
            if not name.startswith('blobs/sha256/'):
                continue
            need(row.isfile() and row.size > 0, 'image blob metadata differs')
            source = archive.extractfile(row)
            need(source is not None, 'image blob unreadable')
            digest = hashlib.sha256()
            total = 0
            for block in iter(lambda: source.read(1024 * 1024), b''):
                total += len(block)
                need(total <= MAX_ARCHIVE, 'image blob exceeds bound')
                digest.update(block)
            need(total == row.size and digest.hexdigest() == name.rsplit('/', 1)[1],
                 'image blob digest differs')
            blobs[name] = row.size
        manifest = bounded_json(archive, members, 'manifest.json', 4096)
        need(type(manifest) is list and len(manifest) == 1 and
             type(manifest[0]) is dict and
             set(manifest[0]) == {'Config', 'Layers', 'RepoTags'} and
             manifest[0]['RepoTags'] == EXPECTED[label][2] and
             manifest[0]['Config'] == 'blobs/sha256/' + EXPECTED_CONFIG and
             type(manifest[0]['Layers']) is list and
             len(manifest[0]['Layers']) == 9 and
             len(set(manifest[0]['Layers'])) == 9 and
             all(name in blobs for name in manifest[0]['Layers']),
             'Docker image manifest differs')
        index = bounded_json(archive, members, 'index.json', 4096)
        need(type(index) is dict and index.get('schemaVersion') == 2 and
             type(index.get('manifests')) is list and len(index['manifests']) == 1 and
             index['manifests'][0].get('digest') ==
             'sha256:' + EXPECTED_IMAGE_MANIFEST and
             'blobs/sha256/' + EXPECTED_IMAGE_MANIFEST in blobs,
             'OCI image index subject differs')
        config = bounded_json(archive, members,
                              'blobs/sha256/' + EXPECTED_CONFIG, 64 * 1024)
        need(config.get('architecture') == 'amd64' and config.get('os') == 'linux' and
             config.get('config', {}).get('Labels', {}).get(
                 'org.opencontainers.image.revision') == EXPECTED_APP,
             'image config app identity differs')
        return {'ociManifestSha256': EXPECTED_IMAGE_MANIFEST,
                'configSha256': EXPECTED_CONFIG,
                'layers': list(manifest[0]['Layers']),
                'blobSizes': blobs}


def main():
    need(len(sys.argv) == 3 and
         os.environ.get('GITHUB_ACTIONS') == 'true' and
         os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
         os.environ.get('GITHUB_REPOSITORY') == 'javAlborz/teleagent-release-authority' and
         os.environ.get('GITHUB_REF') ==
         'refs/heads/fix/teleagent-v3-gate-release' and
         os.uname().nodename.split('.')[0].lower() != 'hermes',
         'hosted unsigned comparison environment differs')
    first_path, second_path = Path(sys.argv[1]), Path(sys.argv[2])
    need((first_path.stat().st_dev, first_path.stat().st_ino) !=
         (second_path.stat().st_dev, second_path.stat().st_ino),
         'independent hosted archives must use separate inodes')
    first = subject(first_path, 'first')
    second = subject(second_path, 'second')
    need(first == second and len(first['blobSizes']) == 11,
         'independent hosted image subjects differ')
    with first_path.open('rb') as left, second_path.open('rb') as right:
        while True:
            left_chunk, right_chunk = left.read(1024 * 1024), right.read(1024 * 1024)
            need(left_chunk == right_chunk, 'independent hosted archive bytes differ')
            if not left_chunk:
                break
    print(json.dumps({'schema': 'teleagent.hosted-voice-replica-comparison.v1',
                      'firstArchiveSha256': EXPECTED['first'][0],
                      'secondArchiveSha256': EXPECTED['second'][0],
                      'ociManifestSha256': EXPECTED_IMAGE_MANIFEST,
                      'configSha256': EXPECTED_CONFIG,
                      'layerCount': 9, 'allBlobsByteIdentical': True, 'fullArchiveByteIdentical': True,
                      'releaseAuthority': False, 'scanApproved': False,
                      'installed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
