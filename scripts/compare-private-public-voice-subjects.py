#!/usr/bin/python3 -I
"""Compare two exact unsigned Docker archives by their complete image blobs.

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
    'private': ('09881f8961f7d48bba756d5fcda67f0f3282d0c3a0a9b1aff1da6131ae917f06',
                70074368, None),
    'public': ('ebccbff28241433c3c8a2746845a4c2fbadb8e21f0de64162f42febf5fb1c220',
               70074368, ['teleagent-voice-diagnostic:20260924']),
}
EXPECTED_IMAGE_MANIFEST = '6a0f070ea18affdeadb37cecc909bfae5300a44d2db92ee45657bad0c8745655'
EXPECTED_CONFIG = '220c03e14d3bda11322a32f6757d05359bbf300d789d434caf71d15e96ccc39a'
EXPECTED_APP = '5c0bc437ec1731bad1e8c6c348d7c72cd2b7cbfb'


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
         'refs/heads/feat/hosted-capacity-probe-20260923' and
         os.uname().nodename.split('.')[0].lower() != 'hermes',
         'hosted unsigned comparison environment differs')
    private = subject(Path(sys.argv[1]), 'private')
    public = subject(Path(sys.argv[2]), 'public')
    need(private == public and len(private['blobSizes']) == 11,
         'private/public image subjects differ')
    print(json.dumps({'schema': 'teleagent.unsigned-voice-subject-comparison.v1',
                      'privateArchiveSha256': EXPECTED['private'][0],
                      'publicArchiveSha256': EXPECTED['public'][0],
                      'ociManifestSha256': EXPECTED_IMAGE_MANIFEST,
                      'configSha256': EXPECTED_CONFIG,
                      'layerCount': 9, 'allBlobsByteIdentical': True,
                      'releaseAuthority': False, 'scanApproved': False,
                      'installed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
