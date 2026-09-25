#!/usr/bin/python3 -I
"""Bind a fresh Trivy report to the fixed unsigned v5 hosted voice image.

This is an evidence check, not release or scan-policy approval.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import tarfile

IMAGE_SHA256 = 'b7882e453a4d5936f8b8e758c0822e099b6eedf41ef81edcd878da65cc96df2b'
APP_REVISION = 'a256435586df2c5a403e9cb9b5cde98eab498448'
IMAGE_NAME = 'teleagent-v5-voice-image.docker.tar'
HEX = re.compile(r'[0-9a-f]{64}\Z')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path, maximum):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
         'evidence file size or type differs')
    return json.loads(path.read_bytes())


def verify(image, report_path, metadata_path, now):
    need(image.is_file() and not image.is_symlink() and
         0 < image.stat().st_size <= 500_000_000, 'image size or type differs')
    with image.open('rb') as stream:
        image_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    need(image_digest == IMAGE_SHA256, 'unsigned image digest differs')
    with tarfile.open(image, 'r:') as archive:
        member = archive.getmember('manifest.json')
        need(member.isfile() and 0 < member.size <= 65_536, 'image manifest differs')
        manifest = json.load(archive.extractfile(member))
        need(type(manifest) is list and len(manifest) == 1 and
             manifest[0].get('RepoTags') == ['teleagent-v5-voice-diagnostic:20260925'],
             'image tag differs')
        config_name = manifest[0].get('Config')
        need(type(config_name) is str and
             re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', config_name),
             'image config name differs')
        config_member = archive.getmember(config_name)
        need(config_member.isfile() and 0 < config_member.size <= 1_048_576,
             'image config differs')
        config_bytes = archive.extractfile(config_member).read()
        need(hashlib.sha256(config_bytes).hexdigest() == config_name.split('/')[-1],
             'image config digest differs')
        config = json.loads(config_bytes)
        need(config['config']['Labels'].get('org.opencontainers.image.revision') ==
             APP_REVISION, 'image application revision differs')

    report = read_json(report_path, 10_000_000)
    need(report.get('SchemaVersion') == 2 and report.get('ArtifactType') ==
         'container_image' and report.get('Trivy') == {'Version': '0.72.0'},
         'scanner report schema or version differs')
    need(report.get('ArtifactName', '').endswith('/' + IMAGE_NAME),
         'scanner artifact name differs')
    report_metadata = report.get('Metadata')
    need(type(report_metadata) is dict and
         report_metadata.get('ImageID') == 'sha256:' + config_name.split('/')[-1] and
         report_metadata.get('ImageConfig', {}).get('config', {}).get('Labels', {}).get(
             'org.opencontainers.image.revision') == APP_REVISION,
         'scanner image identity differs')
    results = report.get('Results')
    need(type(results) is list and len(results) == 2,
         'scanner target coverage differs')
    by_kind = {}
    for row in results:
        need(type(row) is dict and type(row.get('Packages')) is list and
             len(row['Packages']) > 0 and not row.get('Vulnerabilities') and
             not row.get('Secrets'),
             'scanner target empty or findings present')
        kind = (row.get('Class'), row.get('Type'))
        need(kind not in by_kind, 'duplicate scanner target')
        by_kind[kind] = row
    need(set(by_kind) == {('os-pkgs', 'alpine'), ('lang-pkgs', 'node-pkg')} and
         'alpine 3.24.1' in by_kind[('os-pkgs', 'alpine')]['Target'] and
         by_kind[('lang-pkgs', 'node-pkg')]['Target'] == 'Node.js',
         'scanner target identity differs')
    qs = [row for row in by_kind[('lang-pkgs', 'node-pkg')]['Packages']
          if row.get('Name') == 'qs']
    need(len(qs) == 1 and qs[0].get('Version') == '6.16.0',
         'patched qs package absent from scanner inventory')

    metadata = read_json(metadata_path, 65_536)
    next_update = datetime.fromisoformat(metadata['NextUpdate'].replace('Z', '+00:00'))
    need(now.tzinfo is not None and next_update.tzinfo is not None and
         next_update > now + timedelta(hours=1), 'scanner database is stale')
    return {'schema': 'teleagent.voice-scan-diagnostic-check.v1',
            'authorization': 'diagnostic-only-no-release-authority',
            'imageSha256': image_digest,
            'reportSha256': hashlib.sha256(report_path.read_bytes()).hexdigest(),
            'databaseMetadataSha256': hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
            'databaseNextUpdate': next_update.isoformat(),
            'targets': sorted([{'class': klass, 'type': kind,
                                'packageCount': len(row['Packages'])}
                               for (klass, kind), row in by_kind.items()],
                              key=lambda item: item['class']),
            'findingCount': 0, 'scanApproved': False,
            'signatureVerified': False, 'releaseApproved': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--metadata', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.image, args.report, args.metadata,
                            datetime.now(timezone.utc)), sort_keys=True))
