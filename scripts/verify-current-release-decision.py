#!/usr/bin/python3 -I
"""Verify the exact current Teleagent release evidence before authority signing.

The branch diagnostic may report eligibility, but only the protected main
workflow can create an approved predicate. This program never executes a
bundle member, provider binary, image or scanner.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tarfile

HERE = Path(__file__).resolve().parent
APP = '5c0bc437ec1731bad1e8c6c348d7c72cd2b7cbfb'
TREE = '3ab9261e2de3fdd3083c970a013f0b8d1ebfe12b'
BUNDLE_SHA = '35891889bd46058884f748a0901f9bba0cd593f7bc217dbfbbaf95ff49bc127b'
BUNDLE_SIZE = 840222720
MANIFEST_SHA = 'd47f125bd00fbb0f888f49c0f7e285e9940595bc0fb79bd67b43d632b46320da'
VOICE_SHA = 'ebccbff28241433c3c8a2746845a4c2fbadb8e21f0de64162f42febf5fb1c220'
VOICE_CONFIG = 'sha256:220c03e14d3bda11322a32f6757d05359bbf300d789d434caf71d15e96ccc39a'
PROVIDER_MANIFEST = 'sha256:b03031aa3bc6846cb63cf0fa17ae558fb93df9a2fad5b3fe6ce67ee7d24bbf04'
SCAN_SHA = '7b9b935829c7e9a2a0d50e2db8185f7b52112fc3c2096e859a157bf6a432a5a3'
SCAN_CHECK_SHA = '488618a30afde62d895a567f3911841a096d5455eb0bc868381b298c70de19e3'
DB_METADATA_SHA = '6189769c7be637b4250797410f09bacf0c7ecaa6e296e50988c36093cd321b32'
AUTHORITY_REPO = 'javAlborz/teleagent-release-authority'
AUTHORITY_REPO_ID = '1383172221'
WORKFLOW = '.github/workflows/teleagent-current-release-decision.yml'
PREDICATE_TYPE = 'https://github.com/javAlborz/teleagent-release-authority/attestations/release-decision/v1'
HEX40 = re.compile(r'[a-f0-9]{40}\Z')
INPUT_MANIFESTS = {
    'apk.json': 'dcd6c02ebbf9d26efc9f7bce8c58c9a2ad9dfb6d06da36689cebfe56e276338d',
    'engine.json': 'fa6ca7d6da2b13855fe1d0ddeed6b6b36b756e7c917f78c59c2384a1b5e77ab5',
    'indexes.json': '1194d3519645cc83f07d791dbc23aa7dcfa750a5f2eea06b8ee5378bafe7f620',
    'source-pairs-patched-20260923.json': 'dada99e66a0831b7ab974c392affcabe13b4c1ace13d2e9c9b65155d3c7900a9',
    'tools.json': '54f917a136554099a3872abbdd2965483babec33f71d45f4cbb0eaa8f30badb8',
}
INPUT_SELECTION_SHA = 'bb2a08960b9ef3b6279920a083eea4ba1fc45fe7c9a2e5713bbe12028f3caa59'
SOURCE_RUNS = {
    'nativeBuild': 35935470213,
    'publicVoiceImage': 35992034723,
    'imageComparison': 35992359796,
    'initialScan': 35992468711,
    'voiceSbom': 35992525759,
    'privateImageAttestation': 35992626604,
    'bundle': 35992749716,
    'freshScan': 36028598666,
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def checked_file(path, maximum, expected_size=None):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         0 < info.st_size <= maximum and
         (expected_size is None or info.st_size == expected_size),
         'release evidence file identity differs')
    return info


def file_hash(path, maximum, expected=None, expected_size=None):
    before = checked_file(path, maximum, expected_size)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
          before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
          after.st_ctime_ns) and (expected is None or digest == expected),
         'release evidence file changed or digest differs')
    return digest


def compare_bundles(first, second):
    first_info = checked_file(first, BUNDLE_SIZE, BUNDLE_SIZE)
    second_info = checked_file(second, BUNDLE_SIZE, BUNDLE_SIZE)
    need((first_info.st_dev, first_info.st_ino) !=
         (second_info.st_dev, second_info.st_ino),
         'bundle replicas share one inode')
    with first.open('rb') as left, second.open('rb') as right:
        while True:
            a, b = left.read(8 * 1024 * 1024), right.read(8 * 1024 * 1024)
            need(a == b, 'independent bundle replicas differ')
            if not a:
                break
    file_hash(first, BUNDLE_SIZE, BUNDLE_SHA, BUNDLE_SIZE)
    file_hash(second, BUNDLE_SIZE, BUNDLE_SHA, BUNDLE_SIZE)


def bounded_json(path, maximum, expected_sha=None):
    before = checked_file(path, maximum)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        need((opened.st_dev, opened.st_ino, opened.st_size) ==
             (before.st_dev, before.st_ino, before.st_size),
             'JSON evidence changed before reading')
        data = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        need(len(data) == before.st_size and
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
              after.st_ctime_ns) ==
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
              before.st_ctime_ns) and
             (expected_sha is None or
              hashlib.sha256(data).hexdigest() == expected_sha),
             'JSON evidence changed or digest differs')
        return json.loads(data)
    finally:
        os.close(descriptor)


def verify_summary(value):
    expected = {
        'schema': 'teleagent.release-bundle-diagnostic.v1',
        'authorization': 'unsigned-source-only-no-release-authority',
        'applicationRevision': APP, 'applicationTree': TREE,
        'bundleBytes': BUNDLE_SIZE, 'bundleSha256': BUNDLE_SHA,
        'releaseManifestSha256': MANIFEST_SHA,
        'voiceImageTarSha256': VOICE_SHA,
        'voiceSbomSha256': '6705bf4b3a8baa308719522061e9dc7d1fb62b3aec9fc90891f21af6dab9f349',
        'glibcTarSha256': '3001c2ffb4f6cfda7032ee7a3dda684fcae0991860491be38e205bdf51e5f10a',
        'hostDependencyFiles': 4508, 'sourceEntries': 599,
        'sbomAbsoluteReleasePathsNormalized': 25,
        'scanApproved': False, 'signatureVerified': False,
        'releaseApproved': False, 'installed': False,
    }
    need(type(value) is dict and set(value) == set(expected) and
         all(type(value[key]) is type(item) and value[key] == item
             for key, item in expected.items()),
         'unsigned release summary differs from the fixed candidate')


def verify_manifest(bundle):
    release = 'sha256-' + MANIFEST_SHA
    name = release + '/teleagent-release.manifest.json'
    with tarfile.open(bundle, 'r:') as archive:
        need(archive.getmembers()[0].name == release,
             'release archive top level differs')
        member = archive.getmember(name)
        need(member.isfile() and 0 < member.size <= 262144,
             'release manifest member differs')
        raw = archive.extractfile(member).read()
    need(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA,
         'release manifest digest differs')
    manifest = json.loads(raw)
    need(raw == (json.dumps(manifest, ensure_ascii=True, separators=(',', ':'),
                            allow_nan=False) + '\n').encode('ascii'),
         'release manifest encoding differs')
    need(manifest['version'] == 2 and manifest['application'] == 'teleagent' and
         manifest['source'] == {
             'repository': 'https://github.com/javAlborz/teleagent.git',
             'revision': APP, 'tree': TREE} and
         manifest['voiceImage']['archiveSha256'] == 'sha256:' + VOICE_SHA and
         manifest['voiceImage']['configDigest'] == VOICE_CONFIG and
         manifest['voiceImage']['registryReference'] is None and
         manifest['voiceImage']['registryManifestDigest'] is None and
         manifest['providerCli']['manifestSha256'] == PROVIDER_MANIFEST,
         'release manifest semantic binding differs')
    return manifest


def verify_scan(image, report, metadata, check, now):
    file_hash(image, 300_000_000, VOICE_SHA)
    file_hash(report, 10_000_000, SCAN_SHA)
    file_hash(metadata, 65536, DB_METADATA_SHA)
    observed_check = bounded_json(check, 65536, SCAN_CHECK_SHA)
    spec = importlib.util.spec_from_file_location(
        'teleagent_voice_scan_check', HERE / 'verify-voice-scan-diagnostic.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    computed = verifier.verify(image, report, metadata, now)
    need(computed == observed_check and computed['findingCount'] == 0 and
         computed['scanApproved'] is False and
         computed['releaseApproved'] is False,
         'fresh scanner evidence differs')
    return computed


def verify_selected_inputs():
    root = HERE.parent / 'inputs/teleagent'
    need(set(path.name for path in root.iterdir() if path.is_file()) ==
         set(INPUT_MANIFESTS) | {'source-pairs.json', 'trivy.json'},
         'authority input manifest set differs')
    for name, digest in INPUT_MANIFESTS.items():
        file_hash(root / name, 5_000_000, digest)
    selection = (json.dumps(INPUT_MANIFESTS, sort_keys=True,
                            separators=(',', ':')) + '\n').encode('ascii')
    need(hashlib.sha256(selection).hexdigest() == INPUT_SELECTION_SHA,
         'selected input policy digest differs')
    return INPUT_SELECTION_SHA


def verify_inputs(first_bundle, second_bundle, first_summary, second_summary,
                  image, report, metadata, check, now):
    need(now.tzinfo is not None, 'release decision time must be UTC-aware')
    selected_inputs = verify_selected_inputs()
    compare_bundles(first_bundle, second_bundle)
    summaries = [bounded_json(path, 65536) for path in
                 (first_summary, second_summary)]
    need(summaries[0] == summaries[1], 'independent bundle summaries differ')
    verify_summary(summaries[0])
    manifest = verify_manifest(first_bundle)
    scan = verify_scan(image, report, metadata, check, now)
    return {
        'schema': 'teleagent.release-decision.v1',
        'applicationRevision': APP, 'applicationTree': TREE,
        'bundleSha256': BUNDLE_SHA,
        'bundleBytes': BUNDLE_SIZE,
        'releaseManifestSha256': MANIFEST_SHA,
        'voiceImageSha256': VOICE_SHA,
        'voiceImageConfigDigest': VOICE_CONFIG,
        'providerCliManifestSha256': PROVIDER_MANIFEST,
        'inputSelectionSha256': selected_inputs,
        'scanReportSha256': SCAN_SHA,
        'scanDatabaseMetadataSha256': DB_METADATA_SHA,
        'scanDatabaseNextUpdate': scan['databaseNextUpdate'],
        'scanTargets': scan['targets'],
        'scanFindingCount': 0,
        'releaseId': 'sha256-' + MANIFEST_SHA,
        'registryReference': manifest['voiceImage']['registryReference'],
        'registryManifestDigest': manifest['voiceImage']['registryManifestDigest'],
        'environment': 'hermes-shared',
        'sourceRuns': SOURCE_RUNS,
    }


def authorized_context(environment):
    need(environment.get('GITHUB_ACTIONS') == 'true' and
         environment.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
         environment.get('GITHUB_REPOSITORY') == AUTHORITY_REPO and
         environment.get('GITHUB_REPOSITORY_ID') == AUTHORITY_REPO_ID and
         environment.get('GITHUB_REF') == 'refs/heads/main' and
         environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
         environment.get('GITHUB_WORKFLOW_REF') ==
         AUTHORITY_REPO + '/' + WORKFLOW + '@refs/heads/main' and
         type(environment.get('GITHUB_SHA')) is str and
         HEX40.fullmatch(environment['GITHUB_SHA']),
         'accepted release decision requires the protected authority main workflow')
    return environment['GITHUB_SHA']


def decision(candidate, *, authorize, environment):
    result = dict(candidate)
    result['predicateType'] = PREDICATE_TYPE
    result['releaseApproved'] = False
    result['scanApproved'] = False
    result['signatureVerified'] = False
    result['installed'] = False
    if authorize:
        result['authorityRevision'] = authorized_context(environment)
        result['scanApproved'] = True
        result['releaseApproved'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle-a', 'bundle-b', 'summary-a', 'summary-b', 'voice-image',
                 'scan-report', 'scan-metadata', 'scan-check', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--authorize', action='store_true')
    args = parser.parse_args()
    candidate = verify_inputs(
        args.bundle_a, args.bundle_b, args.summary_a, args.summary_b,
        args.voice_image, args.scan_report, args.scan_metadata,
        args.scan_check, datetime.now(timezone.utc))
    result = decision(candidate, authorize=args.authorize,
                      environment=os.environ)
    data = (json.dumps(result, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('ascii')
    need(not args.output.exists() and len(data) <= 16384,
         'release decision destination is unsafe')
    with args.output.open('xb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({'schema': result['schema'],
                      'releaseApproved': result['releaseApproved'],
                      'bundleSha256': result['bundleSha256'],
                      'scanFindingCount': result['scanFindingCount']},
                     sort_keys=True))


if __name__ == '__main__':
    main()
