#!/usr/bin/python3 -I
"""Verify the exact v58 Teleagent release evidence before authority signing.

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
APP = '707d2da6f2338da72d1b16e932958cacb5e2f422'
TREE = '87a476793d130a9441307b0a1426b4a4586cc15c'
BUNDLE_SHA = '22bad00a40120436041f184b60fdef144cb2f2d5e209991bfe036f7ad924f76c'
BUNDLE_SIZE = 896665600
MANIFEST_SHA = '553be21abf61b1329b46ab0eaf44226b090197e7e8b9deb765ef87407dbddd3b'
VOICE_SHA = '46e17f4001b7381fc433c3c8b9a735958f601550757200a9e43dcd2a27432224'
VOICE_CONFIG = 'sha256:fe8868dbabf56de825ce12c1ff2aed68efe9bfc9862a5569852043454751b6e4'
PROVIDER_MANIFEST = 'sha256:3f75ef0c36f8e8c0131b725a3143458b83da954b6aebe253241cc05981273c8b'
SCAN_SHA = '02725bc29dcf63f5b55e7d80885252922f2a08d5caed36f444a2dc991aa6b68c'
SCAN_CHECK_SHA = '5c54da660e5d156c914d1375c8e0e2bf144f59cea3e3e53c3372f6d2d847a907'
DB_METADATA_SHA = 'cb7f87d36b8e0bd9952b88cec7af0cfd792fda428143a3e30e6819df13c8be36'
AUTHORITY_REPO = 'javAlborz/teleagent-release-authority'
AUTHORITY_REPO_ID = '1383172221'
WORKFLOW = '.github/workflows/teleagent-v58-release-decision.yml'
PREDICATE_TYPE = 'https://github.com/javAlborz/teleagent-release-authority/attestations/release-decision/v1'
HEX40 = re.compile(r'[a-f0-9]{40}\Z')
INPUT_MANIFESTS = {'apk.json': 'dcd6c02ebbf9d26efc9f7bce8c58c9a2ad9dfb6d06da36689cebfe56e276338d',
 'controller-ws-v50.json': 'b707dbcb234f65b62470210fda724574650d011ed1a87466cc9525747d00296d',
 'engine.json': 'fa6ca7d6da2b13855fe1d0ddeed6b6b36b756e7c917f78c59c2384a1b5e77ab5',
 'indexes.json': '1194d3519645cc83f07d791dbc23aa7dcfa750a5f2eea06b8ee5378bafe7f620',
 'source-pairs-patched-20260923.json': 'dada99e66a0831b7ab974c392affcabe13b4c1ace13d2e9c9b65155d3c7900a9',
 'source-pairs-v17-20260926.json': '0518fb03ede3624a45798c66860ea8d29e62d52def9cddca087949a2ceff5e82',
 'source-pairs-v50-20260930.json': 'd577efc2b88f666b0a65d6700bfcf5b65b11c66e0d1ef4c1120ace8bb0f86db5',
 'source-pairs-v53-20261001.json': '0ddb1678b5730db4056a6540d3011d7180b45b34b39de142e73e5594dca8dc5e',
 'sqlite-napi-v17.json': '1cbcc979bd96c155e1e11944f9dbd33db2939ee9469b43672c1d4c8fc77cd0ce',
 'tools.json': '54f917a136554099a3872abbdd2965483babec33f71d45f4cbb0eaa8f30badb8',
 'voice-axios-v53.json': '3b26ed8dd1cf3c51ddb3d9dfcf4efee67bfd3d007ee34cd72ef482cd2556b18a'}
INPUT_SELECTION_SHA = 'a9c72d60dcb5760d43209b9c833a3f3dac31e47d3c0f048a17ad71e05e3b9f02'
SOURCE_RUNS = {
    'nativeBuild': 35935470213,
    'publicVoiceImage': 37135802838,
    'voiceSbom': 37136153368,
    'bundle': 37136982942,
    'freshScan': 37135950435,
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
        'voiceSbomSha256': '13e8cdef7c0c8ceac00f994b7f7f29d8141fa1ea885d80ba073ebdf397457d36',
        'glibcTarSha256': '3001c2ffb4f6cfda7032ee7a3dda684fcae0991860491be38e205bdf51e5f10a',
        'hostDependencyFiles': 3939, 'sourceEntries': 660,
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
        'teleagent_voice_scan_check', HERE / 'verify-v58-voice-scan.py')
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
         environment.get('GITHUB_REF_PROTECTED') == 'true' and
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
