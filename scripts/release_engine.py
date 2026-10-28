"""Shared release evidence checks, derived from frozen V85.

Release-specific identities live in releases/vN.json. This module never executes
payloads, installs releases, verifies cryptographic signatures itself or contacts
services. The consumer accepts only the output of the separately required exact
GitHub attestation verification. Existing versioned release paths stay frozen.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tarfile

HEX40 = re.compile(r'[a-f0-9]{40}\Z')

CONSTANT_KEYS = {
    'APP': 'applicationRevision', 'TREE': 'applicationTree',
    'BUNDLE_SHA': 'bundleSha256', 'BUNDLE_SIZE': 'bundleBytes',
    'MANIFEST_SHA': 'manifestSha256', 'VOICE_SHA': 'voiceSha256',
    'VOICE_CONFIG': 'voiceConfigDigest', 'VOICE_SBOM': 'voiceSbomSha256',
    'NATIVE_TAR': 'nativeTarSha256', 'PROVIDER_MANIFEST': 'providerManifestSha256',
    'HOST_DEPENDENCY_FILES': 'hostDependencyFiles', 'SOURCE_ENTRIES': 'sourceEntries',
    'SCAN_SHA': 'scanReportSha256', 'SCAN_CHECK_SHA': 'scanCheckSha256',
    'DB_METADATA_SHA': 'dbMetadataSha256', 'SCAN_VERIFIER_SHA': 'scanVerifierSha256',
    'INPUT_MANIFESTS': 'inputManifests', 'INPUT_SELECTION_SHA': 'inputSelectionSha256',
    'SCAN_TARGETS': 'scanTargets',
}


@dataclass(frozen=True)
class ReleasePolicy:
    """Immutable validated record; collection attributes return independent copies.

    Internal constant names deliberately match the frozen verifier to make the
    security-sensitive extraction auditable against the original implementation.
    """
    root: Path
    encoded: str

    AUTHORITY_REPO = 'javAlborz/teleagent-release-authority'
    AUTHORITY_REPO_ID = '1383172221'
    PREDICATE_TYPE = ('https://github.com/javAlborz/teleagent-release-authority/'
                      'attestations/release-decision/v1')

    @property
    def record(self):
        return json.loads(self.encoded)

    @property
    def version(self):
        return self.record['version']

    @property
    def WORKFLOW(self):
        return f'.github/workflows/teleagent-v{self.version}-release-decision.yml'

    @property
    def SOURCE_RUNS(self):
        return {key: value['id'] for key, value in self.record['sourceRuns'].items()}

    def __getattr__(self, name):
        if name in CONSTANT_KEYS:
            return self.record[CONSTANT_KEYS[name]]
        raise AttributeError(name)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON field: ' + key)
        result[key] = value
    return result


def validate_record(record):
    need(type(record) is dict and set(record) ==
         {'schema', 'version', 'sourceRuns'} | set(CONSTANT_KEYS.values()),
         'release policy fields differ')
    need(record['schema'] == 'teleagent.release-policy.v1' and
         type(record['version']) is int and 1 <= record['version'] <= 9999,
         'release policy schema or version differs')
    for key in ('applicationRevision', 'applicationTree'):
        need(type(record[key]) is str and HEX40.fullmatch(record[key]),
             'invalid source identity: ' + key)
    for key in [k for k in record if k.endswith('Sha256')]:
        prefix = 'sha256:' if key == 'providerManifestSha256' else ''
        need(type(record[key]) is str and
             re.fullmatch(prefix + r'[a-f0-9]{64}', record[key]),
             'invalid digest: ' + key)
    need(type(record['voiceConfigDigest']) is str and
         re.fullmatch(r'sha256:[a-f0-9]{64}', record['voiceConfigDigest']),
         'invalid image config digest')
    for key, maximum in [('bundleBytes', 2_000_000_000),
                         ('sourceEntries', 100_000), ('hostDependencyFiles', 100_000)]:
        need(type(record[key]) is int and 0 < record[key] <= maximum,
             'invalid count: ' + key)
    manifests = record['inputManifests']
    need(type(manifests) is dict and 1 <= len(manifests) <= 200,
         'input manifest count differs')
    for name, digest in manifests.items():
        need(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]*\.json', name) and
             name not in ('source-pairs.json', 'trivy.json') and
             type(digest) is str and re.fullmatch(r'[a-f0-9]{64}', digest),
             'invalid input manifest binding')
    selection = (json.dumps(manifests, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    need(hashlib.sha256(selection).hexdigest() == record['inputSelectionSha256'],
         'input selection does not match manifest digests')
    targets = record['scanTargets']
    need(type(targets) is list and len(targets) == 2, 'scan target coverage differs')
    for target, expected in zip(targets, [('lang-pkgs', 'node-pkg'), ('os-pkgs', 'alpine')]):
        need(type(target) is dict and set(target) == {'class', 'type', 'packageCount'} and
             (target['class'], target['type']) == expected and
             type(target['packageCount']) is int and 0 < target['packageCount'] <= 100_000,
             'scan target identity or package count differs')
    runs = record['sourceRuns']
    need(type(runs) is dict and set(runs) ==
         {'nativeBuild', 'publicVoiceImage', 'voiceSbom', 'bundle', 'freshScan'},
         'source run roles differ')
    for role, run in runs.items():
        need(type(run) is dict and set(run) ==
             {'id', 'revision', 'branch', 'attempt', 'workflow', 'event'},
             'source run fields differ: ' + role)
        need(type(run['id']) is int and run['id'] > 0 and
             type(run['attempt']) is int and run['attempt'] == 1 and
             type(run['revision']) is str and HEX40.fullmatch(run['revision']) and
             type(run['branch']) is str and
             re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_./-]{0,199}', run['branch']) and
             '..' not in run['branch'] and
             type(run['workflow']) is str and
             re.fullmatch(r'\.github/workflows/[a-zA-Z0-9_-]+\.yml', run['workflow']) and
             run['event'] in ('push', 'workflow_dispatch'),
             'invalid source run identity: ' + role)
    need(len({run['id'] for run in runs.values()}) == len(runs),
         'source run roles must have distinct run identities')


def load_policy(path, root=None):
    root = (root or Path(__file__).resolve().parents[1]).resolve(strict=True)
    path = path.absolute()
    record = bounded_json(path, 65536)
    validate_record(record)
    need(path == root / 'releases' / f"v{record['version']}.json" and
         path.resolve(strict=True) == path, 'policy must be the exact repository release record')
    return ReleasePolicy(root, json.dumps(record, sort_keys=True, separators=(',', ':')))


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


def compare_bundles(policy, first, second):
    first_info = checked_file(first, policy.BUNDLE_SIZE, policy.BUNDLE_SIZE)
    second_info = checked_file(second, policy.BUNDLE_SIZE, policy.BUNDLE_SIZE)
    need((first_info.st_dev, first_info.st_ino) !=
         (second_info.st_dev, second_info.st_ino),
         'bundle replicas share one inode')
    with first.open('rb') as left, second.open('rb') as right:
        while True:
            a, b = left.read(8 * 1024 * 1024), right.read(8 * 1024 * 1024)
            need(a == b, 'independent bundle replicas differ')
            if not a:
                break
    file_hash(first, policy.BUNDLE_SIZE, policy.BUNDLE_SHA, policy.BUNDLE_SIZE)
    file_hash(second, policy.BUNDLE_SIZE, policy.BUNDLE_SHA, policy.BUNDLE_SIZE)


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
        return json.loads(data, object_pairs_hook=unique_object)
    finally:
        os.close(descriptor)


def verify_summary(policy, value):
    expected = {
        'schema': 'teleagent.release-bundle-diagnostic.v1',
        'authorization': 'unsigned-source-only-no-release-authority',
        'applicationRevision': policy.APP, 'applicationTree': policy.TREE,
        'bundleBytes': policy.BUNDLE_SIZE, 'bundleSha256': policy.BUNDLE_SHA,
        'releaseManifestSha256': policy.MANIFEST_SHA,
        'voiceImageTarSha256': policy.VOICE_SHA,
        'voiceSbomSha256': policy.VOICE_SBOM,
        'glibcTarSha256': policy.NATIVE_TAR,
        'hostDependencyFiles': policy.HOST_DEPENDENCY_FILES, 'sourceEntries': policy.SOURCE_ENTRIES,
        'scanApproved': False, 'signatureVerified': False,
        'releaseApproved': False, 'installed': False,
    }
    need(type(value) is dict and set(value) == set(expected) and
         all(type(value[key]) is type(item) and value[key] == item
             for key, item in expected.items()),
         'unsigned release summary differs from the fixed candidate')


def verify_manifest(policy, bundle):
    release = 'sha256-' + policy.MANIFEST_SHA
    name = release + '/teleagent-release.manifest.json'
    with tarfile.open(bundle, 'r:') as archive:
        need(archive.getmembers()[0].name == release,
             'release archive top level differs')
        member = archive.getmember(name)
        need(member.isfile() and 0 < member.size <= 262144,
             'release manifest member differs')
        raw = archive.extractfile(member).read()
    need(hashlib.sha256(raw).hexdigest() == policy.MANIFEST_SHA,
         'release manifest digest differs')
    manifest = json.loads(raw)
    need(raw == (json.dumps(manifest, ensure_ascii=True, separators=(',', ':'),
                            allow_nan=False) + '\n').encode('ascii'),
         'release manifest encoding differs')
    need(manifest['version'] == 2 and manifest['application'] == 'teleagent' and
         manifest['source'] == {
             'repository': 'https://github.com/javAlborz/teleagent.git',
             'revision': policy.APP, 'tree': policy.TREE} and
         manifest['voiceImage']['archiveSha256'] == 'sha256:' + policy.VOICE_SHA and
         manifest['voiceImage']['configDigest'] == policy.VOICE_CONFIG and
         manifest['voiceImage']['registryReference'] is None and
         manifest['voiceImage']['registryManifestDigest'] is None and
         manifest['providerCli']['manifestSha256'] == policy.PROVIDER_MANIFEST,
         'release manifest semantic binding differs')
    return manifest


def verify_scan(policy, image, report, metadata, check, now):
    file_hash(image, 300_000_000, policy.VOICE_SHA)
    file_hash(report, 10_000_000, policy.SCAN_SHA)
    file_hash(metadata, 65536, policy.DB_METADATA_SHA)
    observed_check = bounded_json(check, 65536, policy.SCAN_CHECK_SHA)
    verifier_path = policy.root / 'scripts' / f'verify-v{policy.version}-voice-scan.py'
    file_hash(verifier_path, 1_000_000, policy.SCAN_VERIFIER_SHA)
    spec = importlib.util.spec_from_file_location(
        'teleagent_voice_scan_check', verifier_path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    computed = verifier.verify(image, report, metadata, now)
    need(computed == observed_check and computed['findingCount'] == 0 and
         computed['scanApproved'] is False and
         computed['releaseApproved'] is False,
         'fresh scanner evidence differs')
    return computed


def verify_selected_inputs(policy):
    root = policy.root / 'inputs/teleagent'
    need(set(path.name for path in root.iterdir() if path.is_file()) ==
         set(policy.INPUT_MANIFESTS) | {'source-pairs.json', 'trivy.json'},
         'authority input manifest set differs')
    for name, digest in policy.INPUT_MANIFESTS.items():
        file_hash(root / name, 5_000_000, digest)
    selection = (json.dumps(policy.INPUT_MANIFESTS, sort_keys=True,
                            separators=(',', ':')) + '\n').encode('ascii')
    need(hashlib.sha256(selection).hexdigest() == policy.INPUT_SELECTION_SHA,
         'selected input policy digest differs')
    return policy.INPUT_SELECTION_SHA


def verify_inputs(policy, first_bundle, second_bundle, first_summary, second_summary,
                  image, report, metadata, check, now):
    need(now.tzinfo is not None, 'release decision time must be UTC-aware')
    selected_inputs = verify_selected_inputs(policy)
    compare_bundles(policy, first_bundle, second_bundle)
    summaries = [bounded_json(path, 65536) for path in
                 (first_summary, second_summary)]
    need(summaries[0] == summaries[1], 'independent bundle summaries differ')
    verify_summary(policy, summaries[0])
    manifest = verify_manifest(policy, first_bundle)
    scan = verify_scan(policy, image, report, metadata, check, now)
    return {
        'schema': 'teleagent.release-decision.v1',
        'applicationRevision': policy.APP, 'applicationTree': policy.TREE,
        'bundleSha256': policy.BUNDLE_SHA,
        'bundleBytes': policy.BUNDLE_SIZE,
        'releaseManifestSha256': policy.MANIFEST_SHA,
        'voiceImageSha256': policy.VOICE_SHA,
        'voiceImageConfigDigest': policy.VOICE_CONFIG,
        'providerCliManifestSha256': policy.PROVIDER_MANIFEST,
        'inputSelectionSha256': selected_inputs,
        'scanReportSha256': policy.SCAN_SHA,
        'scanDatabaseMetadataSha256': policy.DB_METADATA_SHA,
        'scanDatabaseNextUpdate': scan['databaseNextUpdate'],
        'scanTargets': scan['targets'],
        'scanFindingCount': 0,
        'releaseId': 'sha256-' + policy.MANIFEST_SHA,
        'registryReference': manifest['voiceImage']['registryReference'],
        'registryManifestDigest': manifest['voiceImage']['registryManifestDigest'],
        'environment': 'hermes-shared',
        'sourceRuns': policy.SOURCE_RUNS,
    }


def authorized_context(policy, environment):
    need(environment.get('GITHUB_ACTIONS') == 'true' and
         environment.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
         environment.get('GITHUB_REPOSITORY') == policy.AUTHORITY_REPO and
         environment.get('GITHUB_REPOSITORY_ID') == policy.AUTHORITY_REPO_ID and
         environment.get('GITHUB_REF') == 'refs/heads/main' and
         environment.get('GITHUB_REF_PROTECTED') == 'true' and
         environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
         environment.get('GITHUB_WORKFLOW_REF') ==
         policy.AUTHORITY_REPO + '/' + policy.WORKFLOW + '@refs/heads/main' and
         type(environment.get('GITHUB_SHA')) is str and
         HEX40.fullmatch(environment['GITHUB_SHA']),
         'accepted release decision requires the protected authority main workflow')
    return environment['GITHUB_SHA']


def decision(policy, candidate, *, authorize, environment):
    result = dict(candidate)
    result['predicateType'] = policy.PREDICATE_TYPE
    result['releaseApproved'] = False
    result['scanApproved'] = False
    result['signatureVerified'] = False
    result['installed'] = False
    if authorize:
        result['authorityRevision'] = authorized_context(policy, environment)
        result['scanApproved'] = True
        result['releaseApproved'] = True
    return result



def consume(policy, verified, decision, revision, now):
    need(type(revision) is str and re.fullmatch(r'[a-f0-9]{40}', revision),
         'authority revision is invalid')
    need(type(verified) is list and len(verified) == 1,
         'exactly one verified authority attestation is required')
    result = verified[0]['verificationResult']
    statement = result['statement']
    need(statement['predicateType'] == policy.PREDICATE_TYPE and
         type(statement['subject']) is list and len(statement['subject']) == 1 and
         statement['subject'][0]['digest'] == {'sha256': policy.BUNDLE_SHA} and
         statement['subject'][0]['name'] == 'teleagent-release.tar' and
         type(result['signature']['certificate']) is dict and
         type(result['verifiedTimestamps']) is list and
         len(result['verifiedTimestamps']) >= 1,
         'verified authority subject, type or signature differs')
    need(type(decision) is dict and statement['predicate'] == decision and
         decision.get('schema') == 'teleagent.release-decision.v1' and
         decision.get('predicateType') == policy.PREDICATE_TYPE and
         decision.get('authorityRevision') == revision and
         decision.get('releaseApproved') is True and
         decision.get('scanApproved') is True and
         decision.get('signatureVerified') is False and
         decision.get('installed') is False and
         decision.get('scanFindingCount') == 0 and
         decision.get('bundleSha256') == policy.BUNDLE_SHA and
         decision.get('bundleBytes') == policy.BUNDLE_SIZE and
         decision.get('releaseManifestSha256') == policy.MANIFEST_SHA and
         decision.get('applicationRevision') == policy.APP and
         decision.get('applicationTree') == policy.TREE and
         decision.get('voiceImageSha256') == policy.VOICE_SHA and
         decision.get('voiceImageConfigDigest') == policy.VOICE_CONFIG and
         decision.get('providerCliManifestSha256') == policy.PROVIDER_MANIFEST and
         decision.get('inputSelectionSha256') == policy.INPUT_SELECTION_SHA and
         decision.get('scanReportSha256') == policy.SCAN_SHA and
         decision.get('scanDatabaseMetadataSha256') == policy.DB_METADATA_SHA and
         decision.get('scanTargets') == policy.SCAN_TARGETS and
         decision.get('environment') == 'hermes-shared' and
         decision.get('registryReference') is None and
         decision.get('registryManifestDigest') is None and
         decision.get('releaseId') == 'sha256-' + policy.MANIFEST_SHA and
         decision.get('sourceRuns') == policy.SOURCE_RUNS,
         'signed release decision differs from the fixed policy')
    next_update = datetime.fromisoformat(
        decision['scanDatabaseNextUpdate'].replace('Z', '+00:00'))
    need(now.tzinfo is not None and next_update.tzinfo is not None and
         next_update > now + timedelta(hours=1),
         'the signed scan database is no longer fresh')
    return {
        'version': 2,
        'application': 'teleagent',
        'environment': 'hermes-shared',
        'releaseId': 'sha256-' + policy.MANIFEST_SHA,
        'manifestSha256': 'sha256:' + policy.MANIFEST_SHA,
        'bundleSha256': 'sha256:' + policy.BUNDLE_SHA,
        'sourceRevision': policy.APP,
        'sourceTree': policy.TREE,
        'voiceImageConfigDigest': policy.VOICE_CONFIG,
        'voiceImageRegistryReference': None,
        'voiceImageRegistryDigest': None,
        'providerCliManifestSha256': policy.PROVIDER_MANIFEST,
        'authorityRepositoryId': int(policy.AUTHORITY_REPO_ID),
        'authorityRevision': revision,
        'signedDecisionSha256': 'sha256:' + hashlib.sha256(
            (json.dumps(decision, sort_keys=True, separators=(',', ':'),
                        allow_nan=False) + '\n').encode('ascii')).hexdigest(),
        'inputSelectionSha256': 'sha256:' + policy.INPUT_SELECTION_SHA,
        'scanDatabaseNextUpdate': decision['scanDatabaseNextUpdate'],
    }

