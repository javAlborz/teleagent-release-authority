#!/usr/bin/python3 -I
"""Turn a verified exact authority attestation into a host approval record."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re

import importlib.util

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    'verify_current_release_decision', HERE / 'verify-v5-release-decision.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def consume(verified, decision, revision, now):
    need(type(revision) is str and re.fullmatch(r'[a-f0-9]{40}', revision),
         'authority revision is invalid')
    need(type(verified) is list and len(verified) == 1,
         'exactly one verified authority attestation is required')
    result = verified[0]['verificationResult']
    statement = result['statement']
    need(statement['predicateType'] == POLICY.PREDICATE_TYPE and
         type(statement['subject']) is list and len(statement['subject']) == 1 and
         statement['subject'][0]['digest'] == {'sha256': POLICY.BUNDLE_SHA} and
         statement['subject'][0]['name'] == 'teleagent-release.tar' and
         type(result['signature']['certificate']) is dict and
         type(result['verifiedTimestamps']) is list and
         len(result['verifiedTimestamps']) >= 1,
         'verified authority subject, type or signature differs')
    need(type(decision) is dict and statement['predicate'] == decision and
         decision.get('schema') == 'teleagent.release-decision.v1' and
         decision.get('predicateType') == POLICY.PREDICATE_TYPE and
         decision.get('authorityRevision') == revision and
         decision.get('releaseApproved') is True and
         decision.get('scanApproved') is True and
         decision.get('signatureVerified') is False and
         decision.get('installed') is False and
         decision.get('scanFindingCount') == 0 and
         decision.get('bundleSha256') == POLICY.BUNDLE_SHA and
         decision.get('bundleBytes') == POLICY.BUNDLE_SIZE and
         decision.get('releaseManifestSha256') == POLICY.MANIFEST_SHA and
         decision.get('applicationRevision') == POLICY.APP and
         decision.get('applicationTree') == POLICY.TREE and
         decision.get('voiceImageSha256') == POLICY.VOICE_SHA and
         decision.get('voiceImageConfigDigest') == POLICY.VOICE_CONFIG and
         decision.get('providerCliManifestSha256') == POLICY.PROVIDER_MANIFEST and
         decision.get('inputSelectionSha256') == POLICY.INPUT_SELECTION_SHA and
         decision.get('scanReportSha256') == POLICY.SCAN_SHA and
         decision.get('scanDatabaseMetadataSha256') == POLICY.DB_METADATA_SHA and
         decision.get('scanTargets') == [
             {'class': 'lang-pkgs', 'packageCount': 177, 'type': 'node-pkg'},
             {'class': 'os-pkgs', 'packageCount': 18, 'type': 'alpine'}] and
         decision.get('environment') == 'hermes-shared' and
         decision.get('registryReference') is None and
         decision.get('registryManifestDigest') is None and
         decision.get('releaseId') == 'sha256-' + POLICY.MANIFEST_SHA and
         decision.get('sourceRuns') == POLICY.SOURCE_RUNS,
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
        'releaseId': 'sha256-' + POLICY.MANIFEST_SHA,
        'manifestSha256': 'sha256:' + POLICY.MANIFEST_SHA,
        'bundleSha256': 'sha256:' + POLICY.BUNDLE_SHA,
        'sourceRevision': POLICY.APP,
        'sourceTree': POLICY.TREE,
        'voiceImageConfigDigest': POLICY.VOICE_CONFIG,
        'voiceImageRegistryReference': None,
        'voiceImageRegistryDigest': None,
        'providerCliManifestSha256': POLICY.PROVIDER_MANIFEST,
        'authorityRepositoryId': int(POLICY.AUTHORITY_REPO_ID),
        'authorityRevision': revision,
        'signedDecisionSha256': 'sha256:' + hashlib.sha256(
            (json.dumps(decision, sort_keys=True, separators=(',', ':'),
                        allow_nan=False) + '\n').encode('ascii')).hexdigest(),
        'inputSelectionSha256': 'sha256:' + POLICY.INPUT_SELECTION_SHA,
        'scanDatabaseNextUpdate': decision['scanDatabaseNextUpdate'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verified', type=Path, required=True)
    parser.add_argument('--decision', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--approval', type=Path, required=True)
    args = parser.parse_args()
    revision = POLICY.authorized_context(os.environ)
    POLICY.file_hash(args.bundle, POLICY.BUNDLE_SIZE, POLICY.BUNDLE_SHA,
                     POLICY.BUNDLE_SIZE)
    verified = POLICY.bounded_json(args.verified, 1024 * 1024)
    decision = POLICY.bounded_json(args.decision, 16384)
    approval = consume(verified, decision, revision, datetime.now(timezone.utc))
    body = (json.dumps(approval, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    need(not args.approval.exists() and len(body) <= 4096,
         'approval destination is unsafe')
    with args.approval.open('xb') as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({'schema': 'teleagent.accepted-release-consumer.v1',
                      'signatureVerified': True,
                      'releaseId': approval['releaseId'],
                      'environment': approval['environment']},
                     sort_keys=True))


if __name__ == '__main__':
    main()
