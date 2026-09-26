#!/usr/bin/python3 -I
"""Refuse a signed predicate when its subject or fixed policy fields drift."""

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    'consume_current_release_decision', HERE / 'consume-v19-release-decision.py')
CONSUME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSUME)
POLICY = CONSUME.POLICY
REVISION = 'a' * 40
NOW = datetime(2026, 9, 25, 11, tzinfo=timezone.utc)


def fixture():
    candidate = {
        'schema': 'teleagent.release-decision.v1',
        'applicationRevision': POLICY.APP,
        'applicationTree': POLICY.TREE,
        'bundleSha256': POLICY.BUNDLE_SHA,
        'bundleBytes': POLICY.BUNDLE_SIZE,
        'releaseManifestSha256': POLICY.MANIFEST_SHA,
        'voiceImageSha256': POLICY.VOICE_SHA,
        'voiceImageConfigDigest': POLICY.VOICE_CONFIG,
        'providerCliManifestSha256': POLICY.PROVIDER_MANIFEST,
        'inputSelectionSha256': POLICY.INPUT_SELECTION_SHA,
        'scanReportSha256': POLICY.SCAN_SHA,
        'scanDatabaseMetadataSha256': POLICY.DB_METADATA_SHA,
        'scanDatabaseNextUpdate': '2026-09-26T06:36:11.019457+00:00',
        'scanTargets': [
            {'class': 'lang-pkgs', 'packageCount': 142, 'type': 'node-pkg'},
            {'class': 'os-pkgs', 'packageCount': 18, 'type': 'alpine'}],
        'scanFindingCount': 0,
        'releaseId': 'sha256-' + POLICY.MANIFEST_SHA,
        'registryReference': None,
        'registryManifestDigest': None,
        'environment': 'hermes-shared',
        'sourceRuns': POLICY.SOURCE_RUNS,
    }
    decision = POLICY.decision(candidate, authorize=True,
                               environment={
                                   'GITHUB_ACTIONS': 'true',
                                   'RUNNER_ENVIRONMENT': 'github-hosted',
                                   'GITHUB_REPOSITORY': POLICY.AUTHORITY_REPO,
                                   'GITHUB_REPOSITORY_ID': POLICY.AUTHORITY_REPO_ID,
                                   'GITHUB_REF': 'refs/heads/main',
                                   'GITHUB_REF_PROTECTED': 'true',
                                   'GITHUB_EVENT_NAME': 'workflow_dispatch',
                                   'GITHUB_WORKFLOW_REF': POLICY.AUTHORITY_REPO +
                                   '/' + POLICY.WORKFLOW + '@refs/heads/main',
                                   'GITHUB_SHA': REVISION,
                               })
    verified = [{'verificationResult': {
        'statement': {
            'predicateType': POLICY.PREDICATE_TYPE,
            'subject': [{'name': 'teleagent-release.tar',
                         'digest': {'sha256': POLICY.BUNDLE_SHA}}],
            'predicate': decision,
        },
        'signature': {'certificate': {}},
        'verifiedTimestamps': [{}],
    }}]
    return verified, decision


class ConsumerTests(unittest.TestCase):
    def test_exact_predicate_yields_approval(self):
        verified, decision = fixture()
        approval = CONSUME.consume(verified, decision, REVISION, NOW)
        self.assertEqual(approval['version'], 2)
        self.assertEqual(approval['environment'], 'hermes-shared')
        self.assertEqual(approval['bundleSha256'], 'sha256:' + POLICY.BUNDLE_SHA)
        self.assertEqual(approval['authorityRevision'], REVISION)

    def test_changed_scan_coverage_and_subject_refused(self):
        verified, decision = fixture()
        changed = {**decision, 'scanTargets': []}
        verified[0]['verificationResult']['statement']['predicate'] = changed
        with self.assertRaisesRegex(ValueError, 'fixed policy'):
            CONSUME.consume(verified, changed, REVISION, NOW)
        verified, decision = fixture()
        verified[0]['verificationResult']['statement']['subject'][0]['digest'] = {
            'sha256': '0' * 64}
        with self.assertRaisesRegex(ValueError, 'subject'):
            CONSUME.consume(verified, decision, REVISION, NOW)

    def test_expired_scan_refused(self):
        verified, decision = fixture()
        with self.assertRaisesRegex(ValueError, 'fresh'):
            CONSUME.consume(verified, decision, REVISION,
                            datetime(2026, 9, 26, 6, tzinfo=timezone.utc))


if __name__ == '__main__':
    unittest.main()
