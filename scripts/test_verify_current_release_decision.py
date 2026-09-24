#!/usr/bin/python3 -I
"""Check release decision refusal and independent byte comparison."""

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    'verify_current_release_decision', HERE / 'verify-current-release-decision.py')
DECIDE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECIDE)


class ReleaseDecisionTests(unittest.TestCase):
    def test_approval_requires_exact_protected_main_context(self):
        context = {
            'GITHUB_ACTIONS': 'true',
            'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_REPOSITORY': DECIDE.AUTHORITY_REPO,
            'GITHUB_REPOSITORY_ID': DECIDE.AUTHORITY_REPO_ID,
            'GITHUB_REF': 'refs/heads/main',
            'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_WORKFLOW_REF':
                DECIDE.AUTHORITY_REPO + '/' + DECIDE.WORKFLOW + '@refs/heads/main',
            'GITHUB_SHA': 'a' * 40,
        }
        self.assertEqual(DECIDE.authorized_context(context), 'a' * 40)
        for key, value in (
            ('GITHUB_REF', 'refs/heads/feat/hosted-capacity-probe-20260923'),
            ('GITHUB_REPOSITORY_ID', '1'),
            ('GITHUB_WORKFLOW_REF', DECIDE.AUTHORITY_REPO + '/unreviewed.yml@refs/heads/main'),
            ('RUNNER_ENVIRONMENT', 'self-hosted'),
            ('GITHUB_SHA', 'not-a-commit'),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'protected'):
                DECIDE.authorized_context({**context, key: value})

        candidate = {'schema': 'teleagent.release-decision.v1'}
        inert = DECIDE.decision(candidate, authorize=False, environment={})
        self.assertFalse(inert['releaseApproved'])
        self.assertFalse(inert['scanApproved'])
        self.assertNotIn('authorityRevision', inert)
        approved = DECIDE.decision(candidate, authorize=True, environment=context)
        self.assertTrue(approved['releaseApproved'])
        self.assertTrue(approved['scanApproved'])
        self.assertEqual(approved['authorityRevision'], 'a' * 40)

    def test_complete_comparison_refuses_difference_or_same_inode(self):
        data = b'first complete deterministic release\n'
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            first, second = root / 'first.tar', root / 'second.tar'
            first.write_bytes(data)
            second.write_bytes(data)
            with patch.object(DECIDE, 'BUNDLE_SIZE', len(data)), \
                 patch.object(DECIDE, 'BUNDLE_SHA', hashlib.sha256(data).hexdigest()):
                DECIDE.compare_bundles(first, second)
                second.write_bytes(data[:-1] + b'X')
                with self.assertRaisesRegex(ValueError, 'differ'):
                    DECIDE.compare_bundles(first, second)
                second.unlink()
                os.link(first, second)
                with self.assertRaisesRegex(ValueError, 'identity'):
                    DECIDE.compare_bundles(first, second)

    def test_unsigned_summary_cannot_set_approval_flags(self):
        summary = DECIDE.bounded_json(
            HERE / 'fixtures/current-release-summary.json', 65536)
        DECIDE.verify_summary(summary)
        with self.assertRaisesRegex(ValueError, 'differs'):
            DECIDE.verify_summary({**summary, 'releaseApproved': True})


if __name__ == '__main__':
    unittest.main()
