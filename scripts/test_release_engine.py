"""Compatibility and refusal tests against the frozen, signed V85 implementation."""
from datetime import datetime, timedelta, timezone
import copy
from contextlib import contextmanager, redirect_stdout
import hashlib
import importlib.util
import json
import io
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


E = module('release_engine_tested', 'release_engine.py')
OLD = module('frozen_v85_verifier', 'verify-v85-release-decision.py')
OLD_CONSUME = module('frozen_v85_consumer', 'consume-v85-release-decision.py')
FIXTURE = module('frozen_v85_fixture', 'test_consume_v85_release_decision.py')
TOOL = module('release_tool_tested', 'release-tool.py')
POLICY = E.load_policy(ROOT / 'releases/v85.json')


@contextmanager
def historical_input_root():
    # A later release may add input manifests. Historical comparison must use
    # its exact selected set, not weaken the production verifier's set check.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'inputs/teleagent').mkdir(parents=True)
        (root / 'scripts').mkdir()
        (root / 'releases').mkdir()
        for name in set(POLICY.INPUT_MANIFESTS) | {'source-pairs.json', 'trivy.json'}:
            shutil.copyfile(ROOT / 'inputs/teleagent' / name, root / 'inputs/teleagent' / name)
        shutil.copyfile(HERE / 'verify-v85-voice-scan.py', root / 'scripts/verify-v85-voice-scan.py')
        path = root / 'releases/v85.json'
        path.write_text(POLICY.encoded)
        yield E.load_policy(path, root)


def environment():
    return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_REPOSITORY': POLICY.AUTHORITY_REPO, 'GITHUB_REPOSITORY_ID': POLICY.AUTHORITY_REPO_ID,
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true',
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_WORKFLOW_REF':
            POLICY.AUTHORITY_REPO + '/' + POLICY.WORKFLOW + '@refs/heads/main',
            'GITHUB_SHA': FIXTURE.REVISION}


class PolicyTests(unittest.TestCase):
    def test_all_release_records_have_valid_bounded_schema(self):
        records = list((ROOT / 'releases').glob('v*.json'))
        self.assertTrue(records)
        for path in records:
            with self.subTest(path=path.name):
                E.load_policy(path)

    def test_signed_reference_files_are_unchanged(self):
        reference = json.loads((HERE / 'fixtures/v85-engine-reference.json').read_bytes())
        self.assertEqual(reference['authorityRevision'], 'da7631a094d21dcf5dcec652eb489d0bf48725d0')
        self.assertEqual(set(reference['files']), {'verify-v85-release-decision.py',
            'consume-v85-release-decision.py', 'fetch-v85-release-inputs.sh', 'verify-v85-voice-scan.py'})
        for name, digest in reference['files'].items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest, name)

    def test_frozen_v85_bindings_are_identical(self):
        for name in E.CONSTANT_KEYS.keys() | {'WORKFLOW', 'SOURCE_RUNS', 'AUTHORITY_REPO',
                                            'AUTHORITY_REPO_ID', 'PREDICATE_TYPE'}:
            if hasattr(OLD, name):
                self.assertEqual(getattr(POLICY, name), getattr(OLD, name), name)
        with historical_input_root() as policy, patch.object(OLD, 'HERE', policy.root / 'scripts'):
            self.assertEqual(E.verify_selected_inputs(policy), OLD.verify_selected_inputs())
        POLICY.INPUT_MANIFESTS.clear()
        POLICY.SOURCE_RUNS.clear()
        self.assertEqual(POLICY.INPUT_MANIFESTS, OLD.INPUT_MANIFESTS)

    def test_run_pins_match_the_frozen_fetcher(self):
        rows = (HERE / 'fetch-v85-release-inputs.sh').read_text().split("done <<'RUNS'\n")[1].split('\nRUNS')[0]
        pins = {}
        for row in rows.splitlines():
            run_id, revision, branch, attempt, workflow, event = row.split()
            pins[int(run_id)] = {'id': int(run_id), 'revision': revision, 'branch': branch,
                                'attempt': int(attempt), 'workflow': workflow, 'event': event}
        self.assertEqual(pins, {p['id']: p for p in POLICY.record['sourceRuns'].values()})

    def test_malformed_policy_cannot_relax_fixed_boundaries(self):
        mutations = [lambda p: p.update(authorityRepository='foreign/repository'),
                     lambda p: p.update(version=True), lambda p: p.update(bundleBytes=True),
                     lambda p: p.update(bundleBytes=-1), lambda p: p.update(applicationRevision='main'),
                     lambda p: p.update(voiceConfigDigest='latest'),
                     lambda p: p.update(scanTargets=[]),
                     lambda p: p['scanTargets'][0].update(packageCount=True),
                     lambda p: p.update(inputSelectionSha256='0' * 64),
                     lambda p: p['inputManifests'].update({'../escape.json': '0' * 64}),
                     lambda p: p['sourceRuns']['bundle'].update(attempt=2),
                     lambda p: p['sourceRuns']['bundle'].update(revision='main'),
                     lambda p: p['sourceRuns']['bundle'].update(workflow='../untrusted.py'),
                     lambda p: p['sourceRuns']['bundle'].update(id=p['sourceRuns']['freshScan']['id'])]
        for index, change in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                record = POLICY.record
                change(record)
                E.validate_record(record)

    def test_policy_file_identity_and_duplicate_keys_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'releases').mkdir()
            path = root / 'releases/v85.json'
            path.write_text(POLICY.encoded)
            self.assertEqual(E.load_policy(path, root).APP, POLICY.APP)
            alias = root / 'releases/v86.json'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                E.load_policy(alias, root)
            alias.unlink()
            os.link(path, alias)
            with self.assertRaises(ValueError):
                E.load_policy(path, root)
            alias.unlink()
            path.write_text(POLICY.encoded[:-1] + ',"version":85}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                E.load_policy(path, root)


class EquivalenceTests(unittest.TestCase):
    def test_diagnostic_and_authorized_decisions_match_exactly(self):
        _, signed = FIXTURE.fixture()
        candidate = {k: v for k, v in signed.items() if k not in
                     {'predicateType', 'authorityRevision', 'releaseApproved', 'scanApproved',
                      'signatureVerified', 'installed'}}
        for authorize in (False, True):
            self.assertEqual(E.decision(POLICY, candidate, authorize=authorize, environment=environment()),
                             OLD.decision(candidate, authorize=authorize, environment=environment()))

    def test_every_protected_context_field_remains_required(self):
        good = environment()
        self.assertEqual(E.authorized_context(POLICY, good), OLD.authorized_context(good))
        for key in good:
            for changed in ({**good, key: 'wrong'}, {k: v for k, v in good.items() if k != key}):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    E.authorized_context(POLICY, changed)
                with self.assertRaises(ValueError):
                    OLD.authorized_context(changed)

    def test_summary_identity_and_types_match_frozen_verifier(self):
        good = json.loads((HERE / 'fixtures/v85-release-summary.json').read_bytes())
        E.verify_summary(POLICY, good)
        OLD.verify_summary(good)
        for key in good:
            value = good[key]
            invalid = not value if type(value) is bool else (value + 1 if type(value) is int else 'wrong')
            bad = {**good, key: invalid}
            with self.subTest(key=key), self.assertRaises(ValueError):
                E.verify_summary(POLICY, bad)
            with self.assertRaises(ValueError):
                OLD.verify_summary(bad)
        for bad in ({**good, 'extra': 1}, {**good, 'installed': 0}):
            with self.assertRaises(ValueError):
                E.verify_summary(POLICY, bad)

    def test_consumer_approval_bytes_match_frozen_implementation(self):
        verified, decision = FIXTURE.fixture()
        new = E.consume(POLICY, verified, decision, FIXTURE.REVISION, FIXTURE.NOW)
        old = OLD_CONSUME.consume(verified, decision, FIXTURE.REVISION, FIXTURE.NOW)
        self.assertEqual(json.dumps(new, separators=(',', ':')), json.dumps(old, separators=(',', ':')))

    def test_signed_policy_fields_cannot_be_changed(self):
        original_verified, original = FIXTURE.fixture()
        for key in original:
            verified, decision = copy.deepcopy((original_verified, original))
            decision[key] = 'invalid'
            verified[0]['verificationResult']['statement']['predicate'] = decision
            for consume in [lambda: E.consume(POLICY, verified, decision, FIXTURE.REVISION, FIXTURE.NOW),
                            lambda: OLD_CONSUME.consume(verified, decision, FIXTURE.REVISION, FIXTURE.NOW)]:
                with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                    consume()

    def test_attestation_subject_signature_and_freshness_refuse(self):
        for case in ('subject', 'signature', 'timestamp', 'duplicate', 'mismatched-predicate'):
            verified, decision = FIXTURE.fixture()
            result = verified[0]['verificationResult']
            if case == 'subject':
                result['statement']['subject'][0]['digest']['sha256'] = '0' * 64
            elif case == 'signature':
                result['signature']['certificate'] = None
            elif case == 'timestamp':
                result['verifiedTimestamps'] = []
            elif case == 'duplicate':
                verified.append(verified[0])
            else:
                result['statement']['predicate'] = {}
            with self.subTest(case=case), self.assertRaises(ValueError):
                E.consume(POLICY, verified, decision, FIXTURE.REVISION, FIXTURE.NOW)
        verified, decision = FIXTURE.fixture()
        expiry = datetime.fromisoformat(decision['scanDatabaseNextUpdate'])
        for now in (expiry - timedelta(hours=1), expiry, expiry.replace(tzinfo=None)):
            with self.assertRaises(ValueError):
                E.consume(POLICY, verified, decision, FIXTURE.REVISION, now)

    def test_complete_bundle_comparison_and_hardlink_refusal(self):
        body = b'independent deterministic bytes\n'
        record = POLICY.record
        record.update(bundleBytes=len(body), bundleSha256=hashlib.sha256(body).hexdigest())
        small = E.ReleasePolicy(ROOT, json.dumps(record))
        with tempfile.TemporaryDirectory() as directory:
            a, b = [Path(directory) / name for name in ('a', 'b')]
            a.write_bytes(body)
            b.write_bytes(body)
            E.compare_bundles(small, a, b)
            b.write_bytes(b'X' + body[1:])
            with self.assertRaises(ValueError):
                E.compare_bundles(small, a, b)
            b.unlink()
            os.link(a, b)
            with self.assertRaises(ValueError):
                E.compare_bundles(small, a, b)

    def test_scanner_source_is_pinned_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            source = root / 'scripts/verify-v85-voice-scan.py'
            source.write_text('raise RuntimeError("must never execute")')
            policy = E.ReleasePolicy(root, POLICY.encoded)
            def hash_check(path, *args):
                if path == source:
                    raise ValueError('scanner source digest differs')
            with patch.object(E, 'file_hash', side_effect=hash_check), \
                 patch.object(E, 'bounded_json', return_value={}):
                with self.assertRaisesRegex(ValueError, 'scanner source digest'):
                    E.verify_scan(policy, Path('image'), Path('report'), Path('metadata'), Path('check'), FIXTURE.NOW)


class ToolTests(unittest.TestCase):
    def test_local_check_is_network_free_and_does_not_approve(self):
        output = io.StringIO()
        with historical_input_root() as policy, patch.object(TOOL, 'HERE', policy.root / 'scripts'), \
             patch.object(TOOL.ENGINE, 'load_policy', side_effect=lambda p: E.load_policy(p, policy.root)), \
             patch.object(sys, 'argv', ['release-tool.py', '--release', 'v85', 'check']), \
             patch.object(TOOL.subprocess, 'run') as network, redirect_stdout(output):
            TOOL.main()
            network.assert_not_called()
        value = json.loads(output.getvalue())
        self.assertIs(value['releaseApproved'], False)
        self.assertIs(value['liveStateInspected'], False)
        self.assertEqual(value['releaseId'], 'sha256-' + POLICY.MANIFEST_SHA)

    def test_each_source_run_metadata_binding_is_required(self):
        expected = POLICY.record['sourceRuns']['bundle']
        good = {'status': 'completed', 'conclusion': 'success', 'id': expected['id'],
                'head_sha': expected['revision'], 'head_branch': expected['branch'],
                'run_attempt': expected['attempt'], 'repository': {'id': int(POLICY.AUTHORITY_REPO_ID)},
                'path': expected['workflow'], 'event': expected['event']}
        with patch.object(TOOL.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(good).encode())):
            TOOL.run_metadata(POLICY, expected)
        for key in good:
            bad = {**good, key: {'id': 1} if key == 'repository' else 'wrong'}
            with self.subTest(key=key), patch.object(TOOL.time, 'sleep') as sleep, \
                 patch.object(TOOL.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(bad).encode())) as run:
                with self.assertRaises(ValueError):
                    TOOL.run_metadata(POLICY, expected)
                self.assertEqual(run.call_count, 1)
                sleep.assert_not_called()

    def test_metadata_mismatch_has_no_retry(self):
        with patch.object(TOOL.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'{}')), \
             patch.object(TOOL.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'conflicts'):
                TOOL.run_metadata(POLICY, POLICY.record['sourceRuns']['bundle'])
            sleep.assert_not_called()

    def test_transport_retry_is_bounded(self):
        with patch.object(TOOL.subprocess, 'run', side_effect=subprocess.TimeoutExpired('gh', 30)) as run, \
             patch.object(TOOL.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'transport'):
                TOOL.run_metadata(POLICY, POLICY.record['sourceRuns']['bundle'])
            self.assertEqual(run.call_count, 3)

    def test_fetch_cannot_run_on_hermes_or_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'evidence'
            with self.assertRaises(ValueError):
                TOOL.fetch(POLICY, target, {})
            self.assertFalse(target.exists())
            env = {**environment(), 'RUNNER_TEMP': directory, 'GH_TOKEN': 'fixture-never-sent'}
            with patch.object(TOOL.os, 'uname') as uname:
                uname.return_value.nodename = 'hermes'
                with self.assertRaises(ValueError):
                    TOOL.fetch(POLICY, target, env)
                uname.return_value.nodename = 'hosted'
                target.mkdir()
                with self.assertRaises(ValueError):
                    TOOL.fetch(POLICY, target, env)

    def test_partial_download_is_retained_and_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'evidence'
            env = {**environment(), 'RUNNER_TEMP': directory, 'GH_TOKEN': 'fixture-never-sent'}
            def interrupted(argv, **_kwargs):
                path = Path(argv[-1]) / 'partial'
                path.write_text('retained')
                raise subprocess.TimeoutExpired('gh', 300)
            with patch.object(TOOL.os, 'uname') as uname, \
                 patch.object(TOOL, 'run_metadata'), \
                 patch.object(TOOL.subprocess, 'run', side_effect=interrupted) as run:
                uname.return_value.nodename = 'hosted'
                with self.assertRaisesRegex(ValueError, 'preserve partial evidence'):
                    TOOL.fetch(POLICY, target, env)
                self.assertEqual(run.call_count, 1)
                self.assertEqual((target / 'bundle-a/partial').read_text(), 'retained')


if __name__ == '__main__':
    unittest.main()
