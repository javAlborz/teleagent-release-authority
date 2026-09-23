"""Unsigned comparison refuses changed data and missing cleanup."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest

module = runpy.run_path(str(Path(__file__).with_name('compare-native-diagnostic-observations.py')),
                        run_name='native_comparison_test')
PLAN = 'a' * 64


def observation(target, digest):
    snapshots = {'/materials': {'equalAtReadTime': True,
                                'immutableThroughRun': False,
                                'treeSha256': 'b' * 64}}
    payload = {**snapshots, '/payload': snapshots['/materials'],
               '/work/source': snapshots['/materials']}
    return {'purpose': 'bounded-teleagent-data-projection',
            'materialPlanSha256': 'c' * 64, 'enginePlanSha256': 'd' * 64,
            'unsignedBuildPlanSha256': PLAN, 'sourceEpoch': 1790168683,
            'appSourcePairFilesProjected': 12, 'payloadSourceFilesProjected': 3,
            'cleanupVerified': True, 'privateInputReadOnlyAliasesVerified': True,
            'payloadMaterialPinsMatched': True, 'teleagentBuildExecuted': True,
            'buildPeakMeasured': False, 'trivyFreshnessAcceptedForBuild': False,
            'afterWorkloadQuota': {'availableBytes': 24 * 1024 ** 3},
            'projectedCallbackResult': {
                'target': target, 'unsignedNativeBuildDiagnostic': True,
                'releaseAuthority': False, 'dependencySubjectSha256': digest,
                'dependencyBytes': 1000, 'dependencyEntries': 10,
                'runLogFiles': 3,
                'phases': [{'phase': 'prepare', 'projectedSha256': 'e' * 64,
                            'snapshotEquivalence': snapshots},
                           {'phase': 'payload', 'projectedSha256': 'f' * 64,
                            'snapshotEquivalence': payload}]}}


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-compare-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for target in module['TARGETS']:
            for replica in module['REPLICAS']:
                self.write(target, replica, observation(target, '1' * 64))

    def write(self, target, replica, value):
        (self.root / f'{target}-{replica}.json').write_text(
            json.dumps(value, sort_keys=True) + '\n')

    def test_matching_subjects_are_observations_only(self):
        second = observation('musl', '1' * 64)
        second['projectedCallbackResult']['phases'][0]['projectedSha256'] = '0' * 64
        self.write('musl', '2', second)
        result = module['compare'](self.root, PLAN)
        self.assertEqual(result['matchingDependencySubjects']['glibc']
                         ['dependencySubjectSha256'], '1' * 64)
        self.assertFalse(result['artifactRetained'])
        self.assertFalse(result['releaseApproved'])

    def test_changed_subject_or_missing_cleanup_refuses(self):
        changed = observation('musl', '2' * 64)
        self.write('musl', '2', changed)
        with self.assertRaisesRegex(ValueError, 'subject differs'):
            module['compare'](self.root, PLAN)
        self.write('musl', '2', observation('musl', '1' * 64))
        changed = observation('glibc', '1' * 64)
        changed['cleanupVerified'] = False
        self.write('glibc', '1', changed)
        with self.assertRaisesRegex(ValueError, 'storage'):
            module['compare'](self.root, PLAN)

    def test_duplicate_fields_and_extra_files_refuse(self):
        (self.root / 'glibc-1.json').write_text('{"target":1,"target":2}\n')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            module['compare'](self.root, PLAN)
        (self.root / 'extra').write_text('x')
        with self.assertRaisesRegex(ValueError, 'file set'):
            module['compare'](self.root, PLAN)


if __name__ == '__main__':
    unittest.main()
