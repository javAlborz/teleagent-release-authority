"""Small real-inventory tars must reconstruct the recorded dependency subject."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
comparer = runpy.run_path(str(HERE / 'compare-retained-native-candidates.py'),
                          run_name='retained_candidate_test')
archive = runpy.run_path(str(HERE / 'retain-native-dependency-tar.py'),
                         run_name='retained_candidate_archive_test')
observation_test = runpy.run_path(
    str(HERE / 'test_compare_native_diagnostic_observations.py'),
    run_name='retained_observation_fixture')
source_env = os.environ.get('TELEAGENT_TEST_EXPORT_SOURCE')
SOURCE = Path(source_env) if source_env else None
EPOCH = 1790204008
PLAN = observation_test['PLAN']


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


@unittest.skipUnless(SOURCE is not None and SOURCE.is_file(),
                     'exact private export inventory source is not selected')
class RetainedCompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='teleagent-retained-compare-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.observations = self.base / 'observations'
        self.tars = self.base / 'tars'
        self.observations.mkdir(mode=0o700)
        self.tars.mkdir(mode=0o700)
        export = runpy.run_path(str(SOURCE), run_name='retained_compare_export')
        for target in ('glibc', 'musl'):
            for replica in ('1', '2'):
                root = self.base / f'{target}-{replica}-source'
                root.mkdir()
                for folder in archive['ROOTS'][target]:
                    package = root / folder
                    package.mkdir()
                    (package / 'package.json').write_bytes(b'{}\n')
                    (package / 'node_modules').mkdir()
                    (package / 'node_modules/data').write_bytes(b'fixed dependency')
                    (package / 'node_modules' / ('é' * 55 + '.json')).write_bytes(b'long-name bytes')
                logs = root / 'run-logs'
                logs.mkdir()
                run_log = ('log ' + replica).encode()
                (logs / '0000.log').write_bytes(run_log)
                receipt = {'schema': 'teleagent.offline-native-build.v1',
                           'authorization': 'unsigned-build-data-only',
                           'target': target, 'buildCompleted': True,
                           'commands': [{'logSha256': hashlib.sha256(run_log).hexdigest()}]}
                (root / 'build-receipt.json').write_bytes(canonical(receipt))
                observed = export['inventory'](root, target)
                tar_path = self.tars / f'{target}-{replica}.tar'
                retained = archive['retain'](root, target, SOURCE, tar_path,
                                             observed['subjectSha256'], EPOCH)
                value = observation_test['observation'](target, observed['subjectSha256'])
                callback = value['projectedCallbackResult']
                callback['dependencyBytes'] = retained['dependencyBytes']
                callback['dependencyEntries'] = retained['dependencyEntries']
                callback['retainedCandidate'] = retained
                (self.observations / f'{target}-{replica}.json').write_bytes(
                    json.dumps(value, sort_keys=True).encode() + b'\n')

    def test_four_tars_reconstruct_equal_subjects_without_release_authority(self):
        result = comparer['compare'](self.observations, self.tars, PLAN)
        self.assertTrue(result['artifactRetained'])
        self.assertFalse(result['signatureVerified'])
        self.assertFalse(result['releaseApproved'])
        self.assertEqual(result['matchingRetainedTars']['glibc']['tarSha256'],
                         hashlib.sha256((self.tars / 'glibc-1.tar').read_bytes()).hexdigest())

    def test_changed_tar_or_extra_member_refuses(self):
        path = self.tars / 'musl-2.tar'
        data = bytearray(path.read_bytes())
        data[512] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            comparer['compare'](self.observations, self.tars, PLAN)
        path.write_bytes(data)
        (self.tars / 'unexpected.tar').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'set differs'):
            comparer['compare'](self.observations, self.tars, PLAN)


if __name__ == '__main__':
    unittest.main()
