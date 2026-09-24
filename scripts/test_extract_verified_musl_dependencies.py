"""Exercise bounded materialization of an unsigned musl tar with synthetic bytes."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
module = runpy.run_path(str(HERE / 'extract-verified-musl-dependencies.py'),
                        run_name='musl_extract_test')
archive = runpy.run_path(str(HERE / 'retain-native-dependency-tar.py'),
                         run_name='musl_extract_archive_test')
fixture = runpy.run_path(str(HERE / 'test_compare_native_diagnostic_observations.py'),
                         run_name='musl_extract_observation_fixture')
source_env = os.environ.get('TELEAGENT_TEST_EXPORT_SOURCE')
SOURCE = Path(source_env) if source_env else None


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


@unittest.skipUnless(SOURCE is not None and SOURCE.is_file(),
                     'exact private export inventory source is not selected')
class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='teleagent-extract-musl-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        source = self.root / 'source'
        package = source / 'voice-app'
        (package / 'node_modules').mkdir(parents=True)
        (package / 'package.json').write_bytes(b'{}\n')
        (package / 'node_modules/data').write_bytes(b'fixture dependency')
        (package / 'node_modules/tool').write_bytes(b'fixture executable')
        (package / 'node_modules/tool').chmod(0o755)
        logs = source / 'run-logs'
        logs.mkdir()
        log = b'fixture run log'
        (logs / '0000.log').write_bytes(log)
        (source / 'build-receipt.json').write_bytes(canonical({
            'schema': 'teleagent.offline-native-build.v1',
            'authorization': 'unsigned-build-data-only', 'target': 'musl',
            'buildCompleted': True,
            'commands': [{'logSha256': hashlib.sha256(log).hexdigest()}]}))
        export = runpy.run_path(str(SOURCE), run_name='musl_extract_export_test')
        subject = export['inventory'](source, 'musl')['subjectSha256']
        self.tar = self.root / 'musl.tar'
        record = archive['retain'](source, 'musl', SOURCE, self.tar,
                                   subject, module['EPOCH'])
        observation = fixture['observation']('musl', subject)
        callback = observation['projectedCallbackResult']
        callback['dependencyBytes'] = record['dependencyBytes']
        callback['dependencyEntries'] = record['dependencyEntries']
        callback['retainedCandidate'] = record
        self.observation = self.root / 'musl.json'
        self.observation.write_bytes((json.dumps(observation, sort_keys=True) + '\n').encode('ascii'))
        self.subject, self.tar_sha = subject, record['tarSha256']

    def extract(self, destination):
        with patch.dict(module['extract'].__globals__, SUBJECT_SHA=self.subject, TAR_SHA=self.tar_sha,
                        PLAN_SHA=fixture['PLAN']):
            return module['extract'](self.tar, self.observation, destination)

    def test_exact_tar_materializes_once_with_executable_mode(self):
        output = self.root / 'dependencies'
        result = self.extract(output)
        self.assertEqual(result['dependencySubjectSha256'], self.subject)
        self.assertFalse(result['releaseApproved'])
        self.assertEqual((output / 'voice-app/node_modules/data').read_bytes(),
                         b'fixture dependency')
        self.assertEqual(stat.S_IMODE((output / 'voice-app/node_modules/tool').stat().st_mode),
                         0o555)
        self.assertEqual(stat.S_IMODE((output / 'voice-app/node_modules').stat().st_mode),
                         0o555)
        self.assertEqual(stat.S_IMODE((output / 'voice-app/node_modules/data').stat().st_mode),
                         0o444)
        self.assertFalse((output / 'build-receipt.json').exists())
        with self.assertRaisesRegex(ValueError, 'fresh absolute'):
            self.extract(output)

    def test_changed_tar_or_observation_refuses_without_publishing(self):
        data = bytearray(self.tar.read_bytes())
        data[512] ^= 1
        self.tar.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            self.extract(self.root / 'changed')
        self.assertFalse((self.root / 'changed').exists())
        value = json.loads(self.observation.read_bytes())
        value['cleanupVerified'] = False
        self.observation.write_bytes((json.dumps(value, sort_keys=True) + '\n').encode('ascii'))
        with self.assertRaisesRegex(ValueError, 'storage'):
            self.extract(self.root / 'bad-observation')
        self.assertFalse((self.root / 'bad-observation').exists())

    def test_destination_symlink_refuses(self):
        (self.root / 'alias').symlink_to(self.root / 'target')
        with self.assertRaisesRegex(ValueError, 'fresh absolute'):
            self.extract(self.root / 'alias')


if __name__ == '__main__':
    unittest.main()
