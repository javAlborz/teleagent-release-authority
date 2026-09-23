"""Small real-inventory fixtures for the deterministic native dependency tar."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest
from unittest.mock import patch

module = runpy.run_path(str(Path(__file__).with_name('retain-native-dependency-tar.py')),
                        run_name='retained_native_tar_test')
source_env = os.environ.get('TELEAGENT_TEST_EXPORT_SOURCE')
SOURCE = Path(source_env) if source_env else None
EPOCH = 1790168683


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


@unittest.skipUnless(SOURCE is not None and SOURCE.is_file(),
                     'exact private export inventory source is not selected')
class RetainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='teleagent-retain-tar-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.export = runpy.run_path(str(SOURCE), run_name='retained_export_test')

    def tree(self, name, *, target='musl', log=b'run evidence'):
        root = self.base / name
        root.mkdir()
        folders = module['ROOTS'][target]
        for folder in folders:
            package = root / folder
            package.mkdir()
            (package / 'package.json').write_bytes(b'{}\n')
            (package / 'node_modules').mkdir()
            (package / 'node_modules/data').write_bytes(b'deterministic native dependency')
        logs = root / 'run-logs'
        logs.mkdir()
        (logs / '0000.log').write_bytes(log)
        receipt = {'schema': 'teleagent.offline-native-build.v1',
                   'authorization': 'unsigned-build-data-only',
                   'target': target, 'buildCompleted': True,
                   'commands': [{'logSha256': hashlib.sha256(log).hexdigest()}]}
        (root / 'build-receipt.json').write_bytes(canonical(receipt))
        return root

    def subject(self, root, target='musl'):
        return self.export['inventory'](root, target)['subjectSha256']

    def test_equal_dependency_tars_ignore_variable_run_evidence(self):
        for target in ('musl', 'glibc'):
            with self.subTest(target=target):
                first = self.tree(target + '-first', target=target, log=b'first log')
                second = self.tree(target + '-second', target=target, log=b'second log')
                digest = self.subject(first, target)
                self.assertEqual(digest, self.subject(second, target))
                outputs = []
                for root, name in ((first, target + '-first.tar'),
                                   (second, target + '-second.tar')):
                    output = self.base / name
                    result = module['retain'](root, target, SOURCE, output, digest, EPOCH)
                    self.assertFalse(result['receiptIncluded'])
                    self.assertFalse(result['logsIncluded'])
                    self.assertFalse(result['releaseApproved'])
                    outputs.append((output, result))
                self.assertEqual(outputs[0][1]['tarSha256'], outputs[1][1]['tarSha256'])
                self.assertEqual(outputs[0][0].read_bytes(), outputs[1][0].read_bytes())
                with tarfile.open(outputs[0][0]) as archive:
                    names = archive.getnames()
                    self.assertTrue(any(name.endswith('/node_modules/data')
                                        for name in names))
                    self.assertFalse(any('receipt' in name or 'run-logs' in name
                                         for name in names))
                    self.assertTrue(all(member.uid == member.gid == 0 and
                                        member.mtime == EPOCH for member in archive))

    def test_changed_dependency_or_link_refuses_before_tar(self):
        root = self.tree('changed')
        digest = self.subject(root)
        (root / 'voice-app/node_modules/data').write_bytes(b'changed')
        output = self.base / 'changed.tar'
        with self.assertRaisesRegex(ValueError, 'subject differs'):
            module['retain'](root, 'musl', SOURCE, output, digest, EPOCH)
        self.assertFalse(output.exists())
        (root / 'voice-app/node_modules/alias').symlink_to('data')
        with self.assertRaisesRegex(ValueError, 'linked, special or oversized'):
            module['retain'](root, 'musl', SOURCE, output,
                             self.subject(self.tree('reference')), EPOCH)
        self.assertFalse(output.exists())

    def test_change_during_archive_removes_partial_tar(self):
        root = self.tree('during')
        digest = self.subject(root)
        output = self.base / 'during.tar'
        file = root / 'voice-app/node_modules/data'
        original = module['DigestReader'].read
        changed = False

        def mutate(reader, amount):
            nonlocal changed
            data = original(reader, amount)
            if data == b'deterministic native dependency' and not changed:
                changed = True
                file.write_bytes(b'mutated during archive')
            return data

        with patch.object(module['DigestReader'], 'read', mutate):
            with self.assertRaisesRegex(ValueError, 'changed during archive'):
                module['retain'](root, 'musl', SOURCE, output, digest, EPOCH)
        self.assertTrue(changed)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
