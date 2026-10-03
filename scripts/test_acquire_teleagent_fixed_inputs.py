#!/usr/bin/python3 -I
"""Exercise index copy integrity without network access or large inputs."""
import hashlib
import contextlib
import io
import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'fixed_inputs', Path(__file__).with_name('acquire-teleagent-fixed-inputs.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_atime_ns')


class IndexCopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'index-objects').mkdir()
        self.data = b'exact pinned index fixture\n'
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.source = self.root / 'index-objects' / self.digest
        self.source.write_bytes(self.data)
        self.target = self.root / 'copied'

    def copy(self):
        module.copy_pinned_index(self.root, self.digest, len(self.data), self.target)

    def test_real_read_preserves_exact_bytes(self):
        os.utime(self.source, ns=(1, self.source.stat().st_mtime_ns))
        self.copy()
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_access_timestamp_alone_may_change(self):
        before = self.source.stat()
        values = {key: getattr(before, key) for key in FIELDS}
        values['st_atime_ns'] += 10**9
        with patch.object(module.os, 'fstat', side_effect=[before, types.SimpleNamespace(**values)]):
            self.copy()
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_each_mutation_relevant_identity_change_is_refused(self):
        before = self.source.stat()
        for key in FIELDS[:-1]:
            with self.subTest(field=key):
                self.target.unlink(missing_ok=True)
                values = {name: getattr(before, name) for name in FIELDS}
                values[key] += 1
                with patch.object(module.os, 'fstat', side_effect=[before, types.SimpleNamespace(**values)]):
                    with self.assertRaisesRegex(ValueError, 'bytes changed'):
                        self.copy()

    def test_same_length_corruption_is_refused(self):
        self.source.write_bytes(b'X' + self.data[1:])
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            self.copy()

    def test_symlink_and_hardlink_are_refused(self):
        original = self.root / 'original'
        self.source.rename(original)
        self.source.symlink_to(original)
        with self.assertRaises(OSError):
            self.copy()
        self.source.unlink()
        self.source.hardlink_to(original)
        with self.assertRaisesRegex(ValueError, 'metadata differs'):
            self.copy()


class AcquisitionPurposeTests(unittest.TestCase):
    def acquire(self, purpose):
        inputs = Path(__file__).resolve().parents[1] / 'inputs/teleagent'
        requests = []
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'output'
            def download(_opener, url, digest, size, target, _deadline):
                requests.append((target.parent.name, target.name, url, digest, size))
            with patch.object(module, 'download', side_effect=download), \
                    patch.object(module, 'copy_pinned_index'), \
                    patch.object(module.os, 'geteuid', return_value=1000), \
                    patch.object(module.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=4 * module.MAX_TOTAL)), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = module.acquire(inputs, destination, purpose=purpose)
            groups = {p.name for p in destination.iterdir()}
            return requests, groups, result

    def test_release_omits_build_only_downloads_without_changing_used_input_pins(self):
        full, full_groups, _ = self.acquire('all')
        release, groups, result = self.acquire('release')
        self.assertEqual(full_groups, {'tools', 'engine', 'indexes', 'apk', 'providers'})
        self.assertEqual(groups, {'tools', 'providers'})
        self.assertEqual(release, [r for r in full if r[0] in groups])
        self.assertEqual(len(release), 6)
        self.assertEqual(result['downloadedBytes'], sum(r[4] for r in release))
        self.assertFalse(result['executablesRun'])
        self.assertTrue(any(r[0] == 'apk' for r in full))

    def test_unknown_purpose_refuses_before_any_download(self):
        with patch.object(module, 'download') as download:
            with self.assertRaisesRegex(ValueError, 'unknown acquisition purpose'):
                module.acquire(Path('/unused'), Path('/unused-output'), purpose='unchecked')
            download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
