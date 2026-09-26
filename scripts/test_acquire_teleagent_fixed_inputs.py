#!/usr/bin/python3 -I
"""Exercise index copy integrity without network access or large inputs."""
import hashlib
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


if __name__ == '__main__':
    unittest.main()
