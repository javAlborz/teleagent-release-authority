#!/usr/bin/python3 -I
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('napi', Path(__file__).with_name('project-v17-sqlite-napi.py'))
NAPI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NAPI)


class FixedNapiInputs(unittest.TestCase):
    def test_linked_archive_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'other').write_bytes(b'x')
            NAPI.archive_path(root, 'better-sqlite3').symlink_to(root / 'other')
            with self.assertRaisesRegex(ValueError, 'metadata'):
                NAPI.verified_archive(root, 'better-sqlite3')

    def test_wrong_archive_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            NAPI.archive_path(root, 'node-addon-api').write_bytes(b'x' * NAPI.INPUTS['node-addon-api'][2])
            with self.assertRaisesRegex(ValueError, 'digest'):
                NAPI.verified_archive(root, 'node-addon-api')

    def test_archive_escape_cannot_write_outside_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'malformed.tgz'
            with tarfile.open(archive, 'w:gz') as stream:
                member = tarfile.TarInfo('package/../../escape')
                member.size = 1
                stream.addfile(member, io.BytesIO(b'x'))
            with mock.patch.object(NAPI, 'verified_archive', return_value=archive):
                with self.assertRaisesRegex(ValueError, 'member'):
                    NAPI.extract(root, 'better-sqlite3', root / 'package', 'glibc')
            self.assertFalse((root / 'escape').exists())

    def test_only_the_requested_platform_binary_is_projected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'package.tgz'
            files = {'package/package.json': b'{"version":"13.0.3"}',
                     'package/prebuilds/linux-x64.node': b'glibc',
                     'package/prebuilds/linuxmusl-x64.node': b'musl'}
            with tarfile.open(archive, 'w:gz') as stream:
                for name, body in files.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    stream.addfile(member, io.BytesIO(body))
            with mock.patch.object(NAPI, 'verified_archive', return_value=archive):
                NAPI.extract(root, 'better-sqlite3', root / 'out', 'musl')
            self.assertEqual(sorted(p.name for p in (root / 'out/prebuilds').iterdir()),
                             ['linuxmusl-x64.node'])


if __name__ == '__main__':
    unittest.main()
