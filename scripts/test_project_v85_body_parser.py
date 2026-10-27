#!/usr/bin/python3 -I
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'body_parser_projection', Path(__file__).with_name('project-v85-body-parser.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture(extra=None, change=None, link=False):
    metadata = {'name': 'body-parser', 'version': '1.20.9',
                'dependencies': M.DEPENDENCIES, **(change or {})}
    files = {'package/package.json': json.dumps(metadata).encode(),
             'package/index.js': b'index', 'package/lib/read.js': b'read',
             'package/lib/types/json.js': b'json', **(extra or {})}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            if link and name == 'package/index.js':
                member.type = tarfile.SYMTYPE
                member.linkname = '/etc/passwd'
                member.size = 0
            archive.addfile(member, io.BytesIO(body))
    body = out.getvalue()
    return body, base64.b64encode(hashlib.sha512(body).digest()).decode()


class Tests(unittest.TestCase):
    def test_integrity_checked_before_parsing(self):
        body, digest = fixture()
        self.assertEqual(len(M.verified_files(body, digest)), 4)
        with self.assertRaises(ValueError):
            M.verified_files(body + b'x', digest)

    def test_unsafe_or_nested_dependency_members_refused(self):
        for args in [
            {'extra': {'package/../escape': b'x'}},
            {'extra': {'/package/absolute': b'x'}}, {'link': True},
            {'extra': {'package/node_modules/debug/package.json': b'x'}},
            {'extra': {'package/oversized': b'x' * (512 * 1024 + 1)}},
        ]:
            with self.subTest(args=list(args)), self.assertRaises(ValueError):
                M.verified_files(*fixture(**args))

    def test_new_dependencies_versions_or_install_hooks_refused(self):
        for change in [{'version': '1.20.6'}, {'dependencies': {'surprise': '*'}},
                       {'scripts': {'install': 'run'}}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                M.verified_files(*fixture(change=change))

    def tree(self, base, component):
        root = base / 'deps'
        target = root / component / 'node_modules/body-parser'
        target.mkdir(parents=True)
        (target / 'package.json').write_text('{"version":"1.20.6"}')
        (target / 'stale.js').write_text('old package file')
        nested = target / 'node_modules/debug/package.json'
        nested.parent.mkdir(parents=True)
        nested.write_text('{"version":"2.6.9"}')
        neighbor = target.parent / 'keep'
        neighbor.write_text('unchanged')
        app = base / 'app'
        (app / component).mkdir(parents=True)
        lock = app / component / 'package-lock.json'
        entry = {'version': '1.20.9', 'resolved': M.URL,
                 'integrity': 'sha512-' + M.INTEGRITY, 'dependencies': M.DEPENDENCIES}
        lock.write_text(json.dumps({'packages': {'node_modules/body-parser': entry}}))
        archive = base / 'input'
        archive.write_bytes(b'fixture')
        return root, target, nested, neighbor, app, lock, archive

    def test_patch_preserves_nested_dependencies_and_neighbors(self):
        for component in ('voice-app', 'claude-api-server'):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as folder:
                root, target, nested, neighbor, app, _, archive = self.tree(Path(folder), component)
                before = nested.read_bytes()
                with patch.object(M, 'verified_files', return_value=M.verified_files(*fixture())):
                    M.project(archive, root, app, component)
                    # A blind second projection is not accepted.
                    with self.assertRaises(ValueError):
                        M.project(archive, root, app, component)
                self.assertEqual(json.loads((target / 'package.json').read_bytes())['version'], '1.20.9')
                self.assertEqual(nested.read_bytes(), before)
                self.assertEqual(neighbor.read_text(), 'unchanged')
                self.assertFalse((target / 'stale.js').exists())

    def test_invalid_lock_or_unsafe_source_leaves_original_unchanged(self):
        for case in ('lock', 'symlink', 'hardlink', 'nested-file', 'archive-link'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                root, target, nested, _, app, lock, archive = self.tree(base, 'voice-app')
                if case == 'lock':
                    lock.write_text('{"packages":{"node_modules/body-parser":{}}}')
                elif case == 'symlink':
                    (target / 'link').symlink_to(base / 'outside')
                elif case == 'hardlink':
                    os.link(target / 'stale.js', target / 'alias')
                elif case == 'nested-file':
                    nested.unlink()
                    nested.parent.rmdir()
                    nested.parent.parent.rmdir()
                    nested.parent.parent.write_text('unexpected')
                elif case == 'archive-link':
                    renamed = base / 'actual-input'
                    archive.rename(renamed)
                    archive.symlink_to(renamed)
                with patch.object(M, 'verified_files', return_value=M.verified_files(*fixture())):
                    with self.assertRaises((ValueError, KeyError)):
                        M.project(archive, root, app, 'voice-app')
                self.assertEqual((target / 'stale.js').read_text(), 'old package file')
                self.assertEqual(json.loads((target / 'package.json').read_bytes())['version'], '1.20.6')


if __name__ == '__main__':
    unittest.main()
