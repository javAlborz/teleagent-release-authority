#!/usr/bin/python3 -I
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest

M = runpy.run_path(str(Path(__file__).with_name('project-v86-security-packages.py')))


def fixture(name, extra=None, change=None, link=False):
    record = M['package_record'](name)
    metadata = {'name': name, 'version': record['version'],
                'dependencies': record['dependencies'], **(change or {})}
    files = {'package/package.json': json.dumps(metadata).encode(),
             'package/lib/index.js' if name == 'qs' else 'package/index.js': b'code',
             **(extra or {})}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            if link and name.endswith('index.js'):
                member.type = tarfile.SYMTYPE
                member.linkname = '/etc/passwd'
                member.size = 0
            archive.addfile(member, io.BytesIO(body))
    body = out.getvalue()
    record['sha256'] = hashlib.sha256(body).hexdigest()
    record['integrity'] = 'sha512-' + base64.b64encode(hashlib.sha512(body).digest()).decode()
    return body, record


class Tests(unittest.TestCase):
    def test_fixed_records_and_unrecognized_package(self):
        self.assertEqual(M['package_record']('qs')['version'], '6.16.1')
        self.assertEqual(M['package_record']('follow-redirects')['version'], '1.16.2')
        with self.assertRaises(ValueError):
            M['package_record']('axios')

    def test_integrity_and_archive_boundaries(self):
        for name in ('qs', 'follow-redirects'):
            body, record = fixture(name)
            self.assertEqual(len(M['verified_files'](body, record)), 2)
            with self.assertRaises(ValueError):
                M['verified_files'](body + b'x', record)
            for args in [
                {'extra': {'package/../escape': b'x'}},
                {'extra': {'/package/absolute': b'x'}}, {'link': True},
                {'extra': {'package/node_modules/injected/package.json': b'x'}},
                {'extra': {'package/oversized': b'x' * (512 * 1024 + 1)}},
                {'change': {'version': '0.0.0'}},
                {'change': {'dependencies': {'surprise': '*'}}},
                {'change': {'scripts': {'install': 'run'}}},
            ]:
                with self.subTest(name=name, args=list(args)), self.assertRaises(ValueError):
                    M['verified_files'](*fixture(name, **args))

    def tree(self, base, name, component):
        body, record = fixture(name)
        root = base / 'deps'
        target = root / component / 'node_modules' / name
        target.mkdir(parents=True)
        (target / 'package.json').write_text(json.dumps({'version': record['previousVersion']}))
        (target / 'stale.js').write_text('old package file')
        neighbor = target.parent / 'keep'
        neighbor.write_text('unchanged')
        app = base / 'app'
        (app / component).mkdir(parents=True)
        lock = app / component / 'package-lock.json'
        entry = {'version': record['version'], 'resolved': record['url'],
                 'integrity': record['integrity'], 'dependencies': record['dependencies']}
        lock.write_text(json.dumps({'packages': {'node_modules/' + name: entry}}))
        archive = base / 'input'
        archive.write_bytes(body)
        return root, target, neighbor, app, lock, archive, record

    def test_exact_projection_preserves_neighbors_and_refuses_replay(self):
        for name, component in [('qs', 'voice-app'), ('qs', 'claude-api-server'),
                                ('follow-redirects', 'voice-app')]:
            with self.subTest(name=name, component=component), tempfile.TemporaryDirectory() as folder:
                root, target, neighbor, app, _, archive, record = self.tree(Path(folder), name, component)
                M['project'](archive, root, app, component, record)
                self.assertEqual(json.loads((target / 'package.json').read_bytes())['version'], record['version'])
                self.assertEqual(neighbor.read_text(), 'unchanged')
                self.assertFalse((target / 'stale.js').exists())
                with self.assertRaises(ValueError):
                    M['project'](archive, root, app, component, record)

    def test_invalid_input_leaves_original_unchanged(self):
        for case in ('lock', 'symlink', 'hardlink', 'archive-link', 'hash', 'prior-version', 'component'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                root, target, _, app, lock, archive, record = self.tree(base, 'qs', 'voice-app')
                if case == 'lock':
                    lock.write_text('{"packages":{"node_modules/qs":{}}}')
                elif case == 'symlink':
                    (target / 'link').symlink_to(base / 'outside')
                elif case == 'hardlink':
                    os.link(target / 'stale.js', target / 'alias')
                elif case == 'archive-link':
                    renamed = base / 'actual-input'
                    archive.rename(renamed)
                    archive.symlink_to(renamed)
                elif case == 'hash':
                    archive.write_bytes(archive.read_bytes() + b'x')
                elif case == 'prior-version':
                    (target / 'package.json').write_text('{"version":"unexpected"}')
                elif case == 'component':
                    record['components'] = ['claude-api-server']
                with self.assertRaises((ValueError, KeyError)):
                    M['project'](archive, root, app, 'voice-app', record)
                self.assertEqual((target / 'stale.js').read_text(), 'old package file')


if __name__ == '__main__':
    unittest.main()
