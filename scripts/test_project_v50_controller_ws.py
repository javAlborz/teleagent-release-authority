#!/usr/bin/python3 -I
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

SPEC = importlib.util.spec_from_file_location('ws_projection', Path(__file__).with_name('project-v50-controller-ws.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture(extra=None, metadata=None):
    files = {'package/package.json': json.dumps(metadata or {'name': 'ws', 'version': '8.21.3'}).encode(),
             'package/index.js': b'fixture', 'package/lib/websocket.js': b'fixture',
             'package/lib/websocket-server.js': b'fixture'}
    if extra: files.update(extra)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, body in files.items():
            member = tarfile.TarInfo(name); member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    body = stream.getvalue()
    return body, base64.b64encode(hashlib.sha512(body).digest()).decode()


class ProjectionTests(unittest.TestCase):
    def test_all_bytes_must_match_integrity_before_parsing(self):
        body, integrity = fixture()
        self.assertEqual(len(M.verified_files(body, integrity)), 4)
        with self.assertRaises(ValueError): M.verified_files(body + b'changed', integrity)

    def test_paths_and_new_dependencies_cannot_extend_the_projection(self):
        for extra in ({'package/../escape': b'x'}, {'package/lib/deeper/run.js': b'x'}):
            with self.assertRaises(ValueError): M.verified_files(*fixture(extra=extra))
        for change in ({'version': '9.0.0'}, {'dependencies': {'surprise': '*'}}, {'scripts': {'install': 'run'}}):
            with self.assertRaises(ValueError):
                M.verified_files(*fixture(metadata={'name': 'ws', 'version': '8.21.3', **change}))


if __name__ == '__main__': unittest.main()
