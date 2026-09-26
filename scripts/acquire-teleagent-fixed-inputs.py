#!/usr/bin/python3 -I
"""Download fixed public Teleagent tool, APK, and provider bytes as data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
import urllib.parse
import urllib.request

PINS = {
    'tools': '54f917a136554099a3872abbdd2965483babec33f71d45f4cbb0eaa8f30badb8',
    'engine': 'fa6ca7d6da2b13855fe1d0ddeed6b6b36b756e7c917f78c59c2384a1b5e77ab5',
    'indexes': '1194d3519645cc83f07d791dbc23aa7dcfa750a5f2eea06b8ee5378bafe7f620',
    'apk': 'dcd6c02ebbf9d26efc9f7bce8c58c9a2ad9dfb6d06da36689cebfe56e276338d',
}
PROVIDERS = (
    ('claude-2.1.246', 'https://downloads.claude.ai/claude-code-releases/2.1.246/linux-x64/claude',
     '1a0a662dc1bb938eaec38545abce9a4a69113d7d7f7c5e1a553ea276617b906a', 247905800),
    ('codex-x86_64-unknown-linux-musl.tar.gz',
     'https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-x86_64-unknown-linux-musl.tar.gz',
     'e24fb784c7d71140d67afb620f56e9137496cf7f6c9e19217fa3666dcf306278', 99479490),
)
HOSTS = {'nodejs.org', 'github.com', 'dl-cdn.alpinelinux.org', 'downloads.claude.ai'}
REDIRECT_HOSTS = HOSTS | {'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
MAX_OBJECT = 300 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'duplicate manifest key')
        value[key] = item
    return value


def uri(value, hosts):
    need(type(value) is str and len(value) < 4096, 'invalid URL')
    parsed = urllib.parse.urlsplit(value)
    need(parsed.scheme == 'https' and parsed.hostname in hosts and
         parsed.port in (None, 443) and not parsed.username and
         not parsed.password and not parsed.fragment, 'unapproved URL host')
    return value


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        need(code in (301, 302, 303, 307, 308), 'unexpected redirect')
        uri(newurl, REDIRECT_HOSTS)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def manifest(root, name):
    path = root / (name + '.json')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size < 1024 * 1024,
         'manifest metadata differs')
    data = path.read_bytes()
    need(hashlib.sha256(data).hexdigest() == PINS[name], 'fixed manifest hash differs')
    return data, json.loads(data, object_pairs_hook=unique)


def filename(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9_.+-]{1,255}', value) and
         value not in ('.', '..'), 'unsafe output filename')
    return value


def descriptor(url, digest, size):
    uri(url, HOSTS)
    need(type(digest) is str and re.fullmatch('[a-f0-9]{64}', digest) and
         type(size) is int and 0 < size <= MAX_OBJECT, 'invalid object descriptor')
    return url, digest, size


def download(opener, url, digest, size, target, deadline):
    descriptor(url, digest, size)
    need(not target.exists(), 'output file already exists')
    request = urllib.request.Request(url, headers={
        'User-Agent': 'Teleagent-offline-data-acquisition', 'Accept-Encoding': 'identity'})
    with opener.open(request, timeout=45) as response, target.open('xb') as output:
        need(response.status == 200 and
             response.headers.get('Content-Encoding', 'identity') == 'identity',
             'unexpected download response')
        uri(response.geturl(), REDIRECT_HOSTS)
        length = response.headers.get('Content-Length')
        need(length is None or length.isdecimal() and int(length) == size,
             'download length header differs')
        count, sha = 0, hashlib.sha256()
        while True:
            need(time.monotonic() < deadline, 'acquisition deadline exceeded')
            chunk = response.read(min(1024 * 1024, size + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            need(count <= size, 'download exceeds fixed size')
            sha.update(chunk)
            output.write(chunk)
        need(count == size and sha.hexdigest() == digest, 'download size or digest differs')
        output.flush()
        os.fsync(output.fileno())


def copy_pinned_index(inputs, digest, size, target):
    source = inputs / 'index-objects' / digest
    descriptor('https://dl-cdn.alpinelinux.org/', digest, size)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_size == size, 'pinned index object metadata differs')
        count, sha = 0, hashlib.sha256()
        with target.open('xb') as output:
            while True:
                data = os.read(fd, min(1024 * 1024, size + 1 - count))
                if not data:
                    break
                count += len(data)
                need(count <= size, 'pinned index exceeds size')
                sha.update(data)
                output.write(data)
            # Reading may update atime on a hosted runner. Bind content and
            # mutation-relevant identity, never that access-only timestamp.
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                      'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(count == size and sha.hexdigest() == digest and
                 all(getattr(before, key) == getattr(after, key) for key in fields),
                 'pinned index bytes changed')
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(fd)


def acquire(inputs, output):
    need(os.geteuid() != 0 and inputs.is_absolute() and output.is_absolute() and
         output.parent.is_dir(), 'unprivileged absolute paths required')
    records = {name: manifest(inputs, name) for name in PINS}
    need(shutil.disk_usage(output.parent).free >= 3 * MAX_TOTAL,
         'insufficient acquisition storage')
    rows = {'tools': [], 'engine': [], 'indexes': [], 'apk': [], 'providers': []}
    tools = records['tools'][1]
    need([row['name'] for row in tools['tools']] == ['node', 'syft', 'trivy'],
         'tool inventory differs')
    for row in tools['tools']:
        rows['tools'].append((filename(row['archiveSha256']), *descriptor(
            row['url'], row['archiveSha256'], row['archiveBytes'])))
    engine = records['engine'][1]
    need(engine['schema'] == 'teleagent.buildkit-materials.v1' and
         engine['version'] == 'v0.33.0' and len(engine['assets']) == 4 and
         {row['name'] for row in engine['assets']} == {
             'buildkit-v0.33.0.linux-amd64.' + suffix for suffix in
             ('tar.gz', 'provenance.json', 'sbom.json', 'sigstore.json')},
         'engine asset inventory differs')
    for row in engine['assets']:
        rows['engine'].append((filename(row['sha256']), *descriptor(
            row['url'], row['sha256'], row['bytes'])))
    indexes = records['indexes'][1]
    need({row['repository'] for row in indexes['repositories']} == {'main', 'community'} and
         len(indexes['repositories']) == 2, 'index inventory differs')
    for row in indexes['repositories']:
        rows['indexes'].append((filename(row['sha256']), *descriptor(
            row['url'], row['sha256'], row['bytes'])))
    packages = records['apk'][1]['packages']
    need(type(packages) is list and len(packages) == 37, 'APK inventory differs')
    for row in packages:
        name = filename(row['name'] + '-' + row['version'] + '.apk')
        rows['apk'].append((name, *descriptor(row['url'], row['sha256'], row['bytes'])))
    rows['providers'] = [(filename(name), *descriptor(url, digest, size))
                         for name, url, digest, size in PROVIDERS]
    all_names = [(kind, item[0]) for kind, items in rows.items() for item in items]
    need(len(all_names) == len(set(all_names)) and
         sum(item[3] for items in rows.values() for item in items) <= MAX_TOTAL,
         'duplicate or oversized acquisition')
    output.mkdir(mode=0o700)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())
    deadline = time.monotonic() + 1800
    total = 0
    for kind, items in rows.items():
        child = output / kind
        child.mkdir(mode=0o700)
        if kind in records:
            (child / 'manifest.json').write_bytes(records[kind][0])
        for name, url, digest, size in items:
            if kind == 'indexes':
                copy_pinned_index(inputs, digest, size, child / name)
            else:
                download(opener, url, digest, size, child / name, deadline)
            total += size
        print(json.dumps({'kind': kind, 'objects': len(items), 'bytesDownloaded': total}), flush=True)
    return {'status': 'data-only', 'downloadedBytes': total, 'executablesRun': False,
            'signatureVerified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(acquire(args.inputs, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
