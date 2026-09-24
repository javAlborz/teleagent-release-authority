#!/usr/bin/python3 -I
"""Exercise the private host verifier against a real unsigned bundle in a fixture.

The approval in this temporary root is synthetic and has no release authority.
Only the fixture is written; no application or provider executable is started.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

APP = '5c0bc437ec1731bad1e8c6c348d7c72cd2b7cbfb'
TREE = '3ab9261e2de3fdd3083c970a013f0b8d1ebfe12b'
BUNDLE = '35891889bd46058884f748a0901f9bba0cd593f7bc217dbfbbaf95ff49bc127b'
MANIFEST = 'd47f125bd00fbb0f888f49c0f7e285e9940595bc0fb79bd67b43d632b46320da'
VERIFIER = '6f758fddd1677f60669da3facd3df76bda4ff877f47afb466e9b175f4b6e630a'
NAME = re.compile(r'[A-Za-z0-9._+@/-]+\Z')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def make_dir(path, mode=0o755):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def extract(bundle, release):
    release_id = 'sha256-' + MANIFEST
    seen = set()
    directories = []
    files = 0
    total = 0
    with tarfile.open(bundle, 'r:') as archive:
        for member in archive:
            name = member.name
            need(type(name) is str and NAME.fullmatch(name) and len(name) <= 4096 and
                 not name.startswith('/') and not name.endswith('/') and
                 all(part not in ('', '.', '..') and len(part) <= 255 for part in name.split('/')) and
                 (name == release_id or name.startswith(release_id + '/')) and
                 name not in seen and len(seen) < 100_000,
                 'bundle member path, count or uniqueness differs')
            seen.add(name)
            need(member.uid == member.gid == 0 and member.uname == member.gname == '' and
                 not member.pax_headers and member.mtime == 1790247516 and
                 member.mode in (0o444, 0o555), 'bundle header differs')
            relative = name[len(release_id):].removeprefix('/')
            target = release if not relative else release / relative
            if member.isdir():
                need(member.size == 0, 'bundle directory has data')
                make_dir(target)
                directories.append((target, member.mode))
            else:
                need(member.isfile() and relative and 0 <= member.size <= 300_000_000,
                     'bundle member is not a bounded file')
                need(target.parent.is_dir() and not target.exists(),
                     'bundle file parent or destination differs')
                source = archive.extractfile(member)
                need(source is not None, 'bundle file is unreadable')
                with source, target.open('xb') as output:
                    copied = shutil.copyfileobj(source, output, length=1024 * 1024)
                need(target.stat().st_size == member.size, 'bundle file size differs')
                target.chmod(member.mode)
                files += 1
                total += member.size
                need(total <= 1_000_000_000, 'bundle uncompressed bytes exceed bound')
    need(files > 100 and release.exists() and
         len(directories) > 10, 'bundle extraction is incomplete')
    for directory, mode in reversed(directories):
        directory.chmod(mode)
    return files


def run(bundle, verifier_source):
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and
         os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
         os.environ.get('GITHUB_REPOSITORY') == 'javAlborz/teleagent-release-authority' and
         os.uname().nodename.split('.')[0].lower() != 'hermes',
         'host contract diagnostic requires a disposable hosted runner')
    need(bundle.is_file() and not bundle.is_symlink() and
         bundle.stat().st_size == 840_222_720 and sha(bundle) == BUNDLE,
         'unsigned bundle differs')
    need(verifier_source.is_file() and not verifier_source.is_symlink() and
         verifier_source.stat().st_size <= 512 * 1024,
         'private verifier source differs')
    raw = verifier_source.read_bytes()
    marker = b'VERIFIER_SOURCE_POLICY_SHA256 = "sha256:'
    index = raw.index(marker) + len(marker)
    need(raw.count(marker) == 1 and raw[index:index + 64].decode() == VERIFIER and
         hashlib.sha256(raw[:index] + b'0' * 64 + raw[index + 64:]).hexdigest() == VERIFIER,
         'private verifier self-identity differs')
    tree = ast.parse(raw, filename=str(verifier_source))
    policy = None
    targets = None
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id == 'HOST_APPROVED_SYSTEMD_UNIT_SHA256':
                    policy = ast.literal_eval(statement.value)
                if isinstance(target, ast.Name) and target.id == 'HOST_APPROVED_SYSTEMD_UNIT_TARGETS':
                    targets = ast.literal_eval(statement.value)
    need(type(policy) is dict and len(policy) == 19 and
         type(targets) is dict and set(targets) == set(policy),
         'private systemd unit policy is absent or incomplete')
    with tempfile.TemporaryDirectory(prefix='teleagent-staging-handoff-test-real-', dir='/tmp') as name:
        root = Path(name)
        root.chmod(0o700)
        make_dir(root / 'opt/teleagent/releases')
        make_dir(root / 'etc/teleagent')
        make_dir(root / 'usr/local/libexec')
        make_dir(root / 'proc/sys/kernel/random')
        make_dir(root / 'run')
        release_id = 'sha256-' + MANIFEST
        release = root / 'opt/teleagent/releases' / release_id
        count = extract(bundle, release)
        manifest_path = release / 'teleagent-release.manifest.json'
        need(sha(manifest_path) == MANIFEST, 'bundle manifest differs')
        manifest = json.loads(manifest_path.read_bytes())
        need(manifest['source'] == {
            'repository': 'https://github.com/javAlborz/teleagent.git',
            'revision': APP, 'tree': TREE}, 'bundle app source differs')
        voice = manifest['voiceImage']
        approval = {
            'version': 1, 'application': 'teleagent', 'environment': 'dedicated-staging',
            'releaseId': release_id, 'manifestSha256': 'sha256:' + MANIFEST,
            'bundleSha256': 'sha256:' + BUNDLE,
            'sourceRevision': APP, 'sourceTree': TREE,
            'voiceImageConfigDigest': voice['configDigest'],
            'voiceImageRegistryReference': voice['registryReference'],
            'voiceImageRegistryDigest': voice['registryManifestDigest'],
            'providerCliManifestSha256': manifest['providerCli']['manifestSha256'],
        }
        approval_path = root / 'etc/teleagent/release-approval.json'
        approval_path.write_bytes((json.dumps(approval, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii'))
        approval_path.chmod(0o444)
        policy_path = root / 'etc/teleagent/test-host-approved-systemd-unit-sha256.json'
        policy_path.write_bytes((json.dumps({'version': 1, 'sha256': policy},
                                            separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii'))
        policy_path.chmod(0o444)
        installed = root / 'usr/local/libexec/verify-teleagent-release-closure'
        real = installed.with_name(installed.name + '.real')
        installed.write_bytes(raw)
        real.write_bytes(raw)
        installed.chmod(0o555)
        real.chmod(0o555)
        boot_id = root / 'proc/sys/kernel/random/boot_id'
        boot_id.write_text('00000000-0000-4000-8000-000000000001\n', encoding='ascii')
        boot_id.chmod(0o444)
        os.symlink(str(release), root / 'opt/teleagent/current')
        environment = {'HOME': '/var/empty', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                       'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                       'TELEAGENT_RELEASE_VERIFY_TEST_ONLY': '1',
                       'TELEAGENT_RELEASE_VERIFY_TEST_ROOT': str(root),
                       'TELEAGENT_RELEASE_VERIFY_TEST_UID': str(os.getuid()),
                       'TELEAGENT_RELEASE_VERIFY_TEST_GID': str(os.getgid())}
        result = subprocess.run(['/usr/bin/python3', str(real), '--verify'], env=environment,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        need(result.returncode == 0 and
             result.stdout == b'TELEAGENT_RELEASE_VERIFIED\n',
             'private host verifier refused exact bundle: ' +
             result.stderr.decode('utf-8', 'replace')[-1000:])
        node_source = release / manifest['hostRuntime']['nodePath']
        for absolute in manifest['hostRuntime']['interpreterTargets']:
            need(absolute in ('/opt/teleagent/node/bin/node', '/usr/local/libexec/teleagent-node'),
                 'host interpreter target differs')
            destination = root / absolute.removeprefix('/')
            make_dir(destination.parent)
            shutil.copyfile(node_source, destination)
            destination.chmod(0o555)
        for relative, absolute in targets.items():
            need(type(absolute) is str and absolute.startswith('/etc/systemd/system/'),
                 'installed systemd target differs')
            source = release / relative
            need(sha(source) == policy[relative],
                 'release unit differs from infrastructure pin')
            destination = root / absolute.removeprefix('/')
            make_dir(destination.parent)
            if destination.exists():
                need(sha(destination) == policy[relative],
                     'two source units disagree on installed target')
            else:
                shutil.copyfile(source, destination)
                destination.chmod(0o644)
        for operation, expected in (
            ('--write-gate', b'TELEAGENT_RELEASE_GATE_WRITTEN\n'),
            ('--check-runtime', b'TELEAGENT_RELEASE_RUNTIME_OK\n'),
        ):
            result = subprocess.run(['/usr/bin/python3', str(real), operation], env=environment,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
            need(result.returncode == 0 and result.stdout == expected,
                 'private host verifier refused synthetic runtime check: ' +
                 result.stderr.decode('utf-8', 'replace')[-1000:])
        return {'schema': 'teleagent.real-bundle-host-contract-diagnostic.v1',
                'bundleSha256': BUNDLE, 'releaseManifestSha256': MANIFEST,
                'privateVerifierSourcePolicySha256': VERIFIER,
                'verifiedInventoryEntries': count,
                'syntheticApprovalOnly': True, 'syntheticRuntimeFilesVerified': True,
                'releaseApproved': False,
                'installed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--verifier-source', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.bundle, args.verifier_source), sort_keys=True))
