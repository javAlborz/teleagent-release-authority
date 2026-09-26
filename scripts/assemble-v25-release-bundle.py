#!/usr/bin/python3 -I
"""Assemble one unsigned, non-promotable Teleagent v2 closure on a hosted VM.

All application, native, provider, runtime and image bytes are fixed. This
diagnostic has no deployment, scanner approval or release signing authority.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile

APP = '38542697a44b5314b6cfe73d17f7f7548ff57bf6'
TREE = '9165e2dc3b3d158bb95c11cf82a68a71e85a8ead'
EPOCH = 1790442009
NATIVE_EPOCH = 1790204008
PLAN = '877bf9b1e00cbf627d322a6f3ec6f9a7fb1fa9f47f0aab843e4407536d6dc904'
SOURCE_PAIRS = '0518fb03ede3624a45798c66860ea8d29e62d52def9cddca087949a2ceff5e82'
GLIBC_TAR = '3001c2ffb4f6cfda7032ee7a3dda684fcae0991860491be38e205bdf51e5f10a'
VOICE_TAR = '87d7b185bfd23177c923d19cb3ee07b769d600d493a48f616d9eca729000ff63'
VOICE_SBOM = 'bce86d7e6ceae62527021ea734d38001fa7abc49f9141cbd660963840006854b'
NODE_ARCHIVE = '14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647'
NODE_BINARY = 'bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12'
SYFT_ARCHIVE = '2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f'
SYFT_BINARY = '5a8b71e94f4607973145f02e27e01d50b9f7c7bc41e38d40b39606ad138b43b5'
CLAUDE_BINARY = '1a0a662dc1bb938eaec38545abce9a4a69113d7d7f7c5e1a553ea276617b906a'
CODEX_ARCHIVE = 'e24fb784c7d71140d67afb620f56e9137496cf7f6c9e19217fa3666dcf306278'
CODEX_BINARY = '73dc5888888f411c1f0fa7b81d866e721dcc86b527ce8e3b2cf4708661e823ba'
PACKAGE_ROOTS = {'claude-api-server', 'privileged-action-broker', 'realtime-sip-gateway'}
PATH = re.compile(r'[A-Za-z0-9._+@/-]+\Z')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path, expected, maximum):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         0 < info.st_size <= maximum, 'artifact metadata differs: ' + path.name)
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    need(actual == expected, 'artifact digest differs: ' + path.name)
    return info.st_size


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(argv, *, cwd=None, timeout=600):
    result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    need(len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
         'diagnostic command output exceeds bound')
    need(result.returncode == 0,
         'diagnostic command refused: ' + argv[0] + ' exit=' +
         str(result.returncode) + ' stderr=' +
         result.stderr.decode('utf-8', 'replace')[-2048:])
    return result.stdout


def safe_path(name):
    need(type(name) is str and 0 < len(name) <= 2048 and PATH.fullmatch(name) and
         not name.startswith('/') and not name.endswith('/') and
         all(item not in ('', '.', '..') for item in name.split('/')),
         'archive path differs')
    return name


def copy_member(member, archive, destination, expected=None, maximum=300_000_000):
    need(member.isfile() and 0 <= member.size <= maximum and
         not destination.exists() and not destination.is_symlink(),
         'archive file shape or destination differs')
    destination.parent.mkdir(parents=True, exist_ok=True)
    stream = archive.extractfile(member)
    need(stream is not None, 'archive member cannot be read')
    value = hashlib.sha256()
    total = 0
    with stream, destination.open('xb') as output:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            need(total <= member.size, 'archive member grew')
            output.write(block)
            value.update(block)
    need(total == member.size and (expected is None or value.hexdigest() == expected),
         'archive member digest or size differs')
    destination.chmod(0o555 if member.mode & 0o111 else 0o444)
    return value.hexdigest()


def source_tree(app, work, release):
    need(command(['git', '-C', str(app), 'rev-parse', 'HEAD']).decode().strip() == APP and
         command(['git', '-C', str(app), 'show', '-s', '--format=%T', 'HEAD']).decode().strip() == TREE and
         command(['git', '-C', str(app), 'status', '--porcelain']).strip() == b'',
         'application checkout differs')
    source_tar = work / 'source.tar'
    command(['git', '-C', str(app), 'archive', '--format=tar',
             '--output=' + str(source_tar), APP])
    need(0 < source_tar.stat().st_size <= 500_000_000, 'source archive exceeds bound')
    release.mkdir(mode=0o700)
    count = 0
    with tarfile.open(source_tar, 'r:') as archive:
        for member in archive:
            name = member.name.removesuffix('/') if member.isdir() else member.name
            safe_path(name)
            destination = release / name
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                need(member.isfile(), 'source contains a link or special member')
                copy_member(member, archive, destination, maximum=64_000_000)
            count += 1
            need(count <= 50000, 'source archive entry count exceeds bound')
    need(count >= 100, 'source archive is incomplete')
    return count


def check_dependency_source_pairs(app):
    pairs_path = Path(__file__).resolve().parents[1] / 'inputs/teleagent/source-pairs-v17-20260926.json'
    digest(pairs_path, SOURCE_PAIRS, 1_000_000)
    pairs = json.loads(pairs_path.read_bytes())
    need(type(pairs) is list and len(pairs) == 12 and
         all(type(row) is dict and set(row) == {'path', 'sha256'} for row in pairs),
         'pinned dependency source-pair record differs')
    for row in pairs:
        safe_path(row['path'])
        digest(app / row['path'], row['sha256'], 4_000_000)


def native_dependencies(tar_path, observation_path, release):
    digest(tar_path, GLIBC_TAR, 200_000_000)
    comparator = runpy.run_path(str(Path(__file__).with_name(
        'compare-retained-native-candidates.py')), run_name='release_native_input_check')
    baseline = comparator['base']
    observation = baseline['load'](observation_path)
    baseline['subject'](observation, 'glibc', PLAN)
    record = observation['projectedCallbackResult']['retainedCandidate']
    need(type(record) is dict and set(record) == comparator['RECORD_KEYS'] and
         record['tarSha256'] == GLIBC_TAR and record['target'] == 'glibc' and
         record['sourceEpoch'] == NATIVE_EPOCH and record['signatureVerified'] is False and
         record['releaseApproved'] is False, 'native observation differs')
    comparator['check_tar'](tar_path, 'glibc', record, NATIVE_EPOCH)
    copied = 0
    with tarfile.open(tar_path, 'r:') as archive:
        for member in archive:
            name = member.name.removesuffix('/') if member.isdir() else member.name
            relative = comparator['safe_name'](name, 'glibc')
            parts = relative.split('/')
            if parts[0] not in PACKAGE_ROOTS or len(parts) < 2 or parts[1] != 'node_modules':
                continue
            destination = release / relative
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                copy_member(member, archive, destination)
                copied += 1
    need(copied >= 100, 'host dependency extraction is incomplete')
    old_native = release / ('realtime-sip-gateway/node_modules/better-sqlite3/'
                            'build/Release/better_sqlite3.node')
    new_native = release / ('realtime-sip-gateway/node_modules/better-sqlite3/'
                            'prebuilds/linux-x64.node')
    need(file_sha256(old_native) ==
         'f441cb347cd61f73faa62f14cbfeb3c3fb62524bfbb97f3208f79360a95ddc37' and
         not new_native.exists() and new_native.parent.is_dir(),
         'reviewed realtime SQLite binary projection differs')
    shutil.copyfile(old_native, new_native)
    new_native.chmod(0o444)
    need(file_sha256(new_native) == file_sha256(old_native),
         'realtime SQLite binary changed during projection')
    old_native.unlink()
    return copied


def archive_binary(path, member_name, destination, expected_archive, expected_binary,
                   maximum_archive, maximum_binary):
    digest(path, expected_archive, maximum_archive)
    with tarfile.open(path, 'r:*') as archive:
        member = archive.getmember(member_name)
        copy_member(member, archive, destination, expected_binary, maximum_binary)
    destination.chmod(0o555)


def stage_fixed(fixed, work, release):
    tools = fixed / 'tools'
    providers = fixed / 'providers'
    node = release / 'runtime/node/bin/node'
    archive_binary(tools / NODE_ARCHIVE,
                   'node-v25.19.0-linux-x64/bin/node', node,
                   NODE_ARCHIVE, NODE_BINARY, 40_000_000, 150_000_000)
    claude = providers / 'claude-2.1.246'
    digest(claude, CLAUDE_BINARY, 300_000_000)
    target = release / 'artifacts/provider-cli/claude'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(claude, target)
    target.chmod(0o555)
    digest(target, CLAUDE_BINARY, 300_000_000)
    archive_binary(providers / 'codex-x86_64-unknown-linux-musl.tar.gz',
                   'codex-x86_64-unknown-linux-musl',
                   release / 'artifacts/provider-cli/codex-vendor',
                   CODEX_ARCHIVE, CODEX_BINARY, 120_000_000, 300_000_000)
    archive_binary(providers / 'codex-code-mode-host-x86_64-unknown-linux-musl.tar.gz',
                   'codex-code-mode-host-x86_64-unknown-linux-musl',
                   release / 'artifacts/provider-cli/codex-code-mode-host',
                   '62fa2c3e5d4bc58720bd72b2ee2ab8636e1aaa9d8236ddae41a1cce628b59aeb',
                   '48f3a0d48033039cc7caccd209edb0ee350b81f82ca851a7b129e146e4bec6fb',
                   30_000_000, 100_000_000)
    syft = work / 'syft'
    archive_binary(tools / SYFT_ARCHIVE, 'syft', syft,
                   SYFT_ARCHIVE, SYFT_BINARY, 40_000_000, 100_000_000)
    need(b'1.51.0' in command([str(syft), 'version']), 'pinned Syft version differs')
    return syft


def stage_voice(image, sbom, release):
    digest(image, VOICE_TAR, 300_000_000)
    digest(sbom, VOICE_SBOM, 20_000_000)
    voice = release / 'artifacts/voice'
    voice.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(image, voice / 'voice-image.docker.tar')
    with tarfile.open(image, 'r:') as archive:
        manifest_member = archive.getmember('manifest.json')
        need(manifest_member.isfile() and manifest_member.size <= 65536,
             'voice Docker manifest differs')
        manifest = json.load(archive.extractfile(manifest_member))
        need(type(manifest) is list and len(manifest) == 1,
             'voice Docker image count differs')
        config_path = manifest[0]['Config']
        need(re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', config_path),
             'voice config path differs')
        config_member = archive.getmember(config_path)
        need(config_member.isfile() and config_member.size <= 1_048_576,
             'voice config size differs')
        config_bytes = archive.extractfile(config_member).read()
        need(hashlib.sha256(config_bytes).hexdigest() == config_path.split('/')[-1] and
             json.loads(config_bytes)['config']['Labels'][
                 'org.opencontainers.image.revision'] == APP,
             'voice image config or app revision differs')
    sbom_target = release / 'artifacts/sbom/voice-image.cdx.json'
    sbom_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sbom, sbom_target)
    sbom_target.chmod(0o444)
    return 'sha256:' + config_path.split('/')[-1]


def build(args):
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and
         os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
         os.environ.get('GITHUB_REPOSITORY') == 'javAlborz/teleagent-release-authority' and
         os.uname().nodename.split('.')[0].lower() != 'hermes',
         'release bundle diagnostic requires a hosted runner')
    work = args.work.resolve()
    need(work.is_absolute() and work.is_dir() and not any(work.iterdir()),
         'release diagnostic work root must be empty')
    release = work / 'release'
    check_dependency_source_pairs(args.app)
    source_count = source_tree(args.app, work, release)
    dependency_files = native_dependencies(args.glibc_tar, args.glibc_observation,
                                           release)
    napi = runpy.run_path(str(Path(__file__).with_name('project-v17-sqlite-napi.py')),
                          run_name='fixed_napi_projection')
    napi['project'](release, args.app, args.napi_inputs, 'glibc')
    dependency_files = sum(1 for component in PACKAGE_ROOTS
                           for path in (release / component / 'node_modules').rglob('*')
                           if path.is_file())
    syft = stage_fixed(args.fixed, work, release)
    for component in sorted(PACKAGE_ROOTS):
        command([str(release / 'runtime/node/bin/node'), '-e',
                 'const D=require("better-sqlite3");const db=new D(":memory:");'
                 'let a=[];for(let i=0;i<100000;i++){db.prepare("SELECT 1").get();'
                 'a.push({i});if(a.length>1000)a=[];}db.close();'],
                cwd=release / component)
    config_digest = stage_voice(args.voice_image, args.voice_sbom, release)
    support = args.app / 'scripts/release/ci_release_support.py'
    voice_manifest = release / 'artifacts/voice/voice-image.manifest.json'
    command(['python3', '-E', '-s', str(support), 'write-voice-manifest',
             '--destination', str(voice_manifest), '--revision', APP,
             '--config-digest', config_digest])
    raw = work / 'release.raw.cdx.json'
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE='false',
               SYFT_PARALLELISM='2', SYFT_FORMAT_CYCLONEDX_JSON_PRETTY='false')
    result = subprocess.run([str(syft), 'scan', 'dir:.',
                             '--source-name', 'teleagent-release',
                             '--source-version', APP,
                             '--output', 'cyclonedx-json@1.6=' + str(raw)],
                            cwd=release, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=600, check=False)
    need(result.returncode == 0 and len(result.stdout) <= 65536 and
         len(result.stderr) <= 65536,
         'host release SBOM scan refused: ' +
         result.stderr.decode('utf-8', 'replace')[-2048:])
    command(['python3', '-E', '-s', str(support), 'normalize-sbom',
             '--source', str(raw),
             '--destination', str(release / 'artifacts/sbom/teleagent-release.cdx.json'),
             '--forbid-path', str(work), '--release-root', str(release)])
    print(json.dumps({'hostSbomBytes': (
        release / 'artifacts/sbom/teleagent-release.cdx.json').stat().st_size,
        'voiceSbomBytes': (
            release / 'artifacts/sbom/voice-image.cdx.json').stat().st_size},
        sort_keys=True), file=sys.stderr)
    build_input = work / 'build-input.json'
    command(['python3', '-E', '-s', str(support), 'write-build-input',
             '--destination', str(build_input), '--revision', APP, '--tree', TREE])
    command(['python3', '-E', '-s', str(support), 'strip-metadata', '--root', str(release)])
    bundle = work / 'teleagent-release.diagnostic.tar'
    result = command(['python3', '-E', '-s',
                      str(args.app / 'scripts/release/generate-release-closure.py'),
                      '--root', str(release), '--build-input', str(build_input),
                      '--expected-uid', str(os.getuid()),
                      '--expected-gid', str(os.getgid()),
                      '--bundle', str(bundle), '--source-date-epoch', str(EPOCH)],
                     timeout=900)
    need(result.startswith(b'TELEAGENT_RELEASE_CLOSURE_GENERATED '),
         'release closure generator did not report a digest')
    command(['python3', '-E', '-s',
             str(args.app / 'scripts/release/verify-release-closure.py'),
             '--root', str(release), '--expected-uid', str(os.getuid()),
             '--expected-gid', str(os.getgid())], timeout=900)
    manifest = release / 'teleagent-release.manifest.json'
    return {'schema': 'teleagent.release-bundle-diagnostic.v1',
            'authorization': 'unsigned-source-only-no-release-authority',
            'applicationRevision': APP, 'applicationTree': TREE,
            'sourceEntries': source_count, 'hostDependencyFiles': dependency_files,
            'glibcTarSha256': GLIBC_TAR, 'voiceImageTarSha256': VOICE_TAR,
            'voiceSbomSha256': VOICE_SBOM,
            'releaseManifestSha256': file_sha256(manifest),
            'bundleSha256': file_sha256(bundle),
            'bundleBytes': bundle.stat().st_size,
            'scanApproved': False, 'signatureVerified': False,
            'releaseApproved': False, 'installed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'fixed', 'glibc-tar', 'glibc-observation',
                 'voice-image', 'voice-sbom', 'work', 'napi-inputs'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args), sort_keys=True))


if __name__ == '__main__':
    main()
