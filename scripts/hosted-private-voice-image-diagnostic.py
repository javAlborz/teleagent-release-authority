#!/usr/bin/python3 -I
"""Build one unsigned voice image through the retained private BuildKit/runc handoff.

Only a fresh hosted runner may execute this. The candidate and its workspace are
destroyed with the bounded quota; this module does not approve a release.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
NATIVE_PATH = HERE / 'hosted-native-build-diagnostic.py'
PROJECT_PATH = HERE / 'project-teleagent-data-in-quota.py'
INFRA = HERE.parent.parent / 'infrastructure/scripts/release'
VOICE_RECIPE_SHA256 = '9f7829de408b82cce0625df00d1ab87113a297f92b8669ff949a84a336d27490'
APP_REVISION = '5c0bc437ec1731bad1e8c6c348d7c72cd2b7cbfb'
APP_TREE = '3ab9261e2de3fdd3083c970a013f0b8d1ebfe12b'
DEPENDENCY_TAR_SHA256 = '7f5f674aa3c1fb890747e9f8b3dc3c68e9e80633b969dc8f1636303655cfc925'
MAX_APP_BYTES = 128 * 1024 * 1024
MAX_DEPENDENCY_BYTES = 512 * 1024 * 1024
MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024


def need(value, message):
    if not value:
        raise RuntimeError(message)


def git(root, *args):
    result = subprocess.run(['/usr/bin/git', '-C', str(root), *args],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=False)
    need(result.returncode == 0 and len(result.stdout) <= 128 * 1024 and
         len(result.stderr) <= 4096, 'voice app Git identity differs')
    return result.stdout


def stage_app(root, destination):
    need(git(root, 'rev-parse', 'HEAD').strip().decode('ascii') == APP_REVISION and
         git(root, 'show', '-s', '--format=%T', 'HEAD').strip().decode('ascii') == APP_TREE and
         git(root, 'status', '--porcelain') == b'',
         'voice app revision, tree or cleanliness differs')
    listing = git(root, 'ls-files', '-s', '-z', '--', '.dockerignore', 'voice-app', 'lib')
    rows = listing.rstrip(b'\0').split(b'\0')
    need(100 <= len(rows) <= 300 and len(set(rows)) == len(rows),
         'voice source file count differs')
    destination.mkdir(mode=0o700)
    total = 0
    seen, staged = set(), 0
    for row in rows:
        match = re.fullmatch(
            rb'100644 ([0-9a-f]{40}) 0\t((?:voice-app|lib)/[A-Za-z0-9_./+-]+|\.dockerignore)',
            row)
        need(match is not None, 'voice source mode or path differs')
        path = match.group(2).decode('ascii')
        need(path not in seen and all(component not in ('', '.', '..') for component in path.split('/')),
             'voice source path differs')
        seen.add(path)
        source = root / path
        before = source.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= 8 * 1024 * 1024,
             'voice source metadata differs')
        data = source.read_bytes()
        after = source.lstat()
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
              before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
              after.st_ctime_ns) and len(data) == before.st_size and
             hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest() ==
             match.group(1).decode('ascii'), 'voice source bytes differ from Git tree')
        total += len(data)
        need(total <= MAX_APP_BYTES, 'voice source aggregate exceeds bound')
        if path.startswith(('voice-app/test/', 'voice-app/audio/',
                            'voice-app/state/', 'voice-app/coverage/')):
            continue
        target = destination / path
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o644)
        staged += 1
    need('.dockerignore' in seen and 'voice-app/package.json' in seen and
         'voice-app/index.js' in seen and staged < len(seen),
         'voice source entrypoints absent')
    destination.chmod(0o755)
    return {'verifiedFiles': len(seen), 'stagedFiles': staged,
            'verifiedBytes': total, 'tree': APP_TREE}


def stage_dependencies(source, destination):
    need(source.is_dir() and not destination.exists(), 'verified dependency source differs')
    destination.mkdir(mode=0o700)
    total, files = 0, 0
    for parent, directories, filenames in os.walk(source, followlinks=False):
        base = Path(parent)
        relative = base.relative_to(source)
        need(len(relative.parts) <= 20 and len(directories) + len(filenames) <= 10000,
             'dependency tree shape exceeds bound')
        for name in directories + filenames:
            need(name not in ('', '.', '..') and '/' not in name and '\0' not in name,
                 'dependency entry name differs')
            candidate = base / name
            info = candidate.lstat()
            need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                 'dependency special file refused')
            if stat.S_ISDIR(info.st_mode):
                (destination / relative / name).mkdir(mode=0o755, exist_ok=True)
            else:
                need(info.st_nlink == 1 and info.st_size <= 64 * 1024 * 1024,
                     'dependency file metadata differs')
                total += info.st_size
                files += 1
                need(total <= MAX_DEPENDENCY_BYTES and files <= 20000,
                     'dependency tree aggregate exceeds bound')
                target = destination / relative / name
                shutil.copyfile(candidate, target, follow_symlinks=False)
                target.chmod(0o555 if info.st_mode & 0o111 else 0o444)
    need((destination / 'voice-app/node_modules').is_dir() and files > 100,
         'verified voice dependencies absent')
    for parent, directories, _ in os.walk(destination, topdown=False, followlinks=False):
        for name in directories:
            (Path(parent) / name).chmod(0o555)
    destination.chmod(0o555)
    return {'files': files, 'bytes': total}


def exact_recipe():
    source = INFRA / 'teleagent-offline-voice-image-plan.py'
    need(hashlib.sha256(source.read_bytes()).hexdigest() == VOICE_RECIPE_SHA256,
         'private voice recipe source differs')
    recipe = runpy.run_path(str(source), run_name='private_voice_diagnostic_recipe')
    plan = recipe['build_plan'](recipe['APP_EPOCH'], recipe['MATERIAL_PLAN'], APP_TREE)
    need(plan['appRevision'] == APP_REVISION and plan['appTree'] == APP_TREE and
         plan['muslDependencyTarSha256'] == DEPENDENCY_TAR_SHA256 and
         plan['buildExecuted'] is False and plan['releaseApproved'] is False and
         plan['expectedRunCount'] == 1,
         'unsigned voice recipe binding differs')
    return plan


def inside(mounted):
    need(os.getpid() == 1 and not any(
        line.strip().startswith('0.0.0.0') for line in
        Path('/proc/net/route').read_text().splitlines()),
        'private voice PID/network scope differs')
    native = runpy.run_path(str(NATIVE_PATH), run_name='private_voice_native_helpers')
    native['mounted_exec'](mounted)
    probe = runpy.run_path(str(native['PROBE_PATH']), run_name='private_voice_runtime_probe')
    plan = exact_recipe()
    native_plan_bytes = (mounted / 'native-plan.json').read_bytes()
    need(hashlib.sha256(native_plan_bytes).hexdigest() == native['PLAN_SHA256'],
         'private native daemon plan differs')
    native_plan = json.loads(native_plan_bytes)
    root = native['private_root'](mounted, probe, voice=True)
    jobs = probe['JOB_CGROUP']['create_and_enter_control'](scope := {})
    try:
        (root / 'ownership').mkdir(mode=0o700)
        (root / 'projected-bundles').mkdir(mode=0o700)
        Path('/run/teleagent-build/runc').mkdir(mode=0o700)
        for generated in plan['generatedFiles']:
            path = Path('/infra/voice-image') / generated['path']
            path.write_text(generated['content'])
            need(hashlib.sha256(path.read_bytes()).hexdigest() == generated['sha256'],
                 'voice generated recipe file differs')
        for generated in native_plan['generatedFiles']:
            path = Path('/infra') / generated['path']
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(generated['content'])
            need(hashlib.sha256(path.read_bytes()).hexdigest() == generated['sha256'],
                 'private native daemon support file differs')
        config = Path('/infra/buildkitd.toml')
        adapter_path = Path('/run/teleagent-build/adapter.sock')
        adapter = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        adapter.bind(str(adapter_path))
        adapter_path.chmod(0o600)
        adapter.listen(1)
        adapter.settimeout(1800)
        log = root / 'buildkitd.log'
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        invocation_id = uuid.uuid4().hex
        with log.open('xb') as stream:
            daemon = subprocess.Popen(
                [str(root / 'engine-launch'), '--config', str(config)],
                cwd='/', env=native_plan['hostEnvironment'], stdin=subprocess.DEVNULL,
                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                pidfile = root / 'daemon-pid'
                while not pidfile.exists() and time.monotonic() < deadline:
                    need(daemon.poll() is None, 'private voice daemon exited before admission')
                    time.sleep(0.05)
                need(pidfile.is_file() and re.fullmatch(r'[0-9]{1,16}\n', pidfile.read_text()),
                     'private voice daemon PID differs')
                daemon_pid = int(pidfile.read_text())
                socket_path = Path('/run/teleagent-build/buildkitd.sock')
                while not socket_path.exists() and time.monotonic() < deadline:
                    need(daemon.poll() is None, 'private voice daemon exited before socket')
                    time.sleep(0.05)
                need(socket_path.is_socket(), 'private voice BuildKit socket absent')
                command = [str(root / 'engine-launch'), '--client', *plan['buildctlArgv'][1:]]
                build_log = root / 'buildctl.log'
                with build_log.open('xb') as build_stream:
                    client = subprocess.Popen(command, cwd='/', env=native_plan['hostEnvironment'],
                                              stdin=subprocess.DEVNULL, stdout=build_stream,
                                              stderr=subprocess.STDOUT, start_new_session=True)
                    try:
                        observed = probe['adapter_handoff'](
                            root, adapter, invocation_id, boot_id, daemon_pid,
                            target='voice', phase='voice-apk', epoch=plan['sourceEpoch'],
                            deadline_seconds=1800)
                        container_id = observed['containerId']
                        need(set(observed['snapshotEquivalence']) == {'/materials'} and
                             observed['snapshotBytesRecheckedAfterRun'] is True,
                             'private voice RUN input bytes were not retained')
                        need(client.wait(timeout=1800) == 0 and
                             build_log.stat().st_size <= 8 * 1024 * 1024,
                             'private voice BuildKit solve failed or log exceeded bound')
                    except Exception as error:
                        raise RuntimeError('private voice solve refused: ' + str(error) +
                                           '; buildctl tail=' + native['tail'](build_log) +
                                           '; daemon tail=' + native['tail'](log)) from error
                    finally:
                        if client.poll() is None:
                            client.kill()
                            client.wait(timeout=10)
                need(log.stat().st_size <= 1024 * 1024,
                     'private voice daemon log exceeds bound')
            finally:
                if (jobs / 'engine/cgroup.procs').read_text().strip():
                    (jobs / 'engine/cgroup.kill').write_text('1\n')
                daemon.wait(timeout=10)
                adapter.close()
        calls = probe['read_calls'](root / 'runc-calls.bin')
        owned, actions = set(), []
        for argv in calls:
            intent = probe['PROTOCOL']['parse'](argv, owned_ids=owned)
            actions.append(intent['action'])
            owned.add(intent['containerId'])
        need(actions == ['run', 'delete'] and owned == {container_id} and
             not list(Path('/run/teleagent-build/runc').iterdir()),
             'private voice runc lifecycle differs')
        image = Path('/outputs/voice-image.docker.tar')
        size = image.stat().st_size
        need(stat.S_ISREG(image.stat().st_mode) and image.stat().st_nlink == 1 and
             0 < size <= MAX_IMAGE_BYTES, 'private unsigned voice archive bound differs')
        with image.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        result = {'privateVoiceRunExecuted': True, 'runtimePeerAndSnapshotVerified': True,
                  'actualOfflineApkCommandExecuted': True, 'unsignedImageSha256': digest,
                  'unsignedImageBytes': size, 'projectedSpecSha256': observed['projectedSha256'],
                  'releaseAuthority': False, 'installed': False}
        return result
    finally:
        probe['JOB_CGROUP']['cleanup'](scope)
        if 'returnFd' in scope:
            os.close(scope['returnFd'])


def projected(*, mounted, materials, engines, app, payload, plan, workspace, runner_temp):
    del materials, engines, app, payload
    need(plan['schema'] == 'teleagent.offline-build-plan.v1' and
         plan['sourcePairsSha256'] == 'dada99e66a0831b7ab974c392affcabe13b4c1ace13d2e9c9b65155d3c7900a9',
         'native material projection differs')
    voice_plan = exact_recipe()
    project = runpy.run_path(str(PROJECT_PATH), run_name='private_voice_quota_helpers')
    app_observed = stage_app(workspace / 'app', mounted / 'voice-app-source')
    dependency_observed = stage_dependencies(
        runner_temp / 'teleagent-musl-dependencies', mounted / 'voice-dependencies')
    with project['sealed_alias'](mounted / 'voice-app-source',
                                 mounted / 'sealed-voice-app-source'):
        with project['sealed_alias'](mounted / 'voice-dependencies',
                                     mounted / 'sealed-voice-dependencies'):
            (mounted / 'native-plan.json').write_text(
                json.dumps(plan, sort_keys=True, separators=(',', ':')) + '\n')
            need(hashlib.sha256((mounted / 'native-plan.json').read_bytes()).hexdigest() ==
                 runpy.run_path(str(NATIVE_PATH), run_name='private_voice_plan_pin')['PLAN_SHA256'],
                 'projected private native daemon plan differs')
            for name in ('native-state', 'native-outputs', 'native-tools'):
                (mounted / name).mkdir(mode=0o700)
            native = runpy.run_path(str(NATIVE_PATH), run_name='private_voice_outer_helpers')
            for source, name in (('teleagent-offline-runtime-shim.c', 'buildkit-runc-shim'),
                                 ('teleagent-offline-engine-launch.c', 'engine-launch')):
                native['fixed'](['/usr/bin/gcc', '-static', '-no-pie', '-O2', '-o',
                                 str(mounted / 'native-tools' / name), str(INFRA / source)], timeout=90)
            observed = json.loads(native['fixed'](
                ['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                 '/usr/bin/python3', '-I', str(Path(__file__).resolve()), '--inside', str(mounted),
                 'voice'],
                timeout=3700, maximum=65536))
            retained = runner_temp / 'teleagent-private-voice-candidate'
            need(not retained.exists(), 'private voice candidate destination already exists')
            retained.mkdir(mode=0o700)
            candidate = retained / 'voice-image.docker.tar'
            source = mounted / 'native-outputs/voice-image.docker.tar'
            need(source.is_file() and source.stat().st_size == observed['unsignedImageBytes'] and
                 0 < source.stat().st_size <= MAX_IMAGE_BYTES,
                 'private voice candidate changed before retention')
            shutil.copyfile(source, candidate)
            with candidate.open('rb') as stream:
                copied_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            need(candidate.stat().st_size == observed['unsignedImageBytes'] and
                 copied_sha == observed['unsignedImageSha256'],
                 'private voice candidate bytes changed during retention')
    need(observed['privateVoiceRunExecuted'] is True and
         observed['actualOfflineApkCommandExecuted'] is True and
         observed['releaseAuthority'] is False,
         'private voice diagnostic result differs')
    return {'privateVoiceImageDiagnostic': observed,
            'voiceAppSource': app_observed, 'dependencies': dependency_observed,
            'voiceRecipeAppRevision': voice_plan['appRevision'],
            'retainedUnsignedImage': {'sha256': copied_sha,
                                      'bytes': observed['unsignedImageBytes'],
                                      'releaseAuthority': False},
            'releaseAuthority': False}


def main():
    need(len(sys.argv) in (4, 5) and sys.argv[1] in ('--hosted', '--inside'),
         'private voice diagnostic arguments differ')
    expected = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8', 'GITHUB_ACTIONS': 'true',
                'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': 'javAlborz/teleagent-release-authority',
                'GITHUB_REF': 'refs/heads/feat/hosted-capacity-probe-20260923'}
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0].lower() != 'hermes' and
         os.uname().machine == 'x86_64' and set(os.environ) == set(expected) and
         all(os.environ[key] == value for key, value in expected.items()),
         'private voice hosted guard differs')
    if sys.argv[1] == '--inside':
        need(len(sys.argv) == 4 and re.fullmatch(
            r'/tmp/teleagent-storage-admission-[A-Za-z0-9_]+/mounted', sys.argv[2]) and
             sys.argv[3] == 'voice', 'private voice quota path differs')
        print(json.dumps(inside(Path(sys.argv[2])), sort_keys=True))
    else:
        need(len(sys.argv) == 4, 'private voice hosted arguments differ')
        module = runpy.run_path(str(PROJECT_PATH), run_name='private_voice_material_projection')
        workspace, runner_temp = Path(sys.argv[2]), Path(sys.argv[3])
        result = module['project'](
            on_projected=lambda **kwargs: projected(workspace=workspace,
                                                      runner_temp=runner_temp, **kwargs),
            workspace=workspace, runner_temp=runner_temp)
        need(result['cleanupVerified'] is True and
             result['projectedCallbackResult']['releaseAuthority'] is False,
             'private voice quota cleanup differs')
        retained = runner_temp / 'teleagent-private-voice-candidate'
        archive = retained / 'voice-image.docker.tar'
        expected = result['projectedCallbackResult']['retainedUnsignedImage']
        need(archive.is_file() and archive.stat().st_size == expected['bytes'] and
             expected['releaseAuthority'] is False,
             'retained private voice archive absent after quota cleanup')
        with archive.open('rb') as stream:
            need(hashlib.file_digest(stream, 'sha256').hexdigest() == expected['sha256'],
                 'retained private voice archive changed after quota cleanup')
        owner = workspace.stat()
        need(0 < owner.st_uid <= 65535 and 0 < owner.st_gid <= 65535,
             'hosted retained candidate owner differs')
        os.chown(archive, owner.st_uid, owner.st_gid)
        os.chown(retained, owner.st_uid, owner.st_gid)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
