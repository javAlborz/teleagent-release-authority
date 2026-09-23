#!/usr/bin/python3 -I
"""Run one unsigned glibc dependency diagnostic in a disposable hosted volume.

This is neither a release builder nor a signer. Its output is discarded after
the same-job storage proof; the private source pin and generated plan remain
review candidates. Acquired code runs only after the detached namespace and
projected runc handoff have been established.
"""

import ctypes
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
PROBE_PATH = HERE.parent.parent / 'infrastructure/scripts/release/teleagent-hosted-runc-probe.py'
PROJECT_PATH = HERE / 'project-teleagent-data-in-quota.py'
PLAN_SHA256 = '74fcd1e4634f9ba8b6e413387365abe1ea91858b30f83eb0f8ead669657188a3'
TARGETS = frozenset(('glibc', 'musl'))
ENGINE = {
    'buildctl': (34512200, '0b45ae3696f836bf711dbd78138e403924d7733f0b2328ba29a7fcf9ad5f1dfd'),
    'buildkitd': (80466872, '157da954fa081d9ec4f063d62029fbbf12437c1d47ab63080594eae5a85b36f2'),
    'buildkit-runc': (16269912, '0acdd302ddc5540b2e445b683661bfada9935c702f9008ffb0481abcda16c9b4'),
}


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path, count, expected):
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         before.st_size == count, 'native engine size/metadata differs')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
          before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
          after.st_ctime_ns) and value.hexdigest() == expected,
         'native engine digest or identity differs')


def fixed(argv, timeout=60, maximum=16384):
    process = subprocess.Popen(argv, cwd='/', env=dict(os.environ),
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=10)
        raise RuntimeError('native diagnostic command exceeded deadline')
    need(len(stdout) <= maximum and len(stderr) <= maximum,
         'native diagnostic output exceeds bound')
    need(process.returncode == 0,
         'native diagnostic refused: ' + argv[0] + ' exit=' +
         str(process.returncode) + ' stderr=' +
         stderr.decode('utf-8', 'replace')[-4096:])
    return stdout


def tail(path, maximum=2048):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return '<absent>'
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 64 * 1024 * 1024,
             'native diagnostic log metadata differs')
        os.lseek(fd, max(0, info.st_size - maximum), os.SEEK_SET)
        return os.read(fd, maximum).decode('utf-8', 'replace')
    finally:
        os.close(fd)


def payload_refusal(path):
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 8 * 1024 * 1024,
         'native raw build trace exceeds diagnostic bound')
    messages = []
    with path.open('rb') as stream:
        for line in stream:
            need(len(line) <= 1024 * 1024,
                 'native raw build trace line exceeds bound')
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if type(record) is not dict or type(record.get('logs')) is not list:
                continue
            for entry in record['logs'][:16]:
                if type(entry) is not dict or type(entry.get('data')) is not str:
                    continue
                encoded = entry['data']
                if len(encoded) > 4096:
                    continue
                try:
                    decoded = base64.b64decode(encoded, validate=True)
                except ValueError:
                    continue
                if decoded.startswith(b'offline build refused:') and len(decoded) <= 512:
                    message = decoded.decode('ascii', 'replace').strip()
                    if all(32 <= ord(char) <= 126 for char in message):
                        messages.append(message)
    return messages[-1] if messages else '<no bounded payload refusal line>'


def mounted_exec(path):
    """Enable execution of the quota only in the child mount namespace."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(None, os.fsencode(path), None,
                  ctypes.c_ulong(32 | 2 | 4), None) != 0:  # REMOUNT|NOSUID|NODEV
        raise OSError(ctypes.get_errno(), 'private quota exec remount refused')
    need(not os.statvfs(path).f_flag & os.ST_NOEXEC,
         'private build quota remained noexec')


def bind(source, destination, readonly=False):
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(os.fsencode(source), os.fsencode(destination), None,
                  ctypes.c_ulong(4096 | 16384), None) != 0:
        raise OSError(ctypes.get_errno(), 'private native bind refused')
    if readonly and libc.mount(None, os.fsencode(destination), None,
                               ctypes.c_ulong(32 | 4096 | 1 | 2 | 4 | 8), None) != 0:
        raise OSError(ctypes.get_errno(), 'private native readonly remount refused')
    need((source.stat().st_dev, source.stat().st_ino) ==
         (destination.stat().st_dev, destination.stat().st_ino) and
         (not readonly or os.statvfs(destination).f_flag & os.ST_RDONLY),
         'private native bind identity differs')


def private_root(mounted, probe):
    """Create a bounded exec-capable root with quota-backed state and outputs."""
    private = mounted / 'native-private-root'
    private.mkdir(mode=0o700)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(b'tmpfs', os.fsencode(private), b'tmpfs',
                  ctypes.c_ulong(2), b'size=805306368,nr_inodes=8192,mode=0755') != 0:
        raise OSError(ctypes.get_errno(), 'private native root tmpfs refused')
    private.chmod(0o755)
    for name in ('probe', 'proc', 'sys/fs/cgroup', 'dev', 'etc', 'tmp', 'state',
                 'run/teleagent-build', 'infra/bin', 'infra/context',
                 'infra/empty-provenance', 'infra/empty-docker-config',
                 'infra/glibc', 'infra/musl', 'engines/bin', 'inputs/app', 'materials',
                 'outputs', 'private-home'):
        (private / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, source in (
            ('buildctl', mounted / 'teleagent-engines/bin/buildctl'),
            ('buildkitd', mounted / 'teleagent-engines/bin/buildkitd'),
            ('runc', mounted / 'teleagent-engines/bin/buildkit-runc'),
            ('engine-launch', mounted / 'native-tools/engine-launch'),
            ('buildkit-runc-shim', mounted / 'native-tools/buildkit-runc-shim')):
        target = private / 'probe' / name
        shutil.copyfile(source, target)
        target.chmod(0o555)
        engine_name = 'buildkit-runc' if name == 'runc' else name
        if engine_name in ENGINE:
            count, expected = ENGINE[engine_name]
            digest(target, count, expected)
            alias = private / 'engines/bin' / engine_name
            shutil.copyfile(target, alias)
            alias.chmod(0o555)
            digest(alias, count, expected)
    shutil.copyfile(private / 'probe/buildkit-runc-shim',
                    private / 'infra/bin/teleagent-offline-runc')
    (private / 'infra/bin/teleagent-offline-runc').chmod(0o555)
    (private / 'etc/resolv.conf').write_text('')
    (private / 'etc/hosts').write_text('127.0.0.1 localhost\n')
    os.mknod(private / 'dev/null', stat.S_IFCHR | 0o666, os.makedev(1, 3))
    if libc.mount(b'proc', os.fsencode(private / 'proc'), b'proc',
                  ctypes.c_ulong(2 | 4 | 8), None) != 0:
        raise OSError(ctypes.get_errno(), 'private native proc mount refused')
    bind(Path('/sys/fs/cgroup'), private / 'sys/fs/cgroup')
    bind(mounted / 'native-state', private / 'state')
    bind(mounted / 'native-outputs', private / 'outputs')
    bind(mounted / 'sealed-materials', private / 'materials', readonly=True)
    bind(mounted / 'sealed-app-source', private / 'inputs/app', readonly=True)
    bind(mounted / 'sealed-payload-source', private / 'infra/payload', readonly=True)
    os.chroot(private)
    os.chdir('/')
    geometry = os.statvfs('/')
    need(0 < geometry.f_blocks * geometry.f_frsize <= 805306368 and
         0 < geometry.f_files <= 8192, 'private native root geometry differs')
    return Path('/probe')


def run_target(root, plan, probe, target):
    need(target in TARGETS, 'native diagnostic target differs')
    jobs = probe['JOB_CGROUP']['create_and_enter_control'](scope := {})
    try:
        (root / 'ownership').mkdir(mode=0o700)
        (root / 'projected-bundles').mkdir(mode=0o700)
        Path('/run/teleagent-build/runc').mkdir(mode=0o700)
        (Path('/outputs') / target).mkdir(mode=0o700)
        for generated in plan['generatedFiles']:
            path = Path('/infra') / generated['path']
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(generated['content'])
            need(hashlib.sha256(path.read_bytes()).hexdigest() == generated['sha256'],
                 'generated native build file differs')
        adapter_path = Path('/run/teleagent-build/adapter.sock')
        adapter = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        adapter.bind(str(adapter_path))
        adapter_path.chmod(0o600)
        adapter.listen(1)
        adapter.settimeout(1800)
        log = root / 'buildkitd.log'
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        invocation_id = uuid.uuid4().hex
        with log.open('xb') as log_stream:
            host_env = plan['hostEnvironment']
            daemon = subprocess.Popen(
                [str(root / 'engine-launch'), '--config', '/infra/buildkitd.toml'],
                cwd='/', env=host_env, stdin=subprocess.DEVNULL,
                stdout=log_stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                pidfile = root / 'daemon-pid'
                while not pidfile.exists() and time.monotonic() < deadline:
                    need(daemon.poll() is None, 'native BuildKit daemon exited before admission')
                    time.sleep(0.05)
                need(pidfile.is_file() and re.fullmatch(r'[0-9]{1,16}\n', pidfile.read_text()),
                     'native BuildKit PID record differs')
                daemon_pid = int(pidfile.read_text())
                socket_path = Path('/run/teleagent-build/buildkitd.sock')
                while not socket_path.exists() and time.monotonic() < deadline:
                    need(daemon.poll() is None, 'native BuildKit daemon exited before socket')
                    time.sleep(0.05)
                need(socket_path.is_socket(), 'native BuildKit socket missing')
                stage = next(row for row in plan['serialStages'] if row['target'] == target)
                command = [str(root / 'engine-launch'), '--client', *stage['buildctlArgv'][1:]]
                build_log = root / 'buildctl.log'
                with build_log.open('xb') as build_stream:
                    client = subprocess.Popen(command, cwd='/', env=host_env,
                                              stdin=subprocess.DEVNULL,
                                              stdout=build_stream,
                                              stderr=subprocess.STDOUT,
                                              start_new_session=True)
                    try:
                        ledger = probe['SEQUENCE']['Sequence'](target, plan['sourceEpoch'])
                        records = []
                        for phase in ('prepare', 'payload'):
                            try:
                                observed = probe['adapter_handoff'](
                                    root, adapter, invocation_id, boot_id, daemon_pid,
                                    target=target, phase=phase,
                                    epoch=plan['sourceEpoch'], sequence=ledger,
                                    deadline_seconds=1800)
                            except Exception as error:
                                raise RuntimeError(
                                    'native ' + phase + ' adapter refused: ' + str(error) +
                                    '; payload refusal=' + payload_refusal(build_log) +
                                    '; buildctl tail=' + tail(build_log) +
                                    '; daemon tail=' + tail(log) +
                                    '; runc tail=' + tail(Path(
                                        '/state/runc-overlayfs/executor/runc-log.json'))
                                ) from error
                            need(observed['sequenceClaimedBeforeDelegate'] is True,
                                 'native phase was not claimed before runc')
                            container_id = observed['containerId']
                            calls = probe['read_calls'](root / 'runc-calls.bin')
                            intents = [probe['PROTOCOL']['parse'](argv, owned_ids=set())
                                       for argv in calls if len(argv) >= 6 and
                                       argv[4] == 'run' and argv[-1] == container_id]
                            need(len(intents) == 1 and ledger.expected_phase(intents[0]) == phase,
                                 'native RUN order differs')
                            ledger.claim(intents[0], observed['projectedSha256'])
                            need(ledger.run_exited(container_id, 0),
                                 'native RUN exited unsuccessfully')
                            deletion_deadline = time.monotonic() + 20
                            while time.monotonic() < deletion_deadline:
                                calls = probe['read_calls'](root / 'runc-calls.bin')
                                deleted = [probe['PROTOCOL']['parse'](argv,
                                           owned_ids={container_id}) for argv in calls
                                           if len(argv) == 6 and argv[4:] ==
                                           ['delete', container_id]]
                                if len(deleted) == 1:
                                    break
                                time.sleep(0.05)
                            need(len(deleted) == 1 and ledger.lifecycle(deleted[0]) == 'delete',
                                 'native RUN delete differs')
                            records.append({'phase': phase, 'projectedSha256':
                                            observed['projectedSha256'],
                                            'snapshotEquivalence': observed['snapshotEquivalence']})
                        ledger.complete()
                        need(client.wait(timeout=1800) == 0 and
                             build_log.stat().st_size <= 8 * 1024 * 1024,
                             'native BuildKit solve failed or log exceeded bound')
                        receipt = Path('/outputs') / target / 'build-receipt.json'
                        need(receipt.is_file() and 0 < receipt.stat().st_size <= 4 * 1024 * 1024,
                             'native build receipt is missing or exceeds bound')
                    finally:
                        if client.poll() is None:
                            client.kill()
                            client.wait(timeout=10)
                need(log.stat().st_size <= 1024 * 1024,
                     'native daemon log exceeded bound')
            finally:
                if (jobs / 'engine/cgroup.procs').read_text().strip():
                    (jobs / 'engine/cgroup.kill').write_text('1\n')
                daemon.wait(timeout=10)
                adapter.close()
        return {'target': target, 'phases': records,
                'receiptSha256': hashlib.sha256(receipt.read_bytes()).hexdigest(),
                'unsignedNativeBuildDiagnostic': True,
                'releaseAuthority': False}
    finally:
        probe['JOB_CGROUP']['cleanup'](scope)
        if 'returnFd' in scope:
            os.close(scope['returnFd'])


def inside(mounted, target):
    need(target in TARGETS, 'native diagnostic target differs')
    need(os.getpid() == 1 and not any(
        line.strip().startswith('0.0.0.0') for line in
        Path('/proc/net/route').read_text().splitlines()),
        'private native PID/network namespace differs')
    mounted_exec(mounted)
    probe = runpy.run_path(str(PROBE_PATH), run_name='native_diagnostic_probe')
    plan_path = mounted / 'native-plan.json'
    data = plan_path.read_bytes()
    need(hashlib.sha256(data).hexdigest() == PLAN_SHA256,
         'native diagnostic unsigned plan differs')
    plan = json.loads(data)
    root = private_root(mounted, probe)
    result = run_target(root, plan, probe, target)
    print(json.dumps(result, sort_keys=True))


def projected(*, mounted, materials, engines, app, payload, plan, target):
    need(target in TARGETS, 'native diagnostic target differs')
    need(plan['schema'] == 'teleagent.offline-build-plan.v1' and
         plan['sourceEpoch'] == 1790168683 and
         plan['buildExecuted'] is False, 'native diagnostic plan identity differs')
    (mounted / 'native-plan.json').write_bytes(
        (json.dumps(plan, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'))
    need(hashlib.sha256((mounted / 'native-plan.json').read_bytes()).hexdigest() ==
         PLAN_SHA256, 'native diagnostic plan serialization differs')
    for name in ('native-state', 'native-outputs', 'native-tools'):
        (mounted / name).mkdir(mode=0o700)
    infra = HERE.parent.parent / 'infrastructure/scripts/release'
    for source, name in (('teleagent-offline-runtime-shim.c', 'buildkit-runc-shim'),
                         ('teleagent-offline-engine-launch.c', 'engine-launch')):
        fixed(['/usr/bin/gcc', '-static', '-no-pie', '-O2', '-o',
               str(mounted / 'native-tools' / name), str(infra / source)], timeout=90)
    result = fixed(['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork',
                    '--mount-proc', '/usr/bin/python3', '-I', str(Path(__file__).resolve()),
                    '--inside', str(mounted), target], timeout=3700, maximum=65536)
    return json.loads(result)


def main():
    need(len(sys.argv) in (4, 5) and sys.argv[1] in ('--hosted', '--inside'),
         'native diagnostic arguments differ')
    expected = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8', 'GITHUB_ACTIONS': 'true',
                'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': 'javAlborz/teleagent-release-authority',
                'GITHUB_REF': 'refs/heads/feat/hosted-capacity-probe-20260923'}
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0].lower() != 'hermes' and
         os.uname().machine == 'x86_64' and set(os.environ) == set(expected) and
         all(os.environ[key] == value for key, value in expected.items()),
         'native diagnostic hosted guard differs')
    if sys.argv[1] == '--inside':
        need(len(sys.argv) == 4 and re.fullmatch(
            r'/tmp/teleagent-storage-admission-[A-Za-z0-9_]+/mounted', sys.argv[2]),
            'native diagnostic quota path differs')
        inside(Path(sys.argv[2]), sys.argv[3])
    else:
        need(len(sys.argv) == 5 and sys.argv[4] in TARGETS,
             'native diagnostic hosted arguments differ')
        module = runpy.run_path(str(PROJECT_PATH), run_name='native_diagnostic_projection')
        result = module['project'](on_projected=lambda **kwargs: projected(
                                       target=sys.argv[4], **kwargs),
                                   workspace=Path(sys.argv[2]),
                                   runner_temp=Path(sys.argv[3]))
        need(result['cleanupVerified'] is True and
             result['projectedCallbackResult']['unsignedNativeBuildDiagnostic'] is True,
             'native diagnostic cleanup or result differs')
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
