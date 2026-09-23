#!/usr/bin/python3 -I
"""Project pinned Teleagent inputs as data inside one disposable 32 GiB volume."""

import argparse
from contextlib import contextmanager
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess

MATERIAL_SOURCE_SHA256 = 'a548aad7e6018d57bbddad2eaf99a2fc7ffe1f69ae328982a9d97925448c9cf0'
ENGINE_SOURCE_SHA256 = '0f976d28a4d774346df1942c07fcb40ea1c5d055be9d906e877f4b2428843857'
PLANNER_SOURCE_SHA256 = '11bff95cc2d09c7ed1c8edbcde7a36d173d7b93b313f6eab3d5210c6673181ae'
SOURCE_PAIRS_SHA256 = '8ac1ec2f3599ededaa0e6aefea9d68a3629e3f047bcd514ffe89940d8e3c9e89'
TRIVY_MANIFEST_SHA256 = '0d044673603e2e2c9c0ac23a8d0d9c7d694bae4f22542559e3f2fafe2012675c'
MATERIAL_PLAN_SHA256 = '1bee8f8df904286a1dcddcc23471fa10cfb96b662b4af68feb866cfc18114cd5'
ENGINE_PLAN_SHA256 = '5c2dfee0e305d5a84a7debb142b7ddbae3b4dc855a89126622449ebbd2c6e993'
SOURCE_EPOCH = 1790168683  # Exact pinned app commit's committer timestamp.
UNSIGNED_PLAN_SHA256 = 'e9904348d4daf0453842217aacd07148373e14e376279c9614e0adbde585d36c'


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def same_file(path, expected):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_size <= 4 * 1024 ** 2,
             'pinned data or source metadata differs: ' + path.name)
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(descriptor)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
              before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
              after.st_ctime_ns), 'pinned data changed while hashing: ' + path.name)
    finally:
        os.close(descriptor)
    need(actual == expected, 'pinned data or source hash differs: ' + path.name)


def fixed(argv, *, uid, gid, maximum=16384):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=1800, check=False,
                            user=uid, group=gid, extra_groups=[])
    need(len(result.stdout) <= maximum and len(result.stderr) <= maximum,
         'data projection output exceeded bound')
    need(result.returncode == 0,
         'data projection refused: ' + Path(argv[2]).name +
         ' exit=' + str(result.returncode) +
         ' stderr=' + result.stderr.decode('utf-8', 'replace')[-2048:])
    return result.stdout


def stage_small_tree(source, destination, rows):
    """Copy an exact small source closure into immutable data modes."""
    need(type(rows) is list and 0 < len(rows) <= 16,
         'small source closure count differs')
    destination.mkdir(mode=0o700)
    folders = {destination}
    names = set()
    for row in rows:
        name, expected = row['path'], row['sha256']
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./+-]{1,2048}', name) and
             all(part not in ('', '.', '..') for part in name.split('/')) and
             name not in names and type(expected) is str and
             re.fullmatch('[a-f0-9]{64}', expected),
             'small source closure path or hash differs')
        names.add(name)
        original = source / name
        same_file(original, expected)
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        folders.add(target.parent)
        source_fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                            os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        try:
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                offset = 0
                while offset < len(chunk):
                    amount = os.write(target_fd, chunk[offset:])
                    need(amount > 0, 'small source projection short write')
                    offset += amount
            os.fsync(target_fd)
            os.fchmod(target_fd, 0o444)
            os.utime(target_fd, ns=(0, 0))
        finally:
            os.close(target_fd)
            os.close(source_fd)
        same_file(original, expected)
        same_file(target, expected)
    for folder in sorted(folders, key=lambda item: len(item.parts), reverse=True):
        folder.chmod(0o555)
        os.utime(folder, ns=(0, 0))
    return len(names)


@contextmanager
def sealed_alias(source, alias):
    """Expose one verified tree through a distinct read-only private mount."""
    alias.mkdir(mode=0o700)
    libc = ctypes.CDLL(None, use_errno=True)
    mounted = False
    try:
        if libc.mount(os.fsencode(source), os.fsencode(alias), None,
                      ctypes.c_ulong(4096), None) != 0:  # MS_BIND
            raise OSError(ctypes.get_errno(), 'private input bind refused')
        mounted = True
        if libc.mount(None, os.fsencode(alias), None,
                      ctypes.c_ulong(32 | 4096 | 1 | 2 | 4 | 8), None) != 0:
            raise OSError(ctypes.get_errno(), 'private input read-only remount refused')
        need((source.stat().st_dev, source.stat().st_ino) ==
             (alias.stat().st_dev, alias.stat().st_ino) and
             os.statvfs(alias).f_flag & os.ST_RDONLY,
             'sealed alias identity or read-only state differs')
        try:
            (alias / 'write-must-fail').open('xb').close()
        except OSError as error:
            need(error.errno == errno.EROFS, 'sealed alias write returned unexpected error')
        else:
            raise RuntimeError('sealed alias permitted a write')
        yield alias
    finally:
        if mounted and libc.umount2(os.fsencode(alias), 0) != 0:
            raise OSError(ctypes.get_errno(), 'private sealed alias unmount refused')
        alias.rmdir()


def project(on_projected=None, *, workspace=None, runner_temp=None):
    if workspace is None or runner_temp is None:
        need(workspace is None and runner_temp is None and on_projected is None,
             'projection requires both exact hosted roots')
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--workspace', required=True, type=Path)
        parser.add_argument('--runner-temp', required=True, type=Path)
        args = parser.parse_args()
        workspace, runner_temp = args.workspace, args.runner_temp
    need(isinstance(workspace, Path) and isinstance(runner_temp, Path),
         'projection roots must be paths')
    need(workspace.is_absolute() and runner_temp.is_absolute() and
         workspace.is_dir() and runner_temp.is_dir() and
         workspace.name == 'teleagent-release-authority' and
         runner_temp.name == '_temp', 'hosted workspace or temporary root differs')
    authority = workspace / 'authority'
    infra = workspace / 'infrastructure'
    app = workspace / 'app'
    inputs = runner_temp / 'teleagent-inputs'
    need(all(item.is_dir() for item in (authority, infra, app, inputs)),
         'exact checked-out source and input roots required')
    owner = workspace.stat()
    uid, gid = owner.st_uid, owner.st_gid
    need(0 < uid <= 65535 and 0 < gid <= 65535 and
         all(item.stat().st_uid == uid and item.stat().st_gid == gid for item in
             (authority, infra, app, inputs, runner_temp)),
         'hosted runner source/input ownership differs')
    release = infra / 'scripts/release'
    same_file(release / 'teleagent-offline-materials.py', MATERIAL_SOURCE_SHA256)
    same_file(release / 'teleagent-offline-engine-materials.py', ENGINE_SOURCE_SHA256)
    same_file(release / 'teleagent-offline-build-plan.py', PLANNER_SOURCE_SHA256)
    same_file(inputs / 'trivy/manifest.json', TRIVY_MANIFEST_SHA256)
    pairs_path = authority / 'inputs/teleagent/source-pairs.json'
    same_file(pairs_path, SOURCE_PAIRS_SHA256)
    pairs = json.loads(pairs_path.read_bytes())
    need(type(pairs) is list and len(pairs) == 12 and
         all(type(row) is dict and set(row) == {'path', 'sha256'} for row in pairs),
         'exact source-pair record differs')
    for row in pairs:
        same_file(app / row['path'], row['sha256'])
    storage = runpy.run_path(str(authority / 'scripts/hosted-storage-admission.py'),
                             run_name='teleagent_projected_storage')
    with storage['admitted_storage']() as (mounted, result):
        mounted.parent.chmod(0o755)
        os.chown(mounted, uid, gid)
        materials = mounted / 'teleagent-materials'
        engines = mounted / 'teleagent-engines'
        fixed(['/usr/bin/python3', '-I', str(release / 'teleagent-offline-materials.py'),
               '--oci', str(inputs / 'oci'), '--npm', str(inputs / 'npm'),
               '--trivy', str(inputs / 'trivy'),
               '--tools', str(inputs / 'fixed/tools'),
               '--indexes', str(inputs / 'fixed/indexes'),
               '--apk', str(inputs / 'fixed/apk'),
               '--providers', str(inputs / 'fixed/providers'),
               '--app-source', str(app),
               '--candidate-trivy-manifest-sha256', TRIVY_MANIFEST_SHA256,
               '--output', str(materials)], uid=uid, gid=gid)
        fixed(['/usr/bin/python3', '-I', str(release / 'teleagent-offline-engine-materials.py'),
               '--input', str(inputs / 'fixed/engine'), '--output', str(engines)],
              uid=uid, gid=gid)
        with sealed_alias(materials, mounted / 'sealed-materials') as sealed_materials:
            with sealed_alias(engines, mounted / 'sealed-engines') as sealed_engines:
                verified = json.loads(fixed(
                    ['/usr/bin/python3', '-I',
                     str(authority / 'scripts/verify-teleagent-data-projection.py'),
                     '--infra', str(infra), '--materials', str(sealed_materials),
                     '--engines', str(sealed_engines)], uid=uid, gid=gid,
                    maximum=65536))
                same_file(sealed_materials / 'material-plan.json', MATERIAL_PLAN_SHA256)
                same_file(sealed_engines / 'engine-plan.json', ENGINE_PLAN_SHA256)
                planned = fixed(
                    ['/usr/bin/python3', '-I', str(release / 'teleagent-offline-build-plan.py'),
                     '--material-plan', str(sealed_materials / 'material-plan.json'),
                     '--source-pairs', str(pairs_path), '--payload-root', str(release),
                     '--engine-plan-sha256', ENGINE_PLAN_SHA256,
                     '--epoch', str(SOURCE_EPOCH)], uid=uid, gid=gid, maximum=65536)
                plan = json.loads(planned)
                need(hashlib.sha256(planned).hexdigest() == UNSIGNED_PLAN_SHA256 and
                     plan['materialPlanSha256'] == MATERIAL_PLAN_SHA256 and
                     plan['enginePlanSha256'] == ENGINE_PLAN_SHA256 and
                     plan['sourcePairsSha256'] == SOURCE_PAIRS_SHA256 and
                     plan['sourceEpoch'] == SOURCE_EPOCH and
                     all(plan[name] is False for name in
                         ('executable', 'runtimeAccepted', 'buildExecuted',
                          'signatureVerified', 'promotionAuthorized')),
                     'unsigned offline plan authority or bindings differ')
                app_projection = mounted / 'teleagent-app-source'
                payload_projection = mounted / 'teleagent-payload-source'
                app_count = stage_small_tree(app, app_projection, pairs)
                payload_count = stage_small_tree(
                    release, payload_projection, plan['payloadSourceClosure'])
                with sealed_alias(app_projection, mounted / 'sealed-app-source') as sealed_app:
                    with sealed_alias(payload_projection, mounted / 'sealed-payload-source') as sealed_payload:
                        for row in pairs:
                            same_file(sealed_app / row['path'], row['sha256'])
                        for row in plan['payloadSourceClosure']:
                            same_file(sealed_payload / row['path'], row['sha256'])
                        if on_projected is not None:
                            result['projectedCallbackResult'] = on_projected(
                                mounted=mounted, materials=sealed_materials,
                                engines=sealed_engines, app=sealed_app,
                                payload=sealed_payload, plan=plan)
                need(app_count == 12 and payload_count == 3,
                     'small source closure projection count differs')
        need(verified['materialProjection']['dataOnly'] is True and
             verified['engineProjection']['dataOnly'] is True and
             verified['buildExecuted'] is False and verified['signatureVerified'] is False,
             'bounded projection evidence differs')
        result['purpose'] = 'bounded-teleagent-data-projection'
        result['materialPlanSha256'] = MATERIAL_PLAN_SHA256
        result['enginePlanSha256'] = ENGINE_PLAN_SHA256
        result['unsignedBuildPlanSha256'] = UNSIGNED_PLAN_SHA256
        result['sourceEpoch'] = SOURCE_EPOCH
        result['trivyFreshnessAcceptedForBuild'] = False
        result['privateInputReadOnlyAliasesVerified'] = True
        result['appSourcePairFilesProjected'] = app_count
        result['payloadSourceFilesProjected'] = payload_count
        result['teleagentBuildExecuted'] = on_projected is not None
        mounted.parent.chmod(0o700)
    need(result['cleanupVerified'] is True and result['afterWorkloadQuota']['availableBytes'] >=
         20 * 1024 ** 3, 'bounded material projection consumed unexpected quota')
    return result


def main():
    print(json.dumps(project(), sort_keys=True))


if __name__ == '__main__':
    main()
