#!/usr/bin/python3 -I
"""Measure one disposable, bounded release-build filesystem on a hosted VM."""

import ctypes
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile

GIB = 1024 ** 3
IMAGE_BYTES = 32 * GIB
MIN_BUILD_AVAILABLE = 30 * GIB
MIN_HOST_RESERVE = 15 * GIB
MIN_INITIAL = IMAGE_BYTES + MIN_HOST_RESERVE + GIB


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def space(path):
    observed = os.statvfs(path)
    return {'availableBytes': observed.f_bavail * observed.f_frsize,
            'availableInodes': observed.f_favail,
            'filesystemBytes': observed.f_blocks * observed.f_frsize,
            'filesystemInodes': observed.f_files}


def fixed(argv, *, timeout=60):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    need(len(result.stdout) <= 4096 and len(result.stderr) <= 4096,
         'storage tool output exceeds bound')
    need(result.returncode == 0,
         'storage tool refused: ' + argv[0] + ' exit=' + str(result.returncode) +
         ' stderr=' + result.stderr.decode('utf-8', 'replace')[-1024:])
    return result.stdout


def detached(image):
    return fixed(['/usr/sbin/losetup', '-j', str(image)]).strip() == b''


def detach_owned_loop(image):
    listing = fixed(['/usr/sbin/losetup', '-j', str(image)]).decode('utf-8', 'replace').strip()
    if not listing:
        return
    rows = listing.splitlines()
    need(len(rows) == 1 and rows[0].endswith('(' + str(image) + ')'),
         'owned loop lookup returned an unexpected backing image')
    device = rows[0].split(':', 1)[0]
    need(re.fullmatch(r'/dev/loop[0-9]{1,4}', device) is not None,
         'owned loop lookup returned an unexpected device')
    fixed(['/usr/sbin/losetup', '-d', device])


def guard():
    need(os.uname().nodename.split('.')[0].lower() != 'hermes',
         'never run hosted storage admission on Hermes')
    need(os.geteuid() == 0 and os.uname().machine == 'x86_64',
         'root x86_64 hosted runner required')
    expected = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8', 'GITHUB_ACTIONS': 'true',
                'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': 'javAlborz/teleagent-release-authority',
                'GITHUB_REF': 'refs/heads/feat/hosted-capacity-probe-20260923'}
    need(set(os.environ) == set(expected) and
         all(os.environ[key] == value for key, value in expected.items()),
         'exact hosted storage environment required')


@contextmanager
def admitted_storage():
    """Yield the exact bounded filesystem; drain users before leaving the scope."""
    guard()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    initial = space('/tmp')
    need(initial['availableBytes'] >= MIN_INITIAL and
         initial['availableInodes'] >= 100000,
         'host does not have enough capacity for a 32 GiB image and 15 GiB reserve')
    root = Path(tempfile.mkdtemp(prefix='teleagent-storage-admission-', dir='/tmp'))
    need(root.stat().st_uid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o700,
         'owned storage directory differs')
    image = root / 'quota.img'
    mountpoint = root / 'mounted'
    mountpoint.mkdir(mode=0o700)
    original_device = root.stat().st_dev
    image_fd = None
    try:
        image_fd = os.open(image, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                           os.O_CLOEXEC, 0o600)
        os.posix_fallocate(image_fd, 0, IMAGE_BYTES)
        os.fsync(image_fd)
        admitted = os.fstat(image_fd)
        need(stat.S_ISREG(admitted.st_mode) and admitted.st_uid == 0 and
             admitted.st_gid == 0 and admitted.st_nlink == 1 and
             admitted.st_size == IMAGE_BYTES and admitted.st_blocks * 512 >= IMAGE_BYTES,
             'quota image was not fully allocated and owned')
        need(space('/tmp')['availableBytes'] >= MIN_HOST_RESERVE,
             'host reserve was exhausted by quota preallocation')

        libc = ctypes.CDLL(None, use_errno=True)
        if libc.unshare(0x00020000) != 0:  # CLONE_NEWNS
            raise OSError(ctypes.get_errno(), 'private storage mount namespace failed')
        if libc.mount(None, b'/', None, ctypes.c_ulong(16384 | 1 << 18), None) != 0:
            raise OSError(ctypes.get_errno(), 'private storage mount propagation failed')
        fixed(['/usr/sbin/mkfs.ext4', '-q', '-F', '-m', '0', '-N', '2000000', str(image)],
              timeout=120)
        # mke2fs may punch unused ranges out of an image. Reserve them again
        # after formatting so the loop filesystem cannot outrun its backing.
        os.posix_fallocate(image_fd, 0, IMAGE_BYTES)
        os.fsync(image_fd)
        need(os.fstat(image_fd).st_blocks * 512 >= IMAGE_BYTES,
             'formatted image lost its fully allocated backing')
        need(initial['availableBytes'] - space('/tmp')['availableBytes'] >= IMAGE_BYTES - GIB,
             'formatted image did not consume the expected host allocation')
        fixed(['/usr/bin/mount', '--no-mtab', '-t', 'ext4', '-o',
               'loop,nosuid,nodev,noexec', str(image), str(mountpoint)])
        need(mountpoint.stat().st_dev != original_device,
             'quota image was not mounted as a separate filesystem')
        measured = space(mountpoint)
        host_after = space('/tmp')
        need(0 < measured['filesystemBytes'] <= IMAGE_BYTES and
             measured['availableBytes'] >= MIN_BUILD_AVAILABLE and
             100000 <= measured['filesystemInodes'] <= 3000000 and
             host_after['availableBytes'] >= MIN_HOST_RESERVE and
             initial['availableBytes'] - host_after['availableBytes'] >= IMAGE_BYTES - GIB and
             os.fstat(image_fd).st_blocks * 512 >= IMAGE_BYTES,
             'mounted quota or host reserve differs')
        result = {'purpose': 'inert-release-storage-admission',
                  'initialHost': initial, 'postAllocationHost': host_after,
                  'quotaImageBytes': IMAGE_BYTES, 'mountedQuota': measured,
                  'hostAllocatedDeltaBytes': initial['availableBytes'] -
                                             host_after['availableBytes'],
                  'minimumBuildAvailableBytes': MIN_BUILD_AVAILABLE,
                  'minimumHostReserveBytes': MIN_HOST_RESERVE,
                  'buildPeakMeasured': False, 'teleagentBuildExecuted': False}
        yield mountpoint, result
        result['afterWorkloadQuota'] = space(mountpoint)
        result['afterWorkloadHost'] = space('/tmp')
        need(result['afterWorkloadHost']['availableBytes'] >= MIN_HOST_RESERVE and
             os.fstat(image_fd).st_blocks * 512 >= IMAGE_BYTES and
             mountpoint.stat().st_dev != original_device,
             'post-workload quota backing or host reserve differs')
    finally:
        if mountpoint.stat().st_dev != original_device:
            fixed(['/usr/bin/umount', '--no-mtab', '--detach-loop', str(mountpoint)])
        detach_owned_loop(image)
        need(mountpoint.stat().st_dev == original_device and detached(image),
             'owned quota mount or loop device remained attached')
        if image_fd is not None:
            now = os.stat(image, follow_symlinks=False)
            held = os.fstat(image_fd)
            need((now.st_dev, now.st_ino, now.st_uid, now.st_gid, now.st_nlink,
                  now.st_size) ==
                 (held.st_dev, held.st_ino, held.st_uid, held.st_gid, held.st_nlink,
                  held.st_size), 'owned quota image changed before cleanup')
            os.close(image_fd)
            image.unlink()
        mountpoint.rmdir()
        root.rmdir()
        need(not root.exists(), 'owned storage directory remained after cleanup')
    result['cleanupVerified'] = True


def main():
    with admitted_storage() as (_, result):
        pass
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
