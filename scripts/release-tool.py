#!/usr/bin/env python3
"""Check a release record, retrieve evidence, verify a decision or consume an attestation."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('release_engine', HERE / 'release_engine.py')
ENGINE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ENGINE
SPEC.loader.exec_module(ENGINE)


def run_metadata(policy, expected):
    """Retry failed read-only transport, never successful but conflicting metadata."""
    for attempt in range(3):
        try:
            result = subprocess.run(
                ['gh', 'api', f'repos/{policy.AUTHORITY_REPO}/actions/runs/{expected["id"]}'],
                check=True, capture_output=True, timeout=30)
            ENGINE.need(len(result.stdout) <= 1_000_000, 'run metadata exceeds bound')
            observed = json.loads(result.stdout, object_pairs_hook=ENGINE.unique_object)
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
            if attempt == 2:
                raise ValueError('source run metadata transport failed') from None
            time.sleep(5)
    ENGINE.need(type(observed) is dict and observed.get('status') == 'completed' and
                observed.get('conclusion') == 'success' and
                observed.get('id') == expected['id'] and
                observed.get('head_sha') == expected['revision'] and
                observed.get('head_branch') == expected['branch'] and
                observed.get('run_attempt') == expected['attempt'] and
                observed.get('repository', {}).get('id') == int(policy.AUTHORITY_REPO_ID) and
                observed.get('path') == expected['workflow'] and
                observed.get('event') == expected['event'],
                'source run metadata conflicts with reviewed policy')


def fetch(policy, destination, environment):
    ENGINE.need(environment.get('GITHUB_ACTIONS') == 'true' and
                environment.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
                environment.get('GITHUB_REPOSITORY') == policy.AUTHORITY_REPO and
                environment.get('GITHUB_REPOSITORY_ID') == policy.AUTHORITY_REPO_ID and
                bool(environment.get('GH_TOKEN')) and
                os.uname().nodename.split('.')[0].lower() != 'hermes',
                'evidence retrieval requires the hosted authority repository')
    temporary = Path(environment['RUNNER_TEMP']).resolve(strict=True)
    capacity = os.statvfs(temporary)
    ENGINE.need(capacity.f_bavail * capacity.f_frsize >= 5 * 1024**3,
                'hosted evidence retrieval requires at least 5 GiB available')
    ENGINE.need(destination.is_absolute() and destination.parent.resolve(strict=True) == temporary and
                destination.parent == temporary and not destination.exists() and not destination.is_symlink(),
                'evidence destination must be a new directory directly under RUNNER_TEMP')
    for expected in policy.record['sourceRuns'].values():
        run_metadata(policy, expected)
    version = policy.version
    artifacts = [
        ('bundle-a', 'bundle', f'unsigned-v{version}-release-bundle-1',
         {'teleagent-release.diagnostic.tar', 'summary.json'}),
        ('bundle-b', 'bundle', f'unsigned-v{version}-release-bundle-2',
         {'teleagent-release.diagnostic.tar', 'summary.json'}),
        ('image', 'publicVoiceImage', f'unsigned-v{version}-voice-image-2',
         {f'teleagent-v{version}-voice-image.docker.tar'}),
        ('scan', 'freshScan', f'unsigned-v{version}-voice-image-scan',
         {'scan.json', 'scan-check.json', 'scan.stderr.log', 'db-metadata.json'}),
    ]
    destination.mkdir(mode=0o700)
    for directory, role, name, files in artifacts:
        target = destination / directory
        target.mkdir(mode=0o700)
        # Interrupted downloads leave the exact partial directory for inspection.
        # There is no overwrite, cleanup, alternate artifact or blind download retry.
        try:
            subprocess.run(['gh', 'run', 'download', str(policy.SOURCE_RUNS[role]),
                            '--repo', policy.AUTHORITY_REPO, '--name', name,
                            '--dir', str(target)], check=True, capture_output=True, timeout=300)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise ValueError('artifact retrieval failed; preserve partial evidence at ' + str(target)) from None
        ENGINE.need({p.name for p in target.iterdir()} == files,
                    'retrieved artifact members differ')
        for p in target.iterdir():
            ENGINE.checked_file(p, 2_000_000_000)
    return {'schema': 'teleagent.evidence-retrieval.v1', 'releaseVersion': version,
            'destination': str(destination), 'releaseApproved': False}


def publish(value, destination):
    body = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    ENGINE.need(len(body) <= 65536, 'output exceeds bound')
    if destination is None:
        sys.stdout.write(body.decode('ascii'))
    else:
        with destination.open('xb') as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, help='reviewed record name, for example v85')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check', help='validate local policy, input hashes and scanner source; no network')
    retrieval = commands.add_parser('fetch', help='retrieve exact hosted evidence without executing it')
    retrieval.add_argument('--destination', type=Path, required=True)
    verify = commands.add_parser('verify', help='verify complete evidence; diagnostic unless explicitly authorized')
    for name in ('bundle-a', 'bundle-b', 'summary-a', 'summary-b', 'voice-image',
                 'scan-report', 'scan-metadata', 'scan-check'):
        verify.add_argument('--' + name, type=Path, required=True)
    verify.add_argument('--authorize', action='store_true')
    verify.add_argument('--output', type=Path)
    consumer = commands.add_parser('consume', help='consume separately cryptographically verified attestation JSON')
    for name in ('verified', 'decision', 'bundle', 'approval'):
        consumer.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    ENGINE.need(ENGINE.re.fullmatch(r'v[1-9][0-9]{0,3}', args.release), 'release name differs')
    policy = ENGINE.load_policy(HERE.parent / 'releases' / (args.release + '.json'))
    if args.command == 'check':
        ENGINE.verify_selected_inputs(policy)
        ENGINE.file_hash(HERE / f'verify-v{policy.version}-voice-scan.py', 1_000_000, policy.SCAN_VERIFIER_SHA)
        publish({'schema': 'teleagent.release-policy-check.v1', 'releaseVersion': policy.version,
                 'applicationRevision': policy.APP, 'releaseId': 'sha256-' + policy.MANIFEST_SHA,
                 'bundleBytes': policy.BUNDLE_SIZE, 'sourceRuns': policy.SOURCE_RUNS,
                 'signerWorkflow': policy.WORKFLOW, 'releaseApproved': False,
                 'liveStateInspected': False}, None)
    elif args.command == 'fetch':
        publish(fetch(policy, args.destination, os.environ), None)
    elif args.command == 'verify':
        if args.authorize:
            ENGINE.authorized_context(policy, os.environ)
        candidate = ENGINE.verify_inputs(policy, args.bundle_a, args.bundle_b,
            args.summary_a, args.summary_b, args.voice_image, args.scan_report,
            args.scan_metadata, args.scan_check, datetime.now(timezone.utc))
        publish(ENGINE.decision(policy, candidate, authorize=args.authorize, environment=os.environ), args.output)
    else:
        revision = ENGINE.authorized_context(policy, os.environ)
        ENGINE.file_hash(args.bundle, policy.BUNDLE_SIZE, policy.BUNDLE_SHA, policy.BUNDLE_SIZE)
        approval = ENGINE.consume(policy, ENGINE.bounded_json(args.verified, 1024 * 1024),
                                  ENGINE.bounded_json(args.decision, 16384), revision, datetime.now(timezone.utc))
        publish(approval, args.approval)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print('release-tool: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
