#!/usr/bin/env python3
"""Read-only comparison of shared and frozen verification against real hosted evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True)
    parser.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'v[1-9][0-9]{0,3}', args.release):
        parser.error('release must name an exact reviewed record')
    engine = load('parity_release_engine', HERE / 'release_engine.py')
    policy = engine.load_policy(HERE.parent / 'releases' / (args.release + '.json'))
    reference = engine.bounded_json(HERE / 'fixtures' / (args.release + '-engine-reference.json'), 16384)
    engine.need(reference['schema'] == 'teleagent.release-engine-reference.v1' and
                reference['version'] == policy.version, 'reference policy differs')
    for filename, digest in reference['files'].items():
        engine.need(re.fullmatch(r'[a-zA-Z0-9_-]+\.(py|sh)', filename), 'reference filename differs')
        engine.file_hash(HERE / filename, 1_000_000, digest)
    original = load('frozen_parity_verifier', HERE / f'verify-{args.release}-release-decision.py')
    root = args.input
    inputs = [root / 'bundle-a/teleagent-release.diagnostic.tar',
              root / 'bundle-b/teleagent-release.diagnostic.tar',
              root / 'bundle-a/summary.json', root / 'bundle-b/summary.json',
              root / 'image' / f'teleagent-{args.release}-voice-image.docker.tar',
              root / 'scan/scan.json', root / 'scan/db-metadata.json', root / 'scan/scan-check.json']
    now = datetime.now(timezone.utc)
    expected = original.verify_inputs(*inputs, now)
    actual = engine.verify_inputs(policy, *inputs, now)
    engine.need(actual == expected, 'shared verifier differs from the frozen verifier')
    old_decision = original.decision(expected, authorize=False, environment={})
    new_decision = engine.decision(policy, actual, authorize=False, environment={})
    engine.need(new_decision == old_decision, 'diagnostic decision differs')
    encoded = json.dumps(new_decision, sort_keys=True, separators=(',', ':')).encode('ascii')
    print(json.dumps({'schema': 'teleagent.release-engine-parity.v1',
                      'releaseVersion': policy.version, 'referenceRevision': reference['authorityRevision'],
                      'bundleSha256': policy.BUNDLE_SHA, 'diagnosticDecisionSha256': hashlib.sha256(encoded).hexdigest(),
                      'equivalent': True, 'releaseApproved': False, 'installed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
