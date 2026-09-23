#!/usr/bin/python3 -I
"""Bind a fresh identical Trivy download to the fixed acquisition reference.

The acquisition's actual time-bearing manifest is retained separately. The
projector uses the fixed reference so two independent jobs have identical
material-plan bytes when they download the same OCI objects.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

PIN = '0d044673603e2e2c9c0ac23a8d0d9c7d694bae4f22542559e3f2fafe2012675c'
MAX_JSON = 4 * 1024 * 1024


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate Trivy acquisition field')
        result[key] = value
    return result


def read(path):
    data = path.read_bytes()
    if not 0 < len(data) <= MAX_JSON:
        raise ValueError('Trivy acquisition manifest byte bound')
    return data, json.loads(data, object_pairs_hook=unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acquired', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    reference_bytes, reference = read(args.reference)
    if hashlib.sha256(reference_bytes).hexdigest() != PIN:
        raise ValueError('Trivy reference digest differs')
    manifest = args.acquired / 'manifest.json'
    generated_bytes, generated = read(manifest)
    if (set(reference) != set(generated) or
            any(reference[key] != generated[key] for key in reference if key != 'acquiredAt')):
        raise ValueError('fresh Trivy acquisition differs from pinned object set')
    if type(generated['acquiredAt']) is not str or not generated['acquiredAt']:
        raise ValueError('fresh Trivy acquisition timestamp absent')
    actual = args.acquired / 'manifest.generated.json'
    if actual.exists():
        raise ValueError('fresh Trivy acquisition already bound')
    manifest.rename(actual)
    with manifest.open('xb') as output:
        output.write(reference_bytes)
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({'freshManifestSha256': hashlib.sha256(generated_bytes).hexdigest(),
                      'referenceSha256': PIN, 'sameObjects': True,
                      'signatureVerified': False, 'scannerExecuted': False}, sort_keys=True))


if __name__ == '__main__':
    main()
