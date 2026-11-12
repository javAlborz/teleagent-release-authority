#!/usr/bin/python3 -I
"""Check that each recorded release's cryptographic consumer hashes its own bundle."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def consumer_digest(source):
    marker = '      - name: Verify exact custom attestation and signer identity\n'
    if source.count(marker) != 1:
        raise ValueError('consumer boundary missing or duplicated')
    section = source.split(marker, 1)[1].split('\n      - name:', 1)[0]
    pins = re.findall(r"'([0-9a-f]{64})'", section)
    if len(pins) != 1 or 'sha256sum --check --status' not in section:
        raise ValueError('consumer digest pin missing or ambiguous')
    return pins[0]


class WorkflowBindings(unittest.TestCase):
    def test_recorded_workflows_bind_their_own_bundle_before_signature_verification(self):
        for record in sorted((ROOT / 'releases').glob('v*.json')):
            policy = json.loads(record.read_bytes())
            path = ROOT / f'.github/workflows/teleagent-v{policy["version"]}-release-decision.yml'
            with self.subTest(release=record.name):
                self.assertEqual(consumer_digest(path.read_text()), policy['bundleSha256'])

    def test_previous_release_pin_and_missing_checks_are_not_accepted(self):
        policy = json.loads((ROOT / 'releases/v87.json').read_bytes())
        source = (ROOT / '.github/workflows/teleagent-v87-release-decision.yml').read_text()
        old = json.loads((ROOT / 'releases/v86.json').read_bytes())['bundleSha256']
        self.assertNotEqual(consumer_digest(source.replace(policy['bundleSha256'], old)), policy['bundleSha256'])
        for changed in [source.replace('sha256sum --check --status', 'true'),
                        source.replace("'" + policy['bundleSha256'] + "'", '"$UNBOUND_DIGEST"')]:
            with self.assertRaises(ValueError):
                consumer_digest(changed)


if __name__ == '__main__':
    unittest.main()
