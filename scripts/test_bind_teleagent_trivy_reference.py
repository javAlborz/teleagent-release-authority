"""Exact-digest reference binding checks on synthetic records only."""
from pathlib import Path
import runpy
import unittest

bind = runpy.run_path(str(Path(__file__).with_name('bind-teleagent-trivy-reference.py')),
                      run_name='trivy_reference_test')


class ReferenceTests(unittest.TestCase):
    def test_pinned_digest_survives_tag_rotation_but_changed_bytes_refuse(self):
        reference = {'acquiredAt': 'prior', 'resolvedTag': '2',
                     'manifestDigest': 'sha256:' + 'a' * 64,
                     'layer': {'digest': 'sha256:' + 'b' * 64}}
        acquired = {**reference, 'acquiredAt': 'fresh', 'resolvedTag': None,
                    'requestedDigest': reference['manifestDigest']}
        bind['same_selected_objects'](reference, acquired)
        for changed in ({**acquired, 'requestedDigest': 'sha256:' + 'c' * 64},
                        {**acquired, 'layer': {'digest': 'sha256:' + 'c' * 64}},
                        {**acquired, 'resolvedTag': '2'},
                        {**acquired, 'acquiredAt': ''}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                bind['same_selected_objects'](reference, changed)


if __name__ == '__main__':
    unittest.main()
