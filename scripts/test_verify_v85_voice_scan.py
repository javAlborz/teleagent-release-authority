#!/usr/bin/python3 -I
"""Regression checks for missing-detail scan warnings and vulnerable inventories."""
from pathlib import Path
import runpy
import tempfile
import unittest

M = runpy.run_path(str(Path(__file__).with_name('verify-v85-voice-scan.py')))


class ScanEvidence(unittest.TestCase):
    def test_patched_body_parser_required_even_with_zero_reported_findings(self):
        good = {'Name': 'body-parser', 'Version': '1.20.9'}
        M['verify_body_parser']([good])
        for packages in ([], [{**good, 'Version': '1.20.6'}], [good, good]):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                M['verify_body_parser'](packages)

    def log(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'scan.stderr.log'
            p.write_text(text)
            return M['verify_scanner_log'](p)

    def test_missing_detail_warning_refuses(self):
        with self.assertRaisesRegex(ValueError, 'incomplete vulnerability'):
            self.log('2026-10-23T15:34:54Z\tWARN\tUnable to get vulnerability details (CVE may be rejected)\terr.context.vuln_id="CVE-2026-107891"\n')

    def test_unknown_warning_and_error_refuse(self):
        for level in ('WARN', 'ERROR', 'FATAL'):
            with self.subTest(level=level), self.assertRaises(ValueError):
                self.log('2026-10-23T15:34:54Z\t' + level + '\tFailed to scan package\n')

    def test_known_lifecycle_metadata_warning_is_distinct(self):
        self.assertEqual(len(self.log('2026-10-23T15:34:54Z\tWARN\tThis OS version is not on the EOL list\tfamily="alpine" version="3.24"\n')), 64)

    def test_empty_log_refuses(self):
        with self.assertRaises(ValueError):
            self.log('')

    def test_patched_inventory_required_even_with_zero_reported_findings(self):
        packages = [{'Name': k, 'Version': v} for k, v in M['RUNTIME_PACKAGES'].items()]
        M['verify_runtime_packages'](packages)
        for name in M['RUNTIME_PACKAGES']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                M['verify_runtime_packages']([{**p, 'Version': 'old'} if p['Name'] == name else p for p in packages])
        with self.assertRaises(ValueError):
            M['verify_runtime_packages'](packages + [packages[0]])


if __name__ == '__main__':
    unittest.main()
