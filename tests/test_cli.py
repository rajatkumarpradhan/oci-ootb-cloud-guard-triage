import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from oci_ootb_cloud_guard_triage.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCli(unittest.TestCase):
    def test_missing_file_exits_1(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["/nonexistent/problems.json"]), 1)

    def test_invalid_json_exits_1(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main([os.path.join(ROOT, "pyproject.toml")]), 1)

    def test_seeded_export_exits_2_and_lists_rules(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([os.path.join(ROOT, "samples", "cloud-guard-problems.json")])
        self.assertEqual(code, 2)
        text = out.getvalue()
        self.assertIn("INSTANCE_SSH_PUBLIC_ACCESS", text)
        self.assertIn("prob-1001", text)
        # Resolved problems must not appear in the triage output.
        self.assertNotIn("prob-1005", text)
        self.assertIn("summary:", text)

    def test_clean_export_exits_0(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([os.path.join(ROOT, "samples", "cloud-guard-problems-clean.json")])
        self.assertEqual(code, 0)
        self.assertIn("0 critical", out.getvalue())


if __name__ == "__main__":
    unittest.main()
