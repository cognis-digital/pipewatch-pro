"""Hardening tests — error paths, edge cases, and input validation."""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipewatch_pro.cli import main
from pipewatch_pro.core import (
    audit_paths,
    audit_text,
    discover_pipeline_files,
    summarize,
)


GH_PATH = os.path.join(".github", "workflows", "ci.yml")


# ---------------------------------------------------------------------------
# core.py edge cases
# ---------------------------------------------------------------------------


class TestAuditTextEdgeCases(unittest.TestCase):
    def test_empty_string_returns_no_findings(self):
        findings = audit_text("", GH_PATH)
        self.assertEqual(findings, [])

    def test_whitespace_only_returns_no_findings(self):
        findings = audit_text("   \n\t\n  ", GH_PATH)
        self.assertEqual(findings, [])

    def test_no_trigger_no_permissions_finding(self):
        # A file with permissions but no trigger should not raise CICD-SEC-05.
        text = "name: no-trigger\npermissions:\n  contents: read\n"
        findings = audit_text(text, GH_PATH)
        rules = {f.rule_id for f in findings}
        self.assertNotIn("CICD-SEC-05", rules)

    def test_gitlab_ci_no_permissions_finding(self):
        # GitLab files must never produce the GitHub-only CICD-SEC-05 finding.
        text = "build:\n  script:\n    - uses: actions/checkout@v4\n"
        gitlab_path = ".gitlab-ci.yml"
        findings = audit_text(text, gitlab_path)
        rules = {f.rule_id for f in findings}
        self.assertNotIn("CICD-SEC-05", rules)

    def test_summarize_empty_findings(self):
        s = summarize([])
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["failed"], 0)
        self.assertEqual(s["by_severity"], {})
        self.assertEqual(s["by_rule"], {})

    def test_discover_pipeline_files_empty_root(self):
        result = discover_pipeline_files("")
        self.assertEqual(result, [])

    def test_audit_paths_skips_empty_string_entries(self):
        # Empty-string entries in the paths list must be silently skipped.
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, ".github", "workflows")
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, "ci.yml")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("name: ci\non:\n  push:\npermissions:\n  contents: read\n")
            # Empty string must not cause FileNotFoundError.
            findings = audit_paths(["", tmp])
            self.assertIsInstance(findings, list)

    def test_audit_paths_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            audit_paths(["/absolutely/does/not/exist/xyz123"])


# ---------------------------------------------------------------------------
# cli.py error paths
# ---------------------------------------------------------------------------


class TestCLIErrorPaths(unittest.TestCase):
    def test_permission_denied_exits_two(self):
        """A file that cannot be read should exit 2 with a clear stderr message."""
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, ".github", "workflows")
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, "ci.yml")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("name: ci\n")
            # Mark file unreadable (skip on Windows where chmod is limited).
            try:
                os.chmod(p, 0o000)
                # Verify that the OS actually enforces the permission.
                try:
                    with open(p, "r"):
                        pass
                    # If we can still open it (e.g. running as root), skip.
                    self.skipTest("Cannot restrict read permission on this OS/user")
                except PermissionError:
                    pass
            except (NotImplementedError, AttributeError):
                self.skipTest("chmod not supported on this platform")

            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                rc = main(["audit", p])
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
            self.assertEqual(rc, 2)
            self.assertIn("error", stderr_buf.getvalue().lower())

    def test_missing_path_stderr_message(self):
        """Missing path must print an error message to stderr, not a traceback."""
        stderr_buf = io.StringIO()
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            rc = main(["audit", "/no/such/path/xyz_missing"])
        self.assertEqual(rc, 2)
        err_text = stderr_buf.getvalue()
        self.assertIn("error", err_text.lower())
        self.assertNotIn("Traceback", err_text)

    def test_directory_with_no_pipelines_exits_zero(self):
        """A directory containing no pipeline files should exit 0 with no findings."""
        with tempfile.TemporaryDirectory() as tmp:
            # Write a non-pipeline file.
            with open(os.path.join(tmp, "README.md"), "w", encoding="utf-8") as fh:
                fh.write("# readme\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", tmp])
            self.assertEqual(rc, 0)

    def test_fail_on_medium_exits_one_for_medium_finding(self):
        """--fail-on medium must gate on medium-severity findings."""
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, ".github", "workflows")
            os.makedirs(d, exist_ok=True)
            # Workflow with no permissions block (medium CICD-SEC-05).
            text = (
                "name: ci\non:\n  push:\njobs:\n  build:\n"
                "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
            )
            with open(os.path.join(d, "ci.yml"), "w", encoding="utf-8") as fh:
                fh.write(text)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", tmp, "--fail-on", "medium"])
            self.assertEqual(rc, 1)

    def test_json_output_valid_json_on_empty_dir(self):
        """JSON output on a directory with no pipeline files must be valid JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", tmp, "--format", "json"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["findings"], [])
            self.assertEqual(payload["summary"]["total"], 0)


# ---------------------------------------------------------------------------
# webhook.py input validation
# ---------------------------------------------------------------------------


class TestWebhookValidation(unittest.TestCase):
    def _run_webhook_main(self, argv, stdin_text=""):
        """Import and call integrations.webhook.main() with fake stdin."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "webhook",
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "integrations",
                "webhook.py",
            ),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        old_argv = sys.argv
        old_stdin = sys.stdin
        sys.argv = ["webhook"] + argv
        sys.stdin = io.StringIO(stdin_text)
        stderr_buf = io.StringIO()
        try:
            with redirect_stderr(stderr_buf):
                rc = mod.main()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
        return rc, stderr_buf.getvalue()

    def test_bad_url_scheme_exits_two(self):
        rc, err = self._run_webhook_main(["--url", "ftp://example.com/hook"])
        self.assertEqual(rc, 2)
        self.assertIn("http", err.lower())

    def test_empty_stdin_exits_two(self):
        rc, err = self._run_webhook_main(["--url", "https://example.com/hook"], "")
        self.assertEqual(rc, 2)
        self.assertIn("stdin", err.lower())

    def test_invalid_json_stdin_exits_two(self):
        rc, err = self._run_webhook_main(
            ["--url", "https://example.com/hook"], "not json at all!!!"
        )
        self.assertEqual(rc, 2)
        self.assertIn("json", err.lower())


if __name__ == "__main__":
    unittest.main()
