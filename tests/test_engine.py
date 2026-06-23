"""Detailed detector + CLI behaviour tests (stdlib unittest, offline only)."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipewatch_pro import (
    audit_text, audit_paths, summarize, to_sarif, extract_components,
    TOOL_NAME, TOOL_VERSION, SEVERITY_ORDER, Finding,
)
from pipewatch_pro.core import scan, discover_pipeline_files, _is_pipeline_file
from pipewatch_pro.cli import main, build_parser, enrich_components


GH = os.path.join(".github", "workflows", "ci.yml")
GITLAB = ".gitlab-ci.yml"


class TestActionPinning(unittest.TestCase):
    def test_tag_pinned_action_is_high(self):
        f = audit_text("    - uses: actions/checkout@v4\n", GH)
        m = [x for x in f if x.rule_id == "CICD-SEC-04"]
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0].severity, "high")

    def test_main_branch_ref_is_critical(self):
        f = audit_text("    - uses: foo/bar@main\n", GH)
        m = [x for x in f if x.rule_id == "CICD-SEC-04"]
        self.assertEqual(m[0].severity, "critical")

    def test_master_branch_ref_is_critical(self):
        f = audit_text("    - uses: foo/bar@master\n", GH)
        self.assertEqual(f[0].severity, "critical")

    def test_latest_ref_is_critical(self):
        f = audit_text("    - uses: foo/bar@latest\n", GH)
        self.assertTrue(any(x.severity == "critical" for x in f))

    def test_sha_pinned_action_not_flagged(self):
        sha = "8f152de45cc393bb48ce5d89d36b731f54556e65"
        f = audit_text(f"    - uses: actions/checkout@{sha}\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-04"], [])

    def test_local_action_not_flagged(self):
        f = audit_text("    - uses: ./.github/actions/local\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-04"], [])

    def test_docker_action_not_flagged(self):
        f = audit_text("    - uses: docker://alpine:3.18\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-04"], [])

    def test_quoted_ref_is_parsed(self):
        f = audit_text("    - uses: 'actions/checkout@v4'\n", GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-04"])

    def test_evidence_contains_ref(self):
        f = audit_text("    - uses: actions/checkout@v4\n", GH)
        self.assertIn("actions/checkout@v4", f[0].evidence)

    def test_line_number_is_accurate(self):
        text = "\n\n    - uses: actions/checkout@v4\n"
        f = audit_text(text, GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-04"][0].line, 3)

    def test_owasp_reference_present(self):
        f = audit_text("    - uses: a/b@v1\n", GH)
        self.assertIn("CICD-SEC-04", f[0].owasp)


class TestCurlPipe(unittest.TestCase):
    def test_curl_bash(self):
        f = audit_text("      - run: curl https://x/i.sh | bash\n", GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-07"])

    def test_curl_sh(self):
        f = audit_text("      - run: curl https://x/i.sh | sh\n", GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-07"])

    def test_wget_bash(self):
        f = audit_text("      - run: wget -qO- https://x/i.sh | bash\n", GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-07"])

    def test_curl_sudo_sh(self):
        f = audit_text("      - run: curl https://x/i.sh | sudo sh\n", GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-07"])

    def test_curl_to_file_not_flagged(self):
        f = audit_text("      - run: curl -o i.sh https://x/i.sh\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-07"], [])

    def test_curl_pipe_high_severity(self):
        f = audit_text("      - run: curl https://x/i.sh | bash\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-07"][0].severity, "high")


class TestSecrets(unittest.TestCase):
    def test_hardcoded_api_key(self):
        f = audit_text("        API_KEY: abcdef0123456789abcdef\n", GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-06"])

    def test_hardcoded_is_critical(self):
        f = audit_text("        password: supersecretvalue12345\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-06"][0].severity, "critical")

    def test_hardcoded_secret_redacted(self):
        f = audit_text("        token: abcdefgh01234567890xyz\n", GH)
        ev = [x for x in f if x.rule_id == "CICD-SEC-06"][0].evidence
        self.assertIn("redacted", ev)

    def test_placeholder_not_flagged(self):
        f = audit_text("        password: changeme\n", GH)
        self.assertEqual([x for x in f if x.line and x.rule_id == "CICD-SEC-06"], [])

    def test_xxxx_placeholder_not_flagged(self):
        f = audit_text("        api_key: xxxxxxxxxxxxxxxx\n", GH)
        self.assertEqual([x for x in f if x.line and x.rule_id == "CICD-SEC-06"], [])

    def test_secrets_expr_in_assignment_not_hardcoded(self):
        f = audit_text("        API_KEY: ${{ secrets.API_KEY }}\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-06" and x.severity == "critical"], [])

    def test_inline_secret_interpolation_medium(self):
        f = audit_text("      - run: echo ${{ secrets.TOKEN }}\n", GH)
        m = [x for x in f if x.rule_id == "CICD-SEC-06" and x.severity == "medium"]
        self.assertTrue(m)

    def test_inline_secret_owasp(self):
        f = audit_text("      - run: deploy --key ${{ secrets.K }}\n", GH)
        m = [x for x in f if x.severity == "medium" and x.rule_id == "CICD-SEC-06"]
        self.assertIn("CICD-SEC-06", m[0].owasp)


class TestPermissions(unittest.TestCase):
    def test_missing_permissions_flagged(self):
        text = "on:\n  push:\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
        f = audit_text(text, GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-05"])

    def test_permissions_present_not_flagged(self):
        text = "on:\n  push:\npermissions:\n  contents: read\njobs: {}\n"
        f = audit_text(text, GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-05"], [])

    def test_gitlab_not_flagged_for_permissions(self):
        text = "stages:\n  - build\n"
        f = audit_text(text, GITLAB)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-05"], [])

    def test_no_trigger_no_permissions_finding(self):
        # A file with no `on:` trigger shouldn't raise the PBAC finding.
        text = "jobs:\n  x:\n    steps: []\n"
        f = audit_text(text, GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-05"], [])


class TestPullRequestTarget(unittest.TestCase):
    def test_prt_flagged(self):
        text = "on:\n  pull_request_target:\npermissions:\n  contents: read\n"
        f = audit_text(text, GH)
        self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-01"])

    def test_prt_high(self):
        text = "on:\n  pull_request_target:\npermissions: {}\n"
        f = audit_text(text, GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-01"][0].severity, "high")

    def test_plain_pull_request_not_flagged(self):
        text = "on:\n  pull_request:\npermissions:\n  contents: read\n"
        f = audit_text(text, GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-01"], [])


class TestCommentHandling(unittest.TestCase):
    def test_commented_uses_ignored(self):
        f = audit_text("    # - uses: a/b@v1\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-04"], [])

    def test_sha_pin_with_trailing_comment(self):
        sha = "8f152de45cc393bb48ce5d89d36b731f54556e65"
        f = audit_text(f"    - uses: actions/checkout@{sha}  # v4.1.1\n", GH)
        self.assertEqual([x for x in f if x.rule_id == "CICD-SEC-04"], [])

    def test_hash_in_quotes_not_a_comment(self):
        # A '#' inside a quoted string isn't a comment boundary.
        f = audit_text('      - run: echo "value#1"\n', GH)
        # nothing should crash; no spurious findings
        self.assertIsInstance(f, list)


class TestSummarizeAndSorting(unittest.TestCase):
    def _mixed(self):
        return [
            Finding("R1", "t", "low", "f", 1, "e", "r", "o"),
            Finding("R2", "t", "critical", "f", 2, "e", "r", "o"),
            Finding("R3", "t", "high", "f", 3, "e", "r", "o"),
        ]

    def test_summary_totals(self):
        s = summarize(self._mixed())
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["by_severity"]["critical"], 1)

    def test_summary_failed_counts_crit_high(self):
        s = summarize(self._mixed())
        self.assertEqual(s["failed"], 2)

    def test_by_rule_counts(self):
        s = summarize(self._mixed())
        self.assertEqual(set(s["by_rule"]), {"R1", "R2", "R3"})

    def test_severity_order_constants(self):
        self.assertLess(SEVERITY_ORDER["critical"], SEVERITY_ORDER["high"])
        self.assertLess(SEVERITY_ORDER["high"], SEVERITY_ORDER["medium"])

    def test_finding_to_dict_roundtrip(self):
        d = self._mixed()[0].to_dict()
        for k in ("rule_id", "title", "severity", "file", "line", "evidence", "remediation", "owasp"):
            self.assertIn(k, d)


class TestDiscovery(unittest.TestCase):
    def test_gh_workflow_recognized(self):
        self.assertTrue(_is_pipeline_file(".github/workflows/ci.yml"))

    def test_gitlab_recognized(self):
        self.assertTrue(_is_pipeline_file(".gitlab-ci.yml"))

    def test_random_yaml_not_recognized(self):
        self.assertFalse(_is_pipeline_file("config/app.yml"))

    def test_non_yaml_in_workflows_ignored(self):
        self.assertFalse(_is_pipeline_file(".github/workflows/readme.md"))

    def test_discover_walks_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, ".github", "workflows")
            os.makedirs(d)
            open(os.path.join(d, "a.yml"), "w").close()
            open(os.path.join(d, "b.yaml"), "w").close()
            open(os.path.join(tmp, "ignore.yml"), "w").close()
            found = discover_pipeline_files(tmp)
            self.assertEqual(len(found), 2)


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.findings = audit_text(
            "on:\n  pull_request_target:\n    - uses: a/b@main\n", GH)
        self.sarif = to_sarif(self.findings)

    def test_sarif_schema_version(self):
        self.assertEqual(self.sarif["version"], "2.1.0")

    def test_sarif_has_runs(self):
        self.assertEqual(len(self.sarif["runs"]), 1)

    def test_sarif_tool_name(self):
        self.assertEqual(self.sarif["runs"][0]["tool"]["driver"]["name"], TOOL_NAME)

    def test_sarif_results_count(self):
        self.assertEqual(len(self.sarif["runs"][0]["results"]), len(self.findings))

    def test_sarif_levels_valid(self):
        levels = {r["level"] for r in self.sarif["runs"][0]["results"]}
        self.assertTrue(levels.issubset({"error", "warning", "note"}))

    def test_sarif_rules_deduped(self):
        rules = self.sarif["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_sarif_is_json_serializable(self):
        json.dumps(self.sarif)  # must not raise

    def test_sarif_locations_have_line(self):
        for r in self.sarif["runs"][0]["results"]:
            line = r["locations"][0]["physicalLocation"]["region"]["startLine"]
            self.assertGreaterEqual(line, 1)


class TestComponents(unittest.TestCase):
    def test_extract_action(self):
        c = extract_components("    - uses: actions/checkout@v4\n", GH)
        self.assertTrue(any(x.kind == "action" and x.name == "actions/checkout" for x in c))

    def test_extract_image(self):
        c = extract_components("    image: log4j-core:2.14.1\n", GH)
        img = [x for x in c if x.kind == "image"]
        self.assertEqual(img[0].name, "log4j-core")
        self.assertEqual(img[0].version, "2.14.1")

    def test_extract_pip_pin(self):
        c = extract_components("      - run: pip install requests==2.5.0\n", GH)
        pip = [x for x in c if x.kind == "pip"]
        self.assertEqual(pip[0].name, "requests")
        self.assertEqual(pip[0].version, "2.5.0")

    def test_extract_cve_ref(self):
        c = extract_components("      - run: echo CVE-2021-44228\n", GH)
        self.assertTrue(any(x.kind == "cve-ref" and x.name == "CVE-2021-44228" for x in c))

    def test_ghsa_ref(self):
        c = extract_components("# GHSA-jfh8-c2jp-5v3q\n", GH)
        self.assertTrue(any(x.kind == "cve-ref" for x in c))

    def test_component_dedup(self):
        text = "    - uses: a/b@v1\n    - uses: a/b@v1\n"
        c = extract_components(text, GH)
        self.assertEqual(len([x for x in c if x.kind == "action"]), 1)

    def test_component_to_dict(self):
        c = extract_components("    image: redis:7\n", GH)[0]
        self.assertIn("kind", c.to_dict())


class TestCLI(unittest.TestCase):
    def _repo(self, tmp, text, name="ci.yml"):
        d = os.path.join(tmp, ".github", "workflows")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(text)
        return tmp

    RISKY = "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n      - uses: a/b@main\n"
    CLEAN = ("on:\n  push:\npermissions:\n  contents: read\njobs:\n  b:\n"
             "    steps:\n      - uses: a/b@8f152de45cc393bb48ce5d89d36b731f54556e65\n")

    def test_audit_json_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.RISKY)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", r, "--format", "json"])
            self.assertEqual(rc, 1)
            self.assertEqual(json.loads(buf.getvalue())["tool"], TOOL_NAME)

    def test_audit_sarif_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.RISKY)
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["audit", r, "--format", "sarif", "--fail-on", "never"])
            doc = json.loads(buf.getvalue())
            self.assertEqual(doc["version"], "2.1.0")

    def test_clean_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.CLEAN)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", r])
            self.assertEqual(rc, 0)

    def test_fail_on_never(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.RISKY)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", r, "--fail-on", "never"])
            self.assertEqual(rc, 0)

    def test_fail_on_critical_only(self):
        # RISKY has a critical (main ref) -> fails at critical threshold.
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.RISKY)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", r, "--fail-on", "critical"])
            self.assertEqual(rc, 1)

    def test_missing_path_exits_two(self):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = main(["audit", os.path.join("no", "such", "xyz")])
        self.assertEqual(rc, 2)

    def test_table_output_renders(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.RISKY)
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["audit", r, "--fail-on", "never"])
            self.assertIn("CI/CD supply-chain audit", buf.getvalue())

    def test_parser_requires_subcommand(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args([])

    def test_scan_helper_returns_dicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.RISKY)
            out = scan(r)
            self.assertTrue(out and isinstance(out[0], dict))


class TestAuditPaths(unittest.TestCase):
    def test_audit_single_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, ".gitlab-ci.yml")
            with open(p, "w") as fh:
                fh.write("deploy:\n  script:\n    - curl https://x/i.sh | bash\n")
            f = audit_paths([p])
            self.assertTrue([x for x in f if x.rule_id == "CICD-SEC-07"])

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            audit_paths([os.path.join("nope", "x")])

    def test_results_sorted_by_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, ".github", "workflows")
            os.makedirs(d)
            with open(os.path.join(d, "ci.yml"), "w") as fh:
                fh.write("on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n"
                         "      - uses: a/b@main\n")
            f = audit_paths([tmp])
            ranks = [SEVERITY_ORDER[x.severity] for x in f]
            self.assertEqual(ranks, sorted(ranks))


if __name__ == "__main__":
    unittest.main()
