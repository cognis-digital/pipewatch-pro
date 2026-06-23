"""Offline OSV enrichment tests — proves REAL lookups against the bundled DB.

All assertions run fully offline against pipewatch_pro/cognis_vulndb.jsonl.gz
(262k real OSV records). No network.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipewatch_pro.vulndb_local import VulnDB, severity_band, count
from pipewatch_pro.core import extract_components
from pipewatch_pro.cli import enrich_components, main

GH = os.path.join(".github", "workflows", "ci.yml")


class TestVulnDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = VulnDB()

    def test_corpus_is_large(self):
        self.assertGreaterEqual(self.db.count(), 200000)

    def test_module_count_helper(self):
        self.assertGreaterEqual(count(), 200000)

    def test_record_schema(self):
        r = next(iter(self.db))
        for k in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
            self.assertIn(k, r)

    def test_log4shell_resolves_by_cve(self):
        hits = self.db.by_cve("CVE-2021-44228")
        self.assertTrue(hits, "Log4Shell CVE must resolve")
        self.assertIn("GHSA-jfh8-c2jp-5v3q", [h["id"] for h in hits])

    def test_log4shell_case_insensitive(self):
        self.assertEqual(self.db.by_cve("cve-2021-44228"), self.db.by_cve("CVE-2021-44228"))

    def test_log4shell_record_is_maven(self):
        rec = self.db.by_cve("CVE-2021-44228")[0]
        self.assertEqual(rec["ecosystem"], "Maven")

    def test_log4shell_lists_log4j_core(self):
        rec = self.db.by_cve("CVE-2021-44228")[0]
        self.assertTrue(any("log4j-core" in p for p in rec["packages"]))

    def test_lodash_has_vulns(self):
        self.assertTrue(self.db.by_package("lodash"))

    def test_package_suffix_match_for_log4j(self):
        # bare artifact id resolves the Maven group:artifact form
        self.assertTrue(self.db.package_match("log4j-core"))

    def test_cve_aliases_helper(self):
        rec = self.db.by_cve("CVE-2021-44228")[0]
        aliases = self.db.cve_aliases(rec)
        self.assertIn("CVE-2021-44228", aliases)
        self.assertIn("GHSA-jfh8-c2jp-5v3q", aliases)

    def test_search_substring(self):
        hits = self.db.search("log4j", limit=5)
        self.assertTrue(hits)
        self.assertLessEqual(len(hits), 5)

    def test_unknown_cve_returns_empty(self):
        self.assertEqual(self.db.by_cve("CVE-0000-00000"), [])

    def test_unknown_package_returns_empty(self):
        self.assertEqual(self.db.package_match("definitely-not-a-real-pkg-xyz-123"), [])

    def test_index_is_cached(self):
        a = self.db.by_cve("CVE-2021-44228")
        b = self.db.by_cve("CVE-2021-44228")
        self.assertEqual(a, b)


class TestSeverityBand(unittest.TestCase):
    def test_critical_vector(self):
        self.assertEqual(
            severity_band("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), "critical")

    def test_empty_vector_unknown(self):
        self.assertEqual(severity_band(""), "unknown")

    def test_local_high_impact_medium(self):
        self.assertEqual(severity_band("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/C:H/I:N/A:N"), "medium")

    def test_low_impact_low(self):
        self.assertEqual(severity_band("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/C:L/I:N/A:N"), "low")

    def test_log4shell_band_is_critical(self):
        db = VulnDB()
        rec = db.by_cve("CVE-2021-44228")[0]
        self.assertEqual(severity_band(rec["severity"]), "critical")


class TestEnrichEngine(unittest.TestCase):
    def test_image_component_matches_log4shell(self):
        comps = extract_components("    image: log4j-core:2.14.1\n", GH)
        matches = enrich_components(comps)
        cves = {a for m in matches for a in m["aliases"]}
        self.assertIn("CVE-2021-44228", cves)

    def test_cve_ref_resolves(self):
        comps = extract_components("# CVE-2021-44228\n", GH)
        matches = enrich_components(comps)
        self.assertTrue(any(m["vuln_id"] == "GHSA-jfh8-c2jp-5v3q" for m in matches))

    def test_pip_pin_lodash_none_but_no_crash(self):
        comps = extract_components("      - run: pip install nonexistpkgxyz==1.0\n", GH)
        self.assertEqual(enrich_components(comps), [])

    def test_npm_lodash_matches(self):
        comps = extract_components("      - run: npm install lodash@4.17.4\n", GH)
        matches = enrich_components(comps)
        self.assertTrue(matches)

    def test_match_record_fields(self):
        comps = extract_components("# CVE-2021-44228\n", GH)
        m = enrich_components(comps)[0]
        for k in ("component", "version", "kind", "file", "line",
                  "vuln_id", "aliases", "ecosystem", "summary", "severity"):
            self.assertIn(k, m)

    def test_limit_per_component(self):
        comps = extract_components("    image: log4j-core:2.0\n", GH)
        m = enrich_components(comps, limit_per_component=3)
        self.assertLessEqual(len(m), 3)


class TestEnrichCLI(unittest.TestCase):
    def _repo(self, tmp, text):
        d = os.path.join(tmp, ".github", "workflows")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "ci.yml"), "w", encoding="utf-8") as fh:
            fh.write(text)
        return tmp

    WF = ("on:\n  push:\npermissions:\n  contents: read\njobs:\n  b:\n"
          "    container:\n      image: log4j-core:2.14.1\n    steps:\n"
          "      - run: echo CVE-2021-44228\n")

    def test_enrich_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.WF)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["enrich", r, "--format", "json"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertGreater(payload["matches"], 0)
            cves = {a for res in payload["results"] for a in res["aliases"]}
            self.assertIn("CVE-2021-44228", cves)

    def test_enrich_fail_on_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.WF)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["enrich", r, "--fail-on-match"])
            self.assertEqual(rc, 1)

    def test_enrich_table_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, self.WF)
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["enrich", r])
            self.assertIn("offline OSV enrichment", buf.getvalue())

    def test_enrich_missing_path(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["enrich", os.path.join("no", "such", "dir")])
        self.assertEqual(rc, 2)

    def test_enrich_clean_repo_no_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._repo(tmp, "on:\n  push:\npermissions:\n  contents: read\n"
                                "jobs:\n  b:\n    steps:\n      - run: make build\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["enrich", r])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
