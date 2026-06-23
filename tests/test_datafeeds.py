"""Offline tests for the edge/air-gap data-feed manager (no network calls)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipewatch_pro import datafeeds


class TestCatalog(unittest.TestCase):
    def setUp(self):
        self.cat = datafeeds.load_catalog()

    def test_catalog_loads(self):
        self.assertIn("feeds", self.cat)
        self.assertGreaterEqual(len(self.cat["feeds"]), 20)

    def test_known_vuln_feeds_present(self):
        ids = {f["id"] for f in self.cat["feeds"]}
        for want in ("cisa-kev", "epss", "osv", "nvd-cve"):
            self.assertIn(want, ids)

    def test_feeds_have_required_fields(self):
        for f in self.cat["feeds"]:
            self.assertIn("id", f)
            self.assertIn("url", f)
            self.assertTrue(f["url"].startswith("http"))

    def test_filter_by_domain(self):
        vuln = datafeeds.list_feeds(domain="vuln", catalog=self.cat)
        self.assertTrue(vuln)
        self.assertTrue(all(f["domain"] == "vuln" for f in vuln))

    def test_list_all(self):
        self.assertEqual(len(datafeeds.list_feeds(catalog=self.cat)),
                         len(self.cat["feeds"]))


class TestOfflineBehaviour(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["COGNIS_FEEDS_CACHE"] = self.tmp

    def tearDown(self):
        os.environ.pop("COGNIS_FEEDS_CACHE", None)

    def test_offline_with_no_cache_raises(self):
        with self.assertRaises(FileNotFoundError):
            datafeeds.get("cisa-kev", offline=True)

    def test_cache_dir_created(self):
        d = datafeeds.cache_dir()
        self.assertTrue(d.exists())

    def test_unknown_feed_age_is_none(self):
        self.assertIsNone(datafeeds.cached_age_hours("does-not-exist"))

    def test_snapshot_export_import_roundtrip(self):
        # Seed a fake cached feed, export, wipe, re-import — fully offline.
        d = datafeeds.cache_dir()
        (d / "demo.data").write_bytes(b'{"ok": true}')
        (d / "demo.meta.json").write_text('{"feed":"demo","fetched_at":0}')
        archive = os.path.join(self.tmp, "snap.tar.gz")
        n = datafeeds.snapshot_export(archive)
        self.assertEqual(n, 1)
        (d / "demo.data").unlink()
        imported = datafeeds.snapshot_import(archive)
        self.assertEqual(imported, 1)
        self.assertTrue((d / "demo.data").exists())


if __name__ == "__main__":
    unittest.main()
