import json
import tempfile
import unittest
from pathlib import Path

from phishguard.whitelist import (
    WhitelistError,
    add_exact_rule,
    load_whitelist,
    validate_whitelist,
    whitelist_summary,
)


ROOT = Path(__file__).resolve().parents[1]


class WhitelistTests(unittest.TestCase):
    def test_project_whitelist_validates(self):
        ok, msg = validate_whitelist(str(ROOT / "whitelist.json"))
        self.assertTrue(ok, msg)
        self.assertIn("phishguard", msg.lower())

    def test_missing_and_invalid_files_report_errors(self):
        ok, msg = validate_whitelist(str(ROOT / "does-not-exist.json"))
        self.assertFalse(ok)
        self.assertIn("not found", msg.lower())
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            ok, msg = validate_whitelist(str(bad))
            self.assertFalse(ok)
            self.assertIn("invalid", msg.lower())

    def test_add_exact_rule_roundtrip_and_duplicate(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "wl.json"
            self.assertTrue(add_exact_rule(str(path), "domain", "example.org"))
            self.assertFalse(add_exact_rule(str(path), "domain", "EXAMPLE.org"))
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["exact"]["domain"], ["example.org"])
            wl = load_whitelist(str(path))
            self.assertIsNotNone(wl)
            self.assertTrue(wl.is_whitelisted("domain", "example.org"))
            info = whitelist_summary(str(path))
            self.assertEqual(info["exact"], 1)
            self.assertEqual(info["schema"], "phishguard")

    def test_add_exact_rule_preserves_thephish_schema(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "thephish.json"
            path.write_text(json.dumps({
                "exactMatching": {"domain": [], "mail": []},
                "regexMatching": {"domain": [], "mail": []},
                "domainsInURLs": [],
                "domainsInEmails": [],
            }), encoding="utf-8")
            self.assertTrue(add_exact_rule(str(path), "email", "analyst@example.org"))
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("exactMatching", data)
            self.assertEqual(data["exactMatching"]["mail"], ["analyst@example.org"])
            self.assertEqual(whitelist_summary(str(path))["schema"], "thephish")

    def test_add_exact_rule_rejects_bad_input(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "wl.json")
            with self.assertRaises(WhitelistError):
                add_exact_rule(path, "banana", "x")
            with self.assertRaises(WhitelistError):
                add_exact_rule(path, "domain", "   ")
            with self.assertRaises(WhitelistError):
                add_exact_rule(None, "domain", "example.org")


if __name__ == "__main__":
    unittest.main()
