import json
import tempfile
import unittest
from pathlib import Path

from phishguard.scanner import scan_email, scan_email_file


SAMPLES = Path(__file__).resolve().parents[1] / "samples"


class TestPhishGuardScanner(unittest.TestCase):
    def test_legitimate_sample_low_risk(self):
        r = scan_email_file(str(SAMPLES / "legitimate_example.eml"))
        self.assertEqual(r.verdict, "Low Risk")
        self.assertLess(r.score, 20)
        self.assertIn("spf", r.to_dict().get("auth_analysis", {}))

    def test_phishing_sample_detected(self):
        r = scan_email_file(str(SAMPLES / "phishing_example.eml"))
        self.assertIn(r.verdict, ("Suspicious", "High Risk", "Critical"))
        self.assertGreaterEqual(r.score, 20)
        titles = " ".join(f.title for f in r.findings).lower()
        self.assertTrue(any(x in titles for x in ["url", "reply-to", "credential", "urgency", "impersonation", "suspicious"]))

    def test_auth_fail_sample_has_auth_caveat(self):
        r = scan_email_file(str(SAMPLES / "phishing_with_auth_fail.eml"))
        titles = [f.title for f in r.findings]
        self.assertTrue(any("unverified claims" in t.lower() for t in titles))
        self.assertTrue(any("spf" in t.lower() or "dmarc" in t.lower() or "dkim" in t.lower() for t in titles))
        self.assertGreaterEqual(r.score, 20)

    def test_spoofed_auth_header_is_parsed_but_not_trusted_as_verified(self):
        eml = (
            "From: attacker@example.com\n"
            "To: victim@example.com\n"
            "Subject: test\n"
            "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\n\n"
            "Hello"
        )
        r = scan_email(eml)
        self.assertEqual(r.auth_analysis.get("spf"), "pass")
        self.assertTrue(any("unverified claims" in f.title.lower() for f in r.findings))

    def test_missing_auth_headers(self):
        r = scan_email("From: a@b.com\nTo: c@d.com\nSubject: hi\n\nJust a note")
        self.assertEqual(r.auth_analysis.get("spf"), "unknown")
        self.assertLess(r.score, 20)

    def test_malformed_input_does_not_crash(self):
        r = scan_email("From: \x00\x01\nSubject: bad\n\nhttp://")
        self.assertIsNotNone(r.verdict)

    def test_empty_email(self):
        r = scan_email("")
        self.assertEqual(r.verdict, "Low Risk")

    def test_batch_mixed_files(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "good.eml").write_text((SAMPLES / "legitimate_example.eml").read_text(encoding="utf-8"), encoding="utf-8")
            (td / "bad.eml").write_text((SAMPLES / "phishing_with_auth_fail.eml").read_text(encoding="utf-8"), encoding="utf-8")
            (td / "broken.eml").write_text("\x00\x00not really an email", encoding="utf-8", errors="ignore")
            results = []
            for p in td.iterdir():
                try:
                    results.append(scan_email_file(str(p)).to_dict())
                except Exception as e:
                    results.append({"source": str(p), "error": str(e)})
            self.assertEqual(len(results), 3)
            self.assertTrue(any(r.get("verdict") == "Low Risk" for r in results if "verdict" in r))
            self.assertTrue(any(r.get("score", 0) >= 20 for r in results if "verdict" in r))

    def test_json_report_schema_core_fields(self):
        r = scan_email_file(str(SAMPLES / "phishing_with_auth_fail.eml"))
        d = r.to_dict()
        for key in ["verdict", "score", "summary", "urls", "findings", "metadata", "auth_analysis", "observables", "security_assessment"]:
            self.assertIn(key, d)
        self.assertIsInstance(d["findings"], list)


    def test_linkedin_job_alert_show_original_legit(self):
        r = scan_email_file(str(SAMPLES / "linkedin_job_alert_show_original.eml"), use_default_whitelist=True)
        self.assertEqual(r.verdict, "Low Risk")
        self.assertLess(r.score, 20)
        self.assertEqual(r.auth_analysis.get("spf"), "pass")
        self.assertEqual(r.auth_analysis.get("dkim"), "pass")
        self.assertEqual(r.auth_analysis.get("dmarc"), "pass")
        titles = " ".join(f.title for f in r.findings).lower()
        self.assertNotIn("credential or sensitive-info request", titles)
        obs = r.observables or {}
        wl = obs.get("whitelisted", {}) or {}
        self.assertGreaterEqual(len(wl.get("urls", [])) + len(obs.get("urls", [])), 1)
        self.assertIn("linkedin.com", " ".join(obs.get("domains", []) + wl.get("domains", [])))

    def test_recommendations_present_and_serialized(self):
        r = scan_email_file(str(SAMPLES / "phishing_with_auth_fail.eml"))
        self.assertGreater(len(r.recommendations), 0)
        d = r.to_dict()
        self.assertEqual(d["recommendations"], r.recommendations)
        joined = " ".join(r.recommendations).lower()
        self.assertTrue(any(k in joined for k in ("report", "do not click", "caution", "verify")))

    def test_category_scores_match_finding_totals(self):
        for name in ("phishing_with_auth_fail.eml", "phishing_example.eml", "legitimate_example.eml"):
            r = scan_email_file(str(SAMPLES / name))
            self.assertEqual(
                sum(r.category_scores.values()),
                sum(f.score for f in r.findings),
                f"category total mismatch for {name}",
            )

    def test_ml_toggle_disables_signal(self):
        raw = (SAMPLES / "phishing_with_auth_fail.eml").read_text(encoding="utf-8", errors="replace")
        on = scan_email(raw, enable_ml=True)
        off = scan_email(raw, enable_ml=False)
        self.assertNotEqual(on.ml_analysis.get("label"), "disabled")
        self.assertEqual(off.ml_analysis.get("label"), "disabled")
        self.assertFalse(off.metadata.get("ml_enabled"))
        self.assertTrue(on.metadata.get("ml_enabled"))

    def test_whitelist_metadata_recorded(self):
        r = scan_email_file(str(SAMPLES / "legitimate_example.eml"), use_default_whitelist=True)
        self.assertTrue(r.metadata.get("whitelist_applied"))
        self.assertTrue(r.metadata.get("whitelist_path", "").endswith("whitelist.json"))



if __name__ == "__main__":
    unittest.main()
