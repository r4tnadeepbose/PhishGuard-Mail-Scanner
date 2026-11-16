import unittest

from phishguard.scanner import scan_email_file
from phishguard.threat_framework import build_security_assessment, calculate_cvss_v31_base, estimate_triage_cvss
from pathlib import Path

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


class SecurityAssessmentTests(unittest.TestCase):
    def test_scan_includes_security_assessment(self):
        r = scan_email_file(str(SAMPLES / "phishing_with_auth_fail.eml"))
        sec = r.to_dict().get("security_assessment", {})
        self.assertIn("cvss_estimate", sec)
        self.assertIn("mitre_attack", sec)
        self.assertIn("cwe", sec)
        self.assertTrue(sec["mitre_attack"], "expected at least one MITRE technique")
        self.assertTrue(sec["cwe"], "expected at least one CWE mapping")
        cvss = sec["cvss_estimate"]
        self.assertIn("base_score", cvss)
        self.assertIn("vector", cvss)
        self.assertIn("severity", cvss)

    def test_cvss_v31_calculator_known_vector(self):
        # Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 Critical
        res = calculate_cvss_v31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertAlmostEqual(res["base_score"], 9.8, places=1)
        self.assertEqual(res["severity"], "Critical")
        low = calculate_cvss_v31_base("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
        self.assertEqual(low["base_score"], 0.0)

    def test_triage_cvss_is_bounded_and_labeled(self):
        est = estimate_triage_cvss(85, "Critical", [{"title": "Credential request"}, {"title": "URL"}])
        self.assertGreaterEqual(est["base_score"], 0.0)
        self.assertLessEqual(est["base_score"], 10.0)
        self.assertEqual(est.get("type"), "triage_estimate")
        self.assertIn("not a confirmed software vulnerability", est.get("note", "").lower())

    def test_build_security_assessment_has_expected_shape(self):
        sec = build_security_assessment(
            verdict="High Risk",
            score=55,
            findings=[{"title": "Possible display-name impersonation", "detail": "x"}, {"title": "Sensitive URL", "detail": "login"}],
            auth={"spf": "fail", "dkim": "unknown", "dmarc": "unknown"},
            category_scores={"header_identity": 10, "authentication": 10, "url": 20},
        )
        ids = [m["id"] for m in sec["mitre_attack"]]
        self.assertIn("T1566", ids)
        self.assertIn("T1566.002", ids)
        cwe_ids = [c["id"] for c in sec["cwe"]]
        self.assertTrue(any(c.startswith("CWE-") for c in cwe_ids))

    def test_input_size_limit_raises(self):
        from phishguard.parser import parse_email_text, MAX_INPUT_CHARS
        with self.assertRaises(ValueError):
            parse_email_text("A" * (MAX_INPUT_CHARS + 1))

    def test_oversized_file_raises(self):
        import tempfile
        from phishguard.parser import parse_email_file, MAX_PARSE_BYTES
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "big.eml"
            # create just over limit efficiently
            with open(p, "wb") as f:
                f.seek(MAX_PARSE_BYTES + 1)
                f.write(b"x")
            with self.assertRaises(ValueError):
                parse_email_file(str(p))


if __name__ == "__main__":
    unittest.main()