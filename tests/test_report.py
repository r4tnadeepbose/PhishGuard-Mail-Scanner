import unittest
from pathlib import Path

from phishguard.report import results_batch_to_html
from phishguard.scanner import scan_email_file


SAMPLES = Path(__file__).resolve().parents[1] / "samples"


class ReportTests(unittest.TestCase):
    def test_batch_html_contains_index_and_details(self):
        results = [
            scan_email_file(str(SAMPLES / "legitimate_example.eml")).to_dict(),
            scan_email_file(str(SAMPLES / "phishing_with_auth_fail.eml")).to_dict(),
        ]
        html = results_batch_to_html(results)
        self.assertIn("<html", html.lower())
        self.assertIn("Scan Index", html)
        self.assertIn("Recommended Actions", html)
        self.assertIn("legitimate_example.eml", html)
        self.assertIn("phishing_with_auth_fail.eml", html)
        self.assertIn("Files: 2", html)

    def test_batch_html_handles_error_rows(self):
        html = results_batch_to_html([{"source": "broken.eml", "error": "parse failure"}])
        self.assertIn("broken.eml", html)
        self.assertIn("ERROR", html)
        self.assertIn("parse failure", html)

    def test_single_html_uses_stored_recommendations(self):
        import html as html_mod
        from phishguard.report import result_to_html
        r = scan_email_file(str(SAMPLES / "phishing_with_auth_fail.eml"))
        page = result_to_html(r)
        self.assertIn("Recommended Actions", page)
        self.assertIn(html_mod.escape(r.recommendations[0]), page)


if __name__ == "__main__":
    unittest.main()
