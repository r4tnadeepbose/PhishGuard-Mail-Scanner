import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
PY = sys.executable


class TestCLI(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([PY, "cli.py", *args], cwd=str(ROOT), capture_output=True, text=True)

    def test_scan_sample_file(self):
        p = self.run_cli("--file", str(SAMPLES / "phishing_with_auth_fail.eml"))
        self.assertIn("Verdict:", p.stdout)
        self.assertEqual(p.returncode, 1)

    def test_scan_legit_sample_exit_zero(self):
        p = self.run_cli("--file", str(SAMPLES / "legitimate_example.eml"))
        self.assertEqual(p.returncode, 0)
        self.assertIn("Low Risk", p.stdout)

    def test_json_html_report_generation(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            jp = td / "r.json"
            hp = td / "r.html"
            p = self.run_cli("--file", str(SAMPLES / "phishing_with_auth_fail.eml"), "--json", str(jp), "--html", str(hp))
            self.assertTrue(jp.exists(), p.stdout + p.stderr)
            self.assertTrue(hp.exists(), p.stdout + p.stderr)
            data = json.loads(jp.read_text(encoding="utf-8"))
            self.assertIn("verdict", data)
            self.assertIn("<html", hp.read_text(encoding="utf-8").lower())

    def test_batch_scan(self):
        with tempfile.TemporaryDirectory() as td:
            jp = Path(td) / "batch.json"
            p = self.run_cli("--dir", str(SAMPLES), "--json", str(jp))
            self.assertEqual(p.returncode, 1)
            data = json.loads(jp.read_text(encoding="utf-8"))
            expected = len([p for p in SAMPLES.iterdir() if p.suffix.lower() in (".eml", ".txt", ".mail")])
            self.assertEqual(data.get("count"), expected)
            self.assertGreaterEqual(data.get("count", 0), 3)

    def test_single_scan_writes_case(self):
        with tempfile.TemporaryDirectory() as td:
            cp = Path(td) / "case.json"
            p = self.run_cli("--file", str(SAMPLES / "phishing_with_auth_fail.eml"), "--case", str(cp), "--quiet")
            self.assertTrue(cp.exists(), p.stdout + p.stderr)
            data = json.loads(cp.read_text(encoding="utf-8"))
            self.assertTrue(data["case_id"].startswith("case_"))
            self.assertTrue(data["evidence"])
            self.assertTrue(data["metadata"].get("recommendations"))

    def test_batch_case_dir_writes_one_case_per_file(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "cases"
            p = self.run_cli("--dir", str(SAMPLES), "--case-dir", str(out), "--jobs", "1", "--quiet")
            self.assertEqual(p.returncode, 1)
            expected = len([p for p in SAMPLES.iterdir() if p.suffix.lower() in (".eml", ".txt", ".mail")])
            cases = list(out.glob("*.case.json"))
            self.assertEqual(len(cases), expected)

    def test_no_ml_disables_signal(self):
        with tempfile.TemporaryDirectory() as td:
            jp = Path(td) / "r.json"
            self.run_cli("--file", str(SAMPLES / "phishing_with_auth_fail.eml"), "--json", str(jp), "--no-ml", "--quiet")
            data = json.loads(jp.read_text(encoding="utf-8"))
            self.assertEqual(data["ml_analysis"]["label"], "disabled")
            self.assertFalse(data["metadata"]["ml_enabled"])

    def test_invalid_whitelist_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "wl.json"
            bad.write_text("{not json", encoding="utf-8")
            p = self.run_cli("--file", str(SAMPLES / "legitimate_example.eml"), "--whitelist", str(bad), "--quiet")
            self.assertEqual(p.returncode, 2)
            self.assertIn("invalid", (p.stdout + p.stderr).lower())

    def test_batch_html_report_written(self):
        with tempfile.TemporaryDirectory() as td:
            hp = Path(td) / "batch.html"
            self.run_cli("--dir", str(SAMPLES), "--html", str(hp), "--jobs", "1", "--quiet")
            page = hp.read_text(encoding="utf-8")
            self.assertIn("Scan Index", page)
            self.assertIn("Recommended Actions", page)


if __name__ == "__main__":
    unittest.main()
