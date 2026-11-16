import json
import unittest

from phishguard.scanner import scan_email
from phishguard.investigation import (
    sha256_text,
    normalize_severity,
    normalize_observable_value,
    dedupe_observables,
    Observable,
    scan_result_to_investigation,
    case_to_json,
)
from phishguard.integrations.null_providers import NullExportProvider
from phishguard.integrations.base import IntegrationStatus


class InvestigationTests(unittest.TestCase):
    def test_sha256_and_normalization_helpers(self):
        self.assertEqual(len(sha256_text('abc')), 64)
        self.assertEqual(normalize_severity('High'), 'malicious')
        self.assertEqual(normalize_severity('medium'), 'suspicious')
        self.assertEqual(normalize_severity('LOW'), 'informational')
        self.assertEqual(normalize_severity(None), 'unknown')
        self.assertEqual(normalize_observable_value('domain', 'Example.COM.'), 'example.com')
        self.assertEqual(normalize_observable_value('url', 'https://EXAMPLE.com/path,'), 'https://example.com/path')

    def test_dedupe_observables_merges_tags_and_whitelist(self):
        obs = [
            Observable(obs_type='url', value='https://Example.com', tags=['body']),
            Observable(obs_type='url', value='https://example.com', tags=['header'], whitelisted=True),
        ]
        out = dedupe_observables(obs)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].whitelisted)
        self.assertIn('body', out[0].tags)
        self.assertIn('header', out[0].tags)

    def test_scan_result_to_investigation_case(self):
        raw = "From: test@example.com\nSubject: Hello\n\nVisit https://example.com"
        res = scan_email(raw)
        case = scan_result_to_investigation(res, raw_email_text=raw, source='unit-test')
        d = case.to_dict()
        self.assertTrue(d['case_id'].startswith('case_'))
        self.assertEqual(d['automated_verdict'], res.verdict)
        self.assertEqual(d['risk_score'], res.score)
        self.assertTrue(any(e['kind'] == 'raw_email' and len(e['sha256']) == 64 for e in d['evidence']))
        self.assertTrue(len(d['analyzer_results']) >= 1)
        self.assertEqual(d['analyzer_results'][0]['status'], 'succeeded')
        self.assertTrue(any(ev['event_type'] == 'scan_imported' for ev in d['timeline']))
        # JSON serializable
        parsed = json.loads(case_to_json(case))
        self.assertEqual(parsed['case_id'], d['case_id'])

    def test_null_export_provider_is_safe_default(self):
        p = NullExportProvider()
        self.assertFalse(p.is_configured())
        r = p.run({'case': 'x'})
        self.assertEqual(r.status, IntegrationStatus.SKIPPED)
        self.assertIn('local-only', r.summary.lower())
        self.assertEqual(r.to_dict()['status'], 'skipped')

    def test_local_case_export_provider_writes_json(self):
        import tempfile
        from pathlib import Path
        from phishguard.integrations.local_export import LocalCaseExportProvider

        raw = "From: test@example.com\nSubject: Case export\n\nHello"
        case = scan_result_to_investigation(scan_email(raw), raw_email_text=raw, source='unit-test')
        provider = LocalCaseExportProvider()
        self.assertTrue(provider.is_configured())
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "nested" / "case.json"
            res = provider.run({"case": case.to_dict(), "path": str(target)})
            self.assertEqual(res.status, IntegrationStatus.SUCCEEDED)
            self.assertTrue(target.is_file())
            data = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(data["case_id"], case.case_id)
            missing = provider.run({"case": case.to_dict()})
            self.assertEqual(missing.status, IntegrationStatus.FAILED)

    def test_default_registry_exports_case(self):
        import tempfile
        from pathlib import Path
        from phishguard.integrations.registry import DEFAULT_REGISTRY

        raw = "From: test@example.com\nSubject: Registry\n\nHello"
        case = scan_result_to_investigation(scan_email(raw), raw_email_text=raw, source='unit-test')
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "case.json"
            res = DEFAULT_REGISTRY.export_case(case.to_dict(), str(target))
            self.assertEqual(res.status, IntegrationStatus.SUCCEEDED)
            self.assertTrue(target.is_file())

    def test_case_analyst_verdict_and_notes(self):
        raw = "From: test@example.com\nSubject: Analyst\n\nHello"
        case = scan_result_to_investigation(scan_email(raw), raw_email_text=raw, source='unit-test')
        case.set_analyst_verdict('phishing', note='confirmed by user')
        self.assertEqual(case.analyst_verdict, 'phishing')
        self.assertEqual(case.status, 'closed')
        case.add_note('follow up with sender')
        self.assertEqual(len(case.notes), 1)
        self.assertTrue(any(ev.event_type == 'analyst_verdict' for ev in case.timeline))
        self.assertTrue(any(ev.event_type == 'note_added' for ev in case.timeline))
        with self.assertRaises(ValueError):
            case.add_note('   ')

    def test_case_metadata_carries_recommendations(self):
        raw = "From: test@example.com\nSubject: Recs\n\nVisit http://evil.example/login"
        res = scan_email(raw)
        case = scan_result_to_investigation(res, raw_email_text=raw, source='unit-test')
        self.assertEqual(case.metadata.get('recommendations'), res.recommendations)


if __name__ == '__main__':
    unittest.main()
