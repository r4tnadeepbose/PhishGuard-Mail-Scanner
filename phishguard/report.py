from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Dict, Any

from .scanner import ScanResult, build_recommendations


def result_to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def results_batch_to_json(results: List[Dict[str, Any]]) -> str:
    return json.dumps({"generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z", "count": len(results), "results": results}, indent=2, ensure_ascii=False)


def _recommendations(verdict: str, findings: list, auth: dict) -> list:
    return build_recommendations(verdict, findings, auth)


def result_to_html(result: ScanResult) -> str:
    d = result.to_dict()
    rows = "".join(
        f"<tr><td>{html.escape(str(f.get('severity','')))}</td><td>+{f.get('score',0)}</td><td>{html.escape(str(f.get('title','')))}</td><td>{html.escape(str(f.get('detail','')))}</td></tr>"
        for f in d.get("findings", [])
    ) or '<tr><td colspan="4">No findings</td></tr>'
    urls = "".join(f"<li><code>{html.escape(u)}</code></li>" for u in d.get("urls", [])) or "<li>None</li>"
    meta = d.get("metadata", {})
    auth = d.get("auth_analysis", {})
    obs = d.get("observables", {}) or {}
    wl = (obs.get("whitelisted") or {}) if isinstance(obs, dict) else {}
    ml = d.get("ml_analysis", {}) or {}
    cats = d.get("category_scores", {}) or {}
    recs = d.get("recommendations") or _recommendations(d.get("verdict",""), d.get("findings", []) or [], auth)
    meta_rows = "".join(
        f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in meta.items()
    )
    obs_rows = ""
    if obs:
        obs_rows = f"""
<tr><th>URLs (active)</th><td>{len(obs.get('urls',[]))}</td></tr>
<tr><th>Emails</th><td>{len(obs.get('emails',[]))}</td></tr>
<tr><th>IPs</th><td>{len(obs.get('ips',[]))}</td></tr>
<tr><th>Domains</th><td>{len(obs.get('domains',[]))}</td></tr>
<tr><th>Whitelisted URLs</th><td>{len(wl.get('urls',[]))}</td></tr>
<tr><th>Whitelisted Emails</th><td>{len(wl.get('emails',[]))}</td></tr>
<tr><th>Whitelisted IPs</th><td>{len(wl.get('ips',[]))}</td></tr>
<tr><th>Whitelisted Domains</th><td>{len(wl.get('domains',[]))}</td></tr>
"""
    ml_rows = ""
    if ml:
        ml_rows = f"""
<tr><th>ML label</th><td>{html.escape(str(ml.get('label','unknown')))}</td></tr>
<tr><th>Phishing likelihood</th><td>{int(round(float(ml.get('phishing_probability',0))*100))}%</td></tr>
<tr><th>Legitimate likelihood</th><td>{int(round(float(ml.get('legitimate_probability',0))*100))}%</td></tr>
<tr><th>Confidence</th><td>{int(round(float(ml.get('confidence',0))*100))}%</td></tr>
<tr><th>Top indicators</th><td>{html.escape(', '.join(ml.get('top_indicators',[]) or []) or '-')}</td></tr>
<tr><th>Model</th><td>{html.escape(str(ml.get('model','')))}</td></tr>
"""
    cat_rows = "".join(f"<tr><th>{html.escape(str(k).replace('_',' ').title().replace('Url','URL').replace('Ml','ML'))}</th><td>{int(v)}</td></tr>" for k,v in (cats.items())) if cats else '<tr><td>None</td></tr>'
    sec = d.get("security_assessment", {}) or {}
    cvss = sec.get("cvss_estimate", {}) or {}
    mitre = sec.get("mitre_attack", []) or []
    cwes = sec.get("cwe", []) or []
    mitre_items = "".join(f"<li><a href=\"{html.escape(m.get('url',''))}\">{html.escape(m.get('id',''))}</a> - {html.escape(m.get('name',''))} ({html.escape(m.get('tactic',''))})</li>" for m in mitre) or "<li>None</li>"
    cwe_items = "".join(f"<li><a href=\"{html.escape(c.get('url',''))}\">{html.escape(c.get('id',''))}</a> - {html.escape(c.get('name',''))}</li>" for c in cwes) or "<li>None</li>"
    cve_items = "".join(f"<li>{html.escape(str(x))}</li>" for x in (sec.get("cve_references") or [])) or "<li>None identified from email content (CVEs are product/version-specific).</li>"
    sec_note = " ".join(sec.get("notes") or [])
    rec_items = "".join(f"<li>{html.escape(r)}</li>" for r in recs) or "<li>None</li>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>PhishGuard Scan Report</title>
<style>
:root{{--pg-bg:#EDF2F9;--pg-card:#FFFFFF;--pg-soft:#F8FBFF;--pg-text:#14213D;--pg-muted:#5B6B85;--pg-accent:#123C69;--pg-accent-dark:#0B2A4A;--pg-accent-soft:#DCE8F6;--pg-border:#D6E2F0;--pg-amber:#F3B33D}}
body{{font-family:"Segoe UI","Helvetica Neue",Arial,sans-serif;margin:0;padding:32px;color:var(--pg-text);background:var(--pg-bg);line-height:1.55}}
h1{{font-size:21px;font-weight:600;letter-spacing:-0.01em;margin:0 0 20px 0;padding:16px 20px;background:var(--pg-accent-dark);color:#FFFFFF;border:1px solid var(--pg-accent-dark);border-radius:14px;box-shadow:0 6px 18px rgba(10,35,70,.18)}}
h2{{font-size:15px;font-weight:600;letter-spacing:0;margin:0 0 12px 0;color:var(--pg-text)}}
h3{{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin:14px 0 6px 0;color:var(--pg-muted)}}
.card{{background:var(--pg-card);border:1px solid var(--pg-border);border-radius:14px;padding:18px 20px;margin-bottom:14px;box-shadow:0 6px 18px rgba(80,60,160,.06)}}
.verdict{{font-size:22px;font-weight:600;letter-spacing:-0.01em;color:var(--pg-accent-dark)}}
table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid var(--pg-border);padding:9px 8px;text-align:left;vertical-align:top}}
th{{background:var(--pg-accent-soft);color:var(--pg-accent-dark);font-weight:600;font-size:12px;letter-spacing:.02em}} tr:last-child td{{border-bottom:none}}
a{{color:var(--pg-accent);text-decoration:none}} a:hover{{text-decoration:underline}} code{{white-space:pre-wrap;word-break:break-all;background:var(--pg-soft);padding:2px 6px;border:1px solid var(--pg-border);border-radius:6px;font-size:0.92em}}
ul{{margin:8px 0 0 18px;padding:0}} p{{margin:8px 0;color:var(--pg-muted)}}
.badge{{display:inline-block;padding:5px 11px;border:1px solid var(--pg-border);border-radius:999px;background:var(--pg-accent-soft);color:var(--pg-accent-dark);font-weight:600;font-size:12px}}
</style></head><body>
<h1>PhishGuard Mail Scanner Report</h1>
<div class="card"><div class="verdict">Verdict: {html.escape(d.get('verdict',''))} (Score: {d.get('score',0)}/100)</div>
<p>{html.escape(d.get('summary',''))}</p><p><strong>Source:</strong> {html.escape(d.get('source','-') or '-')}</p>
<p><span class="badge">ML: {html.escape(str(ml.get('label','unknown')))} | {int(round(float(ml.get('phishing_probability',0))*100))}% phishing likelihood</span></p></div>
<div class="card"><h2>Recommended Actions</h2><ul>{rec_items}</ul></div>
<div class="card"><h2>ML / Statistical Analysis</h2><table>{ml_rows or '<tr><td>Not available</td></tr>'}</table></div>
<div class="card"><h2>Risk Category Breakdown (heuristic points)</h2><table>{cat_rows}</table></div>
<div class="card"><h2>Metadata</h2><table>{meta_rows}</table></div>
<div class="card"><h2>Authentication Analysis (header claims, unverified)</h2><table>
<tr><th>SPF</th><td>{html.escape(str(auth.get('spf','unknown')))}</td></tr>
<tr><th>DKIM</th><td>{html.escape(str(auth.get('dkim','unknown')))}</td></tr>
<tr><th>DMARC</th><td>{html.escape(str(auth.get('dmarc','unknown')))}</td></tr>
</table></div>
<div class="card"><h2>Security Assessment (MITRE / CWE / CVSS)</h2>
<table>
<tr><th>CVSS triage estimate</th><td>{html.escape(str(cvss.get('base_score','-')))} ({html.escape(str(cvss.get('severity','Unknown')))})</td></tr>
<tr><th>Vector</th><td><code>{html.escape(str(cvss.get('vector','-')))}</code></td></tr>
<tr><th>Note</th><td>{html.escape(str(cvss.get('note', sec_note or 'Evidence-linked heuristic mapping.')))}</td></tr>
</table>
<h3>MITRE ATT&amp;CK</h3><ul>{mitre_items}</ul>
<h3>CWE</h3><ul>{cwe_items}</ul>
<h3>CVE references</h3><ul>{cve_items}</ul></div>
<div class="card"><h2>Observables</h2><table>{obs_rows or '<tr><td>None</td></tr>'}</table></div>
<div class="card"><h2>URLs</h2><ul>{urls}</ul></div>
<div class="card"><h2>Findings</h2><table><tr><th>Severity</th><th>Score</th><th>Title</th><th>Detail</th></tr>{rows}</table></div>
</body></html>"""


def results_batch_to_html(results: List[Dict[str, Any]], title: str = "PhishGuard Batch Scan Report") -> str:
    """Render a self-contained HTML batch report with a scan index and per-result details."""
    results = results or []
    counts: Dict[str, int] = {}
    for r in results:
        key = str(r.get("verdict") or ("ERROR" if r.get("error") else "Unknown"))
        counts[key] = counts.get(key, 0) + 1
    count_badges = "".join(
        f'<span class="badge">{html.escape(k)}: {v}</span> ' for k, v in sorted(counts.items())
    ) or '<span class="badge">No results</span>'

    index_rows = []
    detail_blocks = []
    for idx, r in enumerate(results, start=1):
        src = str(r.get("source") or "(unknown)")
        name = Path(src).name or src
        if r.get("error"):
            index_rows.append(
                f"<tr><td>{idx}</td><td>{html.escape(name)}</td><td>ERROR</td><td>-</td>"
                f"<td>-</td><td>-</td><td colspan=\"3\">{html.escape(str(r.get('error')))}</td></tr>"
            )
            detail_blocks.append(
                f'<div class="card"><h2>{idx}. {html.escape(name)} - ERROR</h2>'
                f'<p>{html.escape(str(r.get("error")))}</p></div>'
            )
            continue
        auth = r.get("auth_analysis", {}) or {}
        findings = r.get("findings", []) or []
        recs = r.get("recommendations") or _recommendations(str(r.get("verdict", "")), findings, auth)
        index_rows.append(
            f"<tr><td>{idx}</td><td>{html.escape(name)}</td><td>{html.escape(str(r.get('verdict','')))}</td>"
            f"<td>{int(r.get('score', 0) or 0)}</td><td>{len(findings)}</td><td>{len(r.get('urls', []) or [])}</td>"
            f"<td>{html.escape(str(auth.get('spf','unknown')))}</td>"
            f"<td>{html.escape(str(auth.get('dkim','unknown')))}</td>"
            f"<td>{html.escape(str(auth.get('dmarc','unknown')))}</td></tr>"
        )
        finding_rows = "".join(
            f"<tr><td>{html.escape(str(f.get('severity','')))}</td><td>+{int(f.get('score', 0) or 0)}</td>"
            f"<td>{html.escape(str(f.get('title','')))}</td><td>{html.escape(str(f.get('detail','')))}</td></tr>"
            for f in findings
        ) or '<tr><td colspan="4">No findings</td></tr>'
        rec_items = "".join(f"<li>{html.escape(str(x))}</li>" for x in recs) or "<li>None</li>"
        detail_blocks.append(
            f'<div class="card"><h2>{idx}. {html.escape(name)} - {html.escape(str(r.get("verdict","")))} ({int(r.get("score", 0) or 0)}/100)</h2>'
            f'<p><strong>Source:</strong> {html.escape(src)}</p>'
            f'<p>{html.escape(str(r.get("summary", "")))}</p>'
            f'<h3>Recommended Actions</h3><ul>{rec_items}</ul>'
            f'<h3>Findings</h3><table><tr><th>Severity</th><th>Score</th><th>Title</th><th>Detail</th></tr>{finding_rows}</table></div>'
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
:root{{--pg-bg:#EDF2F9;--pg-card:#FFFFFF;--pg-soft:#F8FBFF;--pg-text:#14213D;--pg-muted:#5B6B85;--pg-accent:#123C69;--pg-accent-dark:#0B2A4A;--pg-accent-soft:#DCE8F6;--pg-border:#D6E2F0;--pg-amber:#F3B33D}}
body{{font-family:"Segoe UI","Helvetica Neue",Arial,sans-serif;margin:0;padding:32px;color:var(--pg-text);background:var(--pg-bg);line-height:1.55}}
h1{{font-size:21px;font-weight:600;letter-spacing:-0.01em;margin:0 0 20px 0;padding:16px 20px;background:var(--pg-accent-dark);color:#FFFFFF;border:1px solid var(--pg-accent-dark);border-radius:14px;box-shadow:0 6px 18px rgba(10,35,70,.18)}}
h2{{font-size:15px;font-weight:600;letter-spacing:0;margin:0 0 12px 0;color:var(--pg-text)}}
h3{{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin:14px 0 6px 0;color:var(--pg-muted)}}
.card{{background:var(--pg-card);border:1px solid var(--pg-border);border-radius:14px;padding:18px 20px;margin-bottom:14px;box-shadow:0 6px 18px rgba(80,60,160,.06)}}
table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid var(--pg-border);padding:8px;text-align:left;vertical-align:top}}
th{{background:var(--pg-accent-soft);color:var(--pg-accent-dark);font-weight:600;font-size:12px;letter-spacing:.02em}} tr:last-child td{{border-bottom:none}}
code{{white-space:pre-wrap;word-break:break-all;background:var(--pg-soft);padding:2px 6px;border:1px solid var(--pg-border);border-radius:6px;font-size:0.92em}}
ul{{margin:8px 0 0 18px;padding:0}} p{{margin:8px 0;color:var(--pg-muted)}}
.badge{{display:inline-block;margin:0 6px 6px 0;padding:5px 11px;border:1px solid var(--pg-border);border-radius:999px;background:var(--pg-accent-soft);color:var(--pg-accent-dark);font-weight:600;font-size:12px}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="card"><h2>Summary</h2><p>Generated: {html.escape(datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z")} | Files: {len(results)}</p><p>{count_badges}</p></div>
<div class="card"><h2>Scan Index</h2><table><tr><th>#</th><th>File</th><th>Verdict</th><th>Score</th><th>Findings</th><th>URLs</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr>{''.join(index_rows)}</table></div>
{''.join(detail_blocks)}
</body></html>"""


def write_text(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")

