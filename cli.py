import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from phishguard.scanner import scan_email, scan_email_file
from phishguard.report import (
    result_to_json,
    result_to_html,
    results_batch_to_json,
    results_batch_to_html,
    write_text,
)
from phishguard.whitelist import validate_whitelist
from phishguard.investigation import scan_result_to_investigation
from phishguard.integrations.registry import DEFAULT_REGISTRY
from phishguard.integrations.base import IntegrationStatus
from phishguard.threat_framework import calculate_cvss_v31_base


def print_result(result):
    print(f"\nVerdict: {result.verdict} (Score: {result.score}/100)")
    print(result.summary)
    meta = result.metadata or {}
    if meta.get("subject") or meta.get("from"):
        print("\nMessage:")
        if meta.get("subject"): print(f"  Subject: {meta['subject']}")
        if meta.get("from"): print(f"  From: {meta['from']}")
        if meta.get("reply_to"): print(f"  Reply-To: {meta['reply_to']}")
        if meta.get("return_path"): print(f"  Return-Path: {meta['return_path']}")
        print(f"  Received hops: {meta.get('received_count', 0)} | Attachments: {meta.get('attachment_count', 0)} | URLs: {meta.get('url_count', 0)}")
    auth = result.auth_analysis or {}
    if any(auth.get(k) not in (None, "unknown", "") for k in ("spf", "dkim", "dmarc")) or auth.get("sources"):
        print(f"Auth (header claims, unverified): SPF={auth.get('spf','unknown')} DKIM={auth.get('dkim','unknown')} DMARC={auth.get('dmarc','unknown')}")
    ml = getattr(result, "ml_analysis", None) or {}
    if ml and ml.get("label") not in (None, "disabled"):
        p = int(round(float(ml.get("phishing_probability", 0)) * 100))
        print(f"ML: {ml.get('label','unknown')} ({p}% phishing likelihood, confidence {int(round(float(ml.get('confidence',0))*100))}%) model={ml.get('model','')}")
        if ml.get("top_indicators"):
            print(f"  ML indicators: {', '.join(ml.get('top_indicators', [])[:8])}")
    elif ml.get("label") == "disabled":
        print("ML: disabled for this scan")
    cats = getattr(result, "category_scores", None) or {}
    if cats:
        parts = [f"{k.replace('_',' ')}={v}" for k, v in cats.items() if v]
        if parts:
            print(f"Category risk points: {', '.join(parts)}")
    obs = getattr(result, "observables", None) or {}
    if obs:
        wl = obs.get("whitelisted", {}) or {}
        counts = {k: len(obs.get(k, [])) for k in ("urls","emails","ips","domains")}
        wl_counts = {k: len(wl.get(k, [])) for k in ("urls","emails","ips","domains")}
        if sum(counts.values()) or sum(wl_counts.values()):
            print(f"Observables (non-whitelisted): urls={counts['urls']} emails={counts['emails']} ips={counts['ips']} domains={counts['domains']}")
            if sum(wl_counts.values()):
                print(f"Whitelisted observables: urls={wl_counts['urls']} emails={wl_counts['emails']} ips={wl_counts['ips']} domains={wl_counts['domains']}")
    if result.urls:
        print("\nURLs found:")
        for u in result.urls:
            print(f"  - {u}")
    recs = getattr(result, "recommendations", None) or []
    if recs:
        print("\nRecommended actions:")
        for r in recs:
            print(f"  - {r}")
    sec = getattr(result, "security_assessment", None) or {}
    if sec:
        cvss = sec.get("cvss_estimate", {}) or {}
        mitre = sec.get("mitre_attack", []) or []
        cwes = sec.get("cwe", []) or []
        if cvss:
            print(f"\nSecurity assessment: CVSS triage {cvss.get('base_score', '-')} ({cvss.get('severity','Unknown')})  {cvss.get('vector','')}")
        if mitre:
            print("  MITRE ATT&CK: " + ", ".join(f"{m.get('id')} {m.get('name')}" for m in mitre))
        if cwes:
            print("  CWE: " + ", ".join(f"{c.get('id')} {c.get('name')}" for c in cwes))
        cves = sec.get("cve_references") or []
        if cves:
            print("  CVE refs: " + ", ".join(str(x) for x in cves))
        else:
            print("  CVE refs: none auto-attributed (email content is not a product/version instance)")
    if result.findings:
        print("\nFindings:")
        for f in result.findings:
            print(f"  - [{f.severity} | +{f.score}] {f.title}: {f.detail}")
    else:
        print("\nFindings: none")
    print()


def scan_path(path: Path, whitelist_path=None, use_default_whitelist=False, enable_ml=True):
    res = scan_email_file(str(path), whitelist_path=whitelist_path, use_default_whitelist=use_default_whitelist, enable_ml=enable_ml)
    res.source = str(path)
    return res


def _scan_path_worker(args):
    path, whitelist_path, use_default_whitelist, enable_ml = args
    try:
        r = scan_email_file(path, whitelist_path=whitelist_path, use_default_whitelist=use_default_whitelist, enable_ml=enable_ml)
        r.source = path
        raw = ""
        try:
            raw = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            raw = ""
        case = scan_result_to_investigation(r, raw_email_text=raw, source=path)
        return {"result": r.to_dict(), "case": case.to_dict()}
    except Exception as e:
        return {"source": path, "error": str(e)}


def _case_for(result, raw: str, source: str):
    return scan_result_to_investigation(result, raw_email_text=raw or "", source=source)


def _export_case(case, path: str) -> bool:
    res = DEFAULT_REGISTRY.export_case(case.to_dict(), path)
    if res.status != IntegrationStatus.SUCCEEDED:
        print(f"Case export failed: {res.summary} {'; '.join(res.errors)}", file=sys.stderr)
        return False
    return True


def _unique_path(directory: Path, stem: str) -> Path:
    candidate = directory / f"{stem}.case.json"
    n = 2
    while candidate.exists():
        candidate = directory / f"{stem}_{n}.case.json"
        n += 1
    return candidate


def main():
    ap = argparse.ArgumentParser(description="PhishGuard Mail Scanner - heuristic phishing email detector")
    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("--file", help="Path to an email/text file (.eml, .txt, .msg text export)")
    g.add_argument("--text", help="Raw email text to scan")
    g.add_argument("--stdin", action="store_true", help="Read email content from stdin")
    g.add_argument("--dir", help="Scan all .eml/.txt files in a directory (batch mode)")
    ap.add_argument("--json", dest="json_out", help="Write JSON report to file (or batch report in --dir mode)")
    ap.add_argument("--html", dest="html_out", help="Write HTML report to file (single file or batch index)")
    ap.add_argument("--case", dest="case_out", help="Write a local investigation case JSON file (single-file mode)")
    ap.add_argument("--case-dir", dest="case_dir", help="Write one investigation case JSON per scanned file (--dir mode)")
    ap.add_argument("--whitelist", help="Path to whitelist JSON (PhishGuard or ThePhish-compatible schema)")
    ap.add_argument("--use-default-whitelist", action="store_true", help="Use ./whitelist.json from project root if present")
    ap.add_argument("--jobs", type=int, default=0, help="Parallel workers for --dir batch scans (0=auto, 1=sequential; uses multiple CPU cores when >1)")
    ap.add_argument("--no-ml", action="store_true", help="Disable the embedded ML signal for this scan")
    ap.add_argument("--quiet", action="store_true", help="Suppress console output except errors")
    ap.add_argument("--cvss-vector", dest="cvss_vector", help="Calculate CVSS v3.1 base score from a vector (e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N') and exit")
    ap.add_argument("--version", action="version", version="PhishGuard Mail Scanner 1.1")
    args = ap.parse_args()

    if args.cvss_vector:
        try:
            cvss = calculate_cvss_v31_base(args.cvss_vector)
        except Exception as e:
            print(f"Invalid CVSS vector: {e}", file=sys.stderr)
            sys.exit(2)
        print(json.dumps(cvss, indent=2))
        sys.exit(0)

    if not any([args.file, args.text, args.stdin, args.dir]):
        ap.error("one of the arguments --file --text --stdin --dir is required (unless using --cvss-vector)")

    if args.whitelist:
        ok, msg = validate_whitelist(args.whitelist)
        if not ok:
            print(msg, file=sys.stderr)
            sys.exit(2)
        if not args.quiet:
            print(msg)

    enable_ml = not args.no_ml
    worst = 0
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"Directory not found: {d}", file=sys.stderr)
            sys.exit(2)
        files = sorted([p for p in d.iterdir() if p.suffix.lower() in (".eml", ".txt", ".mail")])
        if not files:
            print("No .eml/.txt/.mail files found.", file=sys.stderr)
            sys.exit(2)
        batch = []
        cases = []
        jobs = args.jobs
        if jobs == 0:
            jobs = min(8, (os.cpu_count() or 2))
        jobs = max(1, int(jobs))
        if jobs > 1 and len(files) > 1:
            tasks = [(str(p), args.whitelist, args.use_default_whitelist, enable_ml) for p in files]
            results_map = {}
            with ProcessPoolExecutor(max_workers=jobs) as ex:
                futs = {ex.submit(_scan_path_worker, t): t[0] for t in tasks}
                for fut in as_completed(futs):
                    rd = fut.result()
                    results_map[rd.get("source", futs[fut])] = rd
            for p in files:
                rd = results_map.get(str(p), {"source": str(p), "error": "missing result"})
                result_dict = rd.get("result", rd)
                batch.append(result_dict)
                if rd.get("case"):
                    cases.append((p, rd["case"]))
                if "score" in result_dict:
                    worst = max(worst, int(result_dict.get("score", 0) or 0))
                if not args.quiet:
                    print(f"== {p} ==")
                    if result_dict.get("error"):
                        print(f"Error: {result_dict['error']}\n")
                    else:
                        print(f"\nVerdict: {result_dict.get('verdict')} (Score: {result_dict.get('score')}/100)")
                        print(result_dict.get('summary',''))
                        ml = result_dict.get('ml_analysis') or {}
                        if ml and ml.get("label") != "disabled":
                            print(f"ML: {ml.get('label')} ({int(round(float(ml.get('phishing_probability',0))*100))}% phishing likelihood)")
                        print(f"Findings: {len(result_dict.get('findings',[]))} | URLs: {len(result_dict.get('urls',[]))}\n")
        else:
            for p in files:
                try:
                    r = scan_path(p, whitelist_path=args.whitelist, use_default_whitelist=args.use_default_whitelist, enable_ml=enable_ml)
                    batch.append(r.to_dict())
                    raw = ""
                    try:
                        raw = p.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        raw = ""
                    case = _case_for(r, raw, str(p))
                    cases.append((p, case.to_dict()))
                    worst = max(worst, r.score)
                    if not args.quiet:
                        print(f"== {p} ==")
                        print_result(r)
                except Exception as e:
                    batch.append({"source": str(p), "error": str(e)})
                    if not args.quiet:
                        print(f"== {p} ==\nError: {e}\n")
        if args.json_out:
            write_text(args.json_out, results_batch_to_json(batch))
            if not args.quiet:
                print(f"JSON batch report written: {args.json_out}")
        if args.html_out:
            write_text(args.html_out, results_batch_to_html(batch))
            if not args.quiet:
                print(f"HTML batch report written: {args.html_out}")
        if args.case_dir:
            out_dir = Path(args.case_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            written = 0
            for p, case in cases:
                if _export_case_dict(case, str(_unique_path(out_dir, p.stem))):
                    written += 1
            if not args.quiet:
                print(f"Investigation cases written: {written} -> {out_dir}")
        if args.case_out and not args.quiet:
            print("Note: --case is for single-file scans; use --case-dir for batch cases.", file=sys.stderr)
    else:
        raw = ""
        try:
            if args.file:
                result = scan_path(Path(args.file), whitelist_path=args.whitelist, use_default_whitelist=args.use_default_whitelist, enable_ml=enable_ml)
                try:
                    raw = Path(args.file).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    raw = ""
                source = str(args.file)
            elif args.stdin:
                raw = sys.stdin.read()
                result = scan_email(raw, whitelist_path=args.whitelist, use_default_whitelist=args.use_default_whitelist, enable_ml=enable_ml)
                result.source = "stdin"
                source = "stdin"
            else:
                raw = args.text
                result = scan_email(raw, whitelist_path=args.whitelist, use_default_whitelist=args.use_default_whitelist, enable_ml=enable_ml)
                result.source = "text"
                source = "text"
        except Exception as e:
            print(f"Scan failed: {e}", file=sys.stderr)
            sys.exit(2)
        worst = result.score
        if not args.quiet:
            print_result(result)
        if args.json_out:
            write_text(args.json_out, result_to_json(result))
            if not args.quiet:
                print(f"JSON report written: {args.json_out}")
        if args.html_out:
            write_text(args.html_out, result_to_html(result))
            if not args.quiet:
                print(f"HTML report written: {args.html_out}")
        if args.case_out:
            case = _case_for(result, raw, source)
            if _export_case(case, args.case_out) and not args.quiet:
                print(f"Investigation case written: {args.case_out}")

    sys.exit(1 if worst >= 20 else 0)


def _export_case_dict(case: dict, path: str) -> bool:
    res = DEFAULT_REGISTRY.export_case(case, path)
    if res.status != IntegrationStatus.SUCCEEDED:
        print(f"Case export failed: {res.summary} {'; '.join(res.errors)}", file=sys.stderr)
        return False
    return True


if __name__ == "__main__":
    main()
