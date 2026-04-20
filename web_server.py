#!/usr/bin/env python3
import concurrent.futures
import html as html_mod
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse

from security_test_runner import (
    analyze_target,
    cross_target_pivot,
    summarize,
    SEVERITY_ORDER,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "scan_results")
os.makedirs(RESULTS_DIR, exist_ok=True)

HOST = os.environ.get("VIBESEC_HOST", "127.0.0.1")
PORT = int(os.environ.get("VIBESEC_PORT", "8765"))

SEV_COLORS = {
    SEVERITY_CRITICAL: "#7a0012",
    SEVERITY_HIGH: "#c0392b",
    SEVERITY_MEDIUM: "#d68910",
    SEVERITY_LOW: "#1f6feb",
    SEVERITY_INFO: "#6c757d",
}

MAX_TARGETS = 25
MAX_TARGET_LEN = 2048
MAX_BODY_BYTES = 200_000


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value[:80] or "target"


def category_slug(value: str) -> str:
    value = (value or "uncategorized").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "uncategorized"


def normalize_severity(value: Any) -> str:
    sev = str(value or SEVERITY_INFO).strip().lower()
    return sev if sev in SEVERITY_ORDER else SEVERITY_INFO


def severity_rank(value: Any) -> int:
    sev = normalize_severity(value)
    return SEVERITY_ORDER.index(sev)


def normalize_finding(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        severity = normalize_severity(item.get("severity"))
        title = item.get("title") or item.get("name") or item.get("issue") or ""
        detail = item.get("detail") or item.get("description") or item.get("message") or ""
        category = item.get("category") or "uncategorized"
        evidence = item.get("evidence")
        recommendation = item.get("recommendation") or item.get("fix")
        return {
            **item,
            "severity": severity,
            "category": str(category),
            "title": str(title),
            "detail": str(detail),
            "evidence": evidence,
            "recommendation": recommendation,
        }
    return {
        "severity": SEVERITY_INFO,
        "category": "uncategorized",
        "title": "Raw finding",
        "detail": str(item),
        "evidence": None,
        "recommendation": None,
    }


def normalize_findings(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [normalize_finding(item) for item in items]


def validate_target(raw: str) -> Tuple[Optional[str], Optional[str]]:
    value = raw.strip()
    if not value:
        return None, "empty"
    if len(value) > MAX_TARGET_LEN:
        return None, "too long"
    if re.search(r"\s", value):
        return None, "contains whitespace"
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", value):
        value = "http://" + value
    parsed = parse.urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return None, f"unsupported scheme `{parsed.scheme}`"
    if not parsed.hostname:
        return None, "missing host"
    return value, None


def save_scan(targets: List[str], options: Dict[str, Any], results: List[Dict[str, Any]], totals: Dict[str, int], elapsed: float) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = slugify(targets[0] if targets else "scan")
    scan_id = f"{ts}_{slug}"
    scan_dir = os.path.join(RESULTS_DIR, scan_id)
    tests_dir = os.path.join(scan_dir, "tests")
    per_target_dir = os.path.join(scan_dir, "targets")
    os.makedirs(tests_dir, exist_ok=True)
    os.makedirs(per_target_dir, exist_ok=True)

    summary = {
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": elapsed,
        "options": options,
        "targets": targets,
        "totals": totals,
        "results": results,
    }
    with open(os.path.join(scan_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        for finding in normalize_findings(r.get("findings", [])):
            cat = category_slug(finding.get("category", "uncategorized"))
            by_category.setdefault(cat, []).append(
                {
                    "target": r.get("target"),
                    "normalized_url": r.get("normalized_url"),
                    **finding,
                }
            )
    for cat, items in by_category.items():
        with open(os.path.join(tests_dir, f"{cat}.json"), "w", encoding="utf-8") as f:
            json.dump({"category": cat, "count": len(items), "findings": items}, f, indent=2)

    for r in results:
        tgt_slug = slugify(str(r.get("target", "target")))
        with open(os.path.join(per_target_dir, f"{tgt_slug}.json"), "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)

    with open(os.path.join(scan_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_scan_page(summary))

    return scan_id


def run_scan(targets: List[str], options: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, int], float]:
    started = time.time()
    results: List[Dict[str, Any]] = []
    concurrency = max(1, min(int(options.get("concurrency", 6)), 12))
    timeout = int(options.get("timeout", 30))
    check_ports = bool(options.get("check_ports"))
    check_paths = bool(options.get("check_paths"))
    active = bool(options.get("active"))
    fetch_evidence = bool(options.get("fetch_evidence"))
    scan_subdomains = bool(options.get("scan_subdomains"))
    extra_ports: List[int] = options.get("extra_ports") or []

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(
                analyze_target,
                t,
                timeout,
                check_ports,
                check_paths,
                active,
                extra_ports,
                fetch_evidence,
                scan_subdomains,
            ): t
            for t in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append(
                    {
                        "target": futures[fut],
                        "findings": [
                            {
                                "severity": SEVERITY_MEDIUM,
                                "category": "Runner",
                                "title": "Analysis crashed",
                                "detail": str(exc),
                            }
                        ],
                    }
                )
    results.sort(key=lambda r: targets.index(r.get("target")) if r.get("target") in targets else 999)

    try:
        cross_target_pivot(results, timeout, fetch_evidence)
    except Exception:
        pass

    totals = summarize(results)
    elapsed = round(time.time() - started, 2)
    return results, totals, elapsed


STYLE = """
:root {
  --bg:#ffffff; --panel:#ffffff; --border:#dddddd; --muted:#555555;
  --text:#111827; --accent:#1f6feb; --accent-soft:#e7f0ff;
  --ok:#16a34a; --danger:#c0392b;
}
*{box-sizing:border-box}
html,body{margin:0}
body{
  font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;
  max-width:1100px; margin:40px auto; padding:0 16px;
  background:var(--bg); color:var(--text); line-height:1.45;
}
main{margin:0}
.card{
  background:var(--panel); border:1px solid var(--border); border-radius:8px;
  padding:16px; margin-bottom:18px;
}
.card h2{margin:0 0 12px 0;font-size:16px;color:#111827}
.card p.legend{color:var(--muted);font-size:12.5px;margin:12px 0 0 0}
label.field-label{display:block;font-size:13px;color:#374151;margin:0 0 6px 0;font-weight:600}
textarea,input[type=text],input[type=number]{
  width:100%; border:1px solid var(--border); border-radius:8px; padding:10px 12px;
  font-size:14px; background:#fff; color:var(--text); outline:none;
  font-family:inherit; transition:border-color .15s, box-shadow .15s;
}
textarea{min-height:120px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
textarea:focus,input:focus{border-color:var(--accent); box-shadow:0 0 0 3px rgba(31,111,235,.15)}
.field-error{color:var(--danger);font-size:12.5px;margin-top:4px;display:none}
.row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.row.sm{grid-template-columns:repeat(2,minmax(0,1fr))}
@media (max-width:820px){.row,.row.sm{grid-template-columns:1fr}}
.opt{
  display:flex;align-items:flex-start;gap:10px;padding:12px;border:1px solid var(--border);
  border-radius:8px;background:#fff;cursor:pointer;
}
.opt:hover{border-color:#c9c9c9;background:#fff}
.opt input{accent-color:var(--accent);width:16px;height:16px;margin-top:2px;flex:none}
.opt strong{font-size:13.5px}
.opt small{display:block;color:var(--muted);font-size:12px;margin-top:2px}
.actions{display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap}
button.primary{
  background:var(--accent);color:#fff;border:0;padding:10px 16px;border-radius:8px;
  font-weight:600;cursor:pointer;font-size:14px;transition:background .15s;
}
button.primary:hover{background:#1458c4}
button.primary[disabled]{background:#9ca3af;cursor:not-allowed}
button.ghost{
  background:#fff;color:var(--text);border:1px solid var(--border);padding:10px 14px;
  border-radius:8px;font-weight:500;cursor:pointer;font-size:13.5px;
}
button.ghost:hover{background:#f3f4f6}
.loader{display:none;color:var(--muted);font-size:13px;align-items:center;gap:8px}
.loader.active{display:inline-flex}
.spinner{
  width:14px;height:14px;border-radius:50%;border:2px solid #d1d5db;border-top-color:var(--accent);
  animation:spin .9s linear infinite; display:inline-block;
}
@keyframes spin{to{transform:rotate(360deg)}}
.pill{display:inline-block;padding:4px 10px;border-radius:12px;color:#fff;font-weight:600;font-size:12px;margin:0 6px 6px 0}
.pill.meta{background:#e5e7eb;color:#374151}
.summary{display:flex;flex-wrap:wrap;align-items:center;margin:4px 0 0 0}
.banner{
  border-radius:8px;padding:12px 14px;margin:0 0 14px 0;border:1px solid var(--border);
  font-size:13.5px;background:#fff;
}
.banner.error{background:#fef2f2;border-color:#fecaca;color:#991b1b}
.banner.success{background:#ecfdf5;border-color:#a7f3d0;color:#065f46}
.banner.info{background:var(--accent-soft);border-color:#bfdbfe;color:#1e40af}
.banner ul{margin:6px 0 0 20px;padding:0}
section.target{margin:22px 0;padding:16px;border:1px solid var(--border);border-radius:8px;background:#fff}
section.target h2{margin:0 0 6px 0;font-size:16px;word-break:break-all}
section.target .meta{color:#555;margin:2px 0 10px 0;font-size:13px;line-height:1.55;word-break:break-all}
table.findings{width:100%;border-collapse:collapse;border:1px solid #eee;background:#fff;table-layout:fixed}
table.findings td{padding:8px 10px;border-top:1px solid #eee;vertical-align:top;word-wrap:break-word;word-break:break-word}
table.findings tr:first-child td{border-top:0}
table.findings col.c-sev{width:96px}
table.findings col.c-cat{width:160px}
.sev{display:inline-block;padding:3px 8px;border-radius:6px;color:#fff;font-weight:700;font-size:11px;letter-spacing:.5px;text-transform:uppercase;white-space:nowrap}
.detail strong{display:block;font-size:13.5px;margin-bottom:2px}
.detail .muted{color:var(--muted);font-size:12.5px}
.evidence{
  margin-top:8px; background:#0b1021; color:#d1d5db; border-radius:6px; border:1px solid #1f2937;
  padding:10px 12px; font-size:12px; font-family:ui-monospace,Menlo,monospace;
  max-height:240px; overflow:auto; white-space:pre-wrap; word-break:break-all;
}
.fix{color:#374151;font-size:12.5px;margin-top:6px}
.scan-list a{
  display:flex;justify-content:space-between;align-items:center;gap:8px;padding:10px 12px;
  border:1px solid var(--border);border-radius:8px;margin-bottom:8px;text-decoration:none;
  color:var(--text);background:#fff;
}
.scan-list a:hover{border-color:#c9c9c9;background:#fff}
.scan-list .muted{color:var(--muted);font-size:12.5px}
.kbd{font-family:ui-monospace,Menlo,monospace;background:#f3f4f6;padding:1px 6px;border:1px solid var(--border);border-radius:4px;font-size:12px}
.flex{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.right{margin-left:auto}
footer{padding:22px;text-align:center;color:var(--muted);font-size:12px}
.no-results{color:var(--muted);font-size:13px;padding:8px 0}
"""


def render_layout(title: str, body: str, extra_head: str = "") -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html_mod.escape(title)}</title>
<style>{STYLE}</style>
{extra_head}
</head>
<body>
<main>
<h1 style="margin:0 0 16px 0">Security Scanner Report Console</h1>
{body}
</main>
</body>
</html>"""


def render_form(
    targets_text: str = "",
    timeout: int = 30,
    extra_ports: str = "",
    checked: Optional[Dict[str, bool]] = None,
) -> str:
    c = checked or {"check_paths": True, "check_ports": False, "fetch_evidence": False, "active": False, "scan_subdomains": False}

    def cb(name: str, title: str, desc: str) -> str:
        attr = " checked" if c.get(name) else ""
        return (
            f"<label class='opt'><input type='checkbox' name='{name}'{attr}>"
            f"<div><strong>{html_mod.escape(title)}</strong><small>{html_mod.escape(desc)}</small></div></label>"
        )

    return f"""
<form method='POST' action='/scan' id='scanForm' novalidate>
  <label class='field-label' for='targets'>Targets (one per line, max {MAX_TARGETS})</label>
  <textarea name='targets' id='targets' placeholder='https://example.com&#10;http://10.0.0.1:8080/login' required>{html_mod.escape(targets_text)}</textarea>
  <div class='field-error' id='targetsError'>Please enter at least one target URL.</div>

  <div class='row' style='margin-top:14px'>
    {cb("check_paths", "Sensitive paths", ".git/.env deep checks with content validation, soft-404 detection, auto-escalation")}
    {cb("check_ports", "Port scan", "Common TCP ports (DB, admin, Docker, Redis, etc.)")}
    {cb("fetch_evidence", "Fetch evidence", "Capture content of exposed files (secrets redacted)")}
    {cb("active", "Active probes", "XSS (multi-context), SQLi (error + boolean), open-redirect bypass pack, path traversal, SSTI, XXE — safe markers only")}
  </div>
  <div class='row' style='margin-top:12px'>
    {cb("scan_subdomains", "Subdomain pivot", "On confirmed .git/.env leak, probe common subdomains for the same files")}
  </div>

  <div class='row sm' style='margin-top:14px'>
    <div>
      <label class='field-label'>Timeout (seconds)</label>
      <input type='number' name='timeout' value='{timeout}' min='2' max='120'>
    </div>
    <div>
      <label class='field-label'>Extra ports (comma-separated)</label>
      <input type='text' name='extra_ports' placeholder='8443, 9090' value='{html_mod.escape(extra_ports)}'>
    </div>
  </div>

  <div class='actions'>
    <button type='submit' id='runBtn' class='primary'>Run scan</button>
    <button type='button' id='clearBtn' class='ghost'>Clear</button>
    <span class='loader' id='loader'><span class='spinner'></span><span id='loaderText'>Scanning… 0s</span></span>
  </div>
</form>

<script>
(function(){{
  const form = document.getElementById('scanForm');
  const ta = document.getElementById('targets');
  const err = document.getElementById('targetsError');
  const btn = document.getElementById('runBtn');
  const clearBtn = document.getElementById('clearBtn');
  const loader = document.getElementById('loader');
  const loaderText = document.getElementById('loaderText');

  clearBtn.addEventListener('click', () => {{ ta.value = ''; ta.focus(); }});

  form.addEventListener('submit', (e) => {{
    const lines = (ta.value || '').split(/\\r?\\n/).map(s => s.trim()).filter(Boolean);
    if (lines.length === 0) {{
      e.preventDefault();
      err.style.display = 'block';
      ta.focus();
      return;
    }}
    if (lines.length > {MAX_TARGETS}) {{
      e.preventDefault();
      err.textContent = 'Too many targets (max {MAX_TARGETS}).';
      err.style.display = 'block';
      ta.focus();
      return;
    }}
    err.style.display = 'none';
    btn.disabled = true;
    btn.textContent = 'Scanning…';
    loader.classList.add('active');
    const start = Date.now();
    setInterval(() => {{
      const s = Math.floor((Date.now() - start) / 1000);
      loaderText.textContent = 'Scanning… ' + s + 's';
    }}, 500);
  }});

  ta.addEventListener('input', () => {{ err.style.display = 'none'; }});
}})();
</script>
"""


def render_index(message: Optional[str] = None, error: Optional[str] = None, invalid: Optional[List[str]] = None, preserved: Optional[Dict[str, Any]] = None) -> str:
    scans = list_recent_scans(limit=10)
    if scans:
        items = []
        for s in scans:
            totals = s.get("totals", {}) or {}
            pills = "".join(
                f"<span class='pill' style='background:{SEV_COLORS[sev]}'>{sev.upper()}: {totals.get(sev,0)}</span>"
                for sev in SEVERITY_ORDER
                if totals.get(sev, 0)
            ) or "<span class='pill meta'>no findings</span>"
            tgts = s.get("targets", []) or []
            items.append(
                f"<a href='/scan_results/{html_mod.escape(s['scan_id'])}'>"
                f"<div><strong>{html_mod.escape(s['scan_id'])}</strong>"
                f"<div class='muted' style='margin-top:2px'>{html_mod.escape(', '.join(tgts[:3]))}{' …' if len(tgts) > 3 else ''}</div></div>"
                f"<div class='right'>{pills}</div>"
                f"</a>"
            )
        scan_list = f"<div class='scan-list'>{''.join(items)}</div>"
    else:
        scan_list = "<div class='no-results'>No previous scans yet.</div>"

    banners = []
    if message:
        banners.append(f"<div class='banner success'>{html_mod.escape(message)}</div>")
    if error:
        banners.append(f"<div class='banner error'>{html_mod.escape(error)}</div>")
    if invalid:
        items = "".join(f"<li><code>{html_mod.escape(x)}</code></li>" for x in invalid)
        banners.append(f"<div class='banner error'>Some targets were rejected:<ul>{items}</ul></div>")

    preserved = preserved or {}
    targets_text = preserved.get("targets_text", "")
    timeout = preserved.get("timeout", 30)
    extra_ports = preserved.get("extra_ports", "")
    checked = preserved.get("checked") or {"check_paths": True}

    body = f"""
{''.join(banners)}
<div class='card'>
  <h2>Run a new scan</h2>
  {render_form(targets_text=targets_text, timeout=timeout, extra_ports=extra_ports, checked=checked)}
  <p class='legend'>Only scan systems you are authorized to test. Each scan is saved to <code>scan_results/&lt;timestamp&gt;_&lt;slug&gt;/</code> with per-category JSON in <code>tests/</code> and per-target JSON in <code>targets/</code>.</p>
</div>

<div class='card'>
  <h2>Recent scans</h2>
  {scan_list}
</div>
"""
    return render_layout("Security Scanner Console", body)


def render_scan_page(summary: Dict[str, Any]) -> str:
    totals = summary.get("totals", {})
    options = summary.get("options", {})
    opt_pills = []
    for k, v in options.items():
        if isinstance(v, bool) and v:
            opt_pills.append(f"<span class='pill meta'>{html_mod.escape(k)}</span>")
        elif not isinstance(v, bool) and v not in (None, "", [], 0):
            opt_pills.append(f"<span class='pill meta'>{html_mod.escape(k)}: {html_mod.escape(str(v))}</span>")
    summary_pills = "".join(
        f"<span class='pill' style='background:{SEV_COLORS[s]}'>{s.upper()}: {totals.get(s,0)}</span>"
        for s in SEVERITY_ORDER
    )

    blocks = []
    for r in summary.get("results", []):
        findings = sorted(
            normalize_findings(r.get("findings", [])),
            key=lambda x: severity_rank(x.get("severity")),
        )
        rows = []
        for f in findings:
            sev = f.get("severity", "info")
            color = SEV_COLORS.get(sev, "#6c757d")
            evidence = f.get("evidence")
            evidence_html = (
                f"<div class='evidence'>{html_mod.escape(str(evidence)[:6000])}</div>"
                if evidence
                else ""
            )
            rec = f.get("recommendation")
            rec_html = (
                f"<div class='fix'><strong>Fix:</strong> {html_mod.escape(str(rec))}</div>"
                if rec
                else ""
            )
            rows.append(
                f"<tr>"
                f"<td><span class='sev' style='background:{color}'>{html_mod.escape(sev)}</span></td>"
                f"<td><span class='muted'>{html_mod.escape(str(f.get('category','')))}</span></td>"
                f"<td class='detail'>"
                f"<strong>{html_mod.escape(str(f.get('title','')))}</strong>"
                f"<span class='muted'>{html_mod.escape(str(f.get('detail','')))}</span>"
                f"{evidence_html}{rec_html}"
                f"</td>"
                f"</tr>"
            )
        findings_html = (
            "<table class='findings'><colgroup><col class='c-sev'><col class='c-cat'><col></colgroup>"
            + "".join(rows)
            + "</table>"
            if rows
            else "<div class='no-results'>No findings.</div>"
        )
        tls = r.get("tls") or {}
        meta_parts = [
            f"{html_mod.escape(str(r.get('hostname') or ''))} ({html_mod.escape(str(r.get('resolved_ip') or ''))})",
            f"HTTP {html_mod.escape(str(r.get('http_status')))}",
        ]
        if tls.get("enabled"):
            meta_parts.append(
                f"TLS {html_mod.escape(str(tls.get('version')))} &middot; exp {html_mod.escape(str(tls.get('not_after')))} ({html_mod.escape(str(tls.get('days_until_expiry')))}d)"
            )
        ports = r.get("open_ports") or []
        if ports:
            meta_parts.append("open ports: " + html_mod.escape(", ".join(str(p) for p in ports)))
        blocks.append(
            f"<section class='target'>"
            f"<h2>{html_mod.escape(str(r.get('target')))}</h2>"
            f"<div class='meta'>{' | '.join(meta_parts)}</div>"
            f"{findings_html}"
            f"</section>"
        )

    scan_id = summary.get("scan_id", "")
    per_cat = list_test_files(scan_id)
    per_cat_links = "".join(
        f"<a href='/scan_results/{html_mod.escape(scan_id)}/tests/{html_mod.escape(c)}' class='pill meta' style='text-decoration:none'>{html_mod.escape(c)}.json</a>"
        for c in per_cat
    )

    body = f"""
<div class='card'>
  <div class='flex'>
    <h2 style='margin:0'>Scan {html_mod.escape(scan_id)}</h2>
    <div class='right flex'>
      <a href='/' class='pill meta' style='text-decoration:none'>New scan</a>
      <a href='/scan_results/{html_mod.escape(scan_id)}/summary.json' class='pill meta' style='text-decoration:none'>summary.json</a>
    </div>
  </div>
  <div class='muted' style='margin-top:6px;font-size:12.5px'>
    Generated {html_mod.escape(summary.get('generated_at',''))} in {summary.get('elapsed_seconds',0)}s
  </div>
  <div class='summary' style='margin-top:10px'>{summary_pills}</div>
  <div class='summary' style='margin-top:4px'>{''.join(opt_pills)}</div>
</div>

<div class='card'>
  <h2>Per-category downloads</h2>
  <div>{per_cat_links or "<span class='muted'>none</span>"}</div>
  <p class='legend'>Files live at <code>scan_results/{html_mod.escape(scan_id)}/tests/&lt;category&gt;.json</code>.</p>
</div>

{''.join(blocks) if blocks else "<div class='card no-results'>No targets analyzed.</div>"}
"""
    return render_layout(f"Scan {scan_id}", body)


def list_recent_scans(limit: int = 20) -> List[Dict[str, Any]]:
    if not os.path.isdir(RESULTS_DIR):
        return []
    dirs = [d for d in os.listdir(RESULTS_DIR) if os.path.isdir(os.path.join(RESULTS_DIR, d))]
    dirs.sort(reverse=True)
    results: List[Dict[str, Any]] = []
    for d in dirs[:limit]:
        summary_path = os.path.join(RESULTS_DIR, d, "summary.json")
        if os.path.isfile(summary_path):
            try:
                with open(summary_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                results.append(
                    {
                        "scan_id": data.get("scan_id", d),
                        "targets": data.get("targets", []),
                        "totals": data.get("totals", {}),
                    }
                )
            except Exception:
                continue
    return results


def list_test_files(scan_id: str) -> List[str]:
    path = os.path.join(RESULTS_DIR, scan_id, "tests")
    if not os.path.isdir(path):
        return []
    return sorted(os.path.splitext(f)[0] for f in os.listdir(path) if f.endswith(".json"))


def load_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(RESULTS_DIR, scan_id, "summary.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def parse_form(raw: bytes) -> Dict[str, List[str]]:
    return parse.parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=False)


def safe_scan_id(value: str) -> Optional[str]:
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", value or ""):
        return None
    return value


def safe_category(value: str) -> Optional[str]:
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", value or ""):
        return None
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "SecurityScanner/1.0"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _send_html(self, status: int, html_body: str):
        self._send(status, html_body.encode("utf-8"), "text/html; charset=utf-8")

    def _send_json(self, status: int, data: Any):
        self._send(status, json.dumps(data, indent=2).encode("utf-8"), "application/json")

    def do_GET(self):
        parsed = parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            return self._send_html(200, render_index())

        if path == "/api/scan_results":
            return self._send_json(200, list_recent_scans(limit=50))

        m = re.match(r"^/scan_results/([A-Za-z0-9_\-]+)/?$", path)
        if m:
            scan_id = safe_scan_id(m.group(1))
            if not scan_id:
                return self._send_html(400, render_layout("Bad request", "<div class='card banner error'>Invalid scan id.</div>"))
            data = load_scan(scan_id)
            if not data:
                return self._send_html(404, render_layout("Not found", "<div class='card banner error'>Scan not found. <a href='/'>Go home</a>.</div>"))
            return self._send_html(200, render_scan_page(data))

        m = re.match(r"^/scan_results/([A-Za-z0-9_\-]+)/summary\.json$", path)
        if m:
            scan_id = safe_scan_id(m.group(1))
            if not scan_id:
                return self._send_json(400, {"error": "bad scan id"})
            data = load_scan(scan_id)
            if not data:
                return self._send_json(404, {"error": "not found"})
            return self._send_json(200, data)

        m = re.match(r"^/scan_results/([A-Za-z0-9_\-]+)/tests/([A-Za-z0-9_\-]+)/?$", path)
        if m:
            scan_id = safe_scan_id(m.group(1))
            category = safe_category(m.group(2))
            if not scan_id or not category:
                return self._send_json(400, {"error": "bad id"})
            test_path = os.path.join(RESULTS_DIR, scan_id, "tests", f"{category}.json")
            if not os.path.isfile(test_path):
                return self._send_json(404, {"error": "test not found"})
            with open(test_path, "rb") as f:
                return self._send(200, f.read(), "application/json")

        return self._send_html(404, render_layout("Not found", "<div class='card banner error'>Page not found. <a href='/'>Go home</a>.</div>"))

    def do_POST(self):
        parsed = parse.urlparse(self.path)
        if parsed.path != "/scan":
            return self._send_html(404, render_layout("Not found", "<div class='card banner error'>Unknown endpoint.</div>"))

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return self._send_html(
                400,
                render_index(error="Empty submission. Please enter at least one target."),
            )
        if length > MAX_BODY_BYTES:
            return self._send_html(
                413,
                render_index(error=f"Submission too large (max {MAX_BODY_BYTES} bytes)."),
            )

        raw = self.rfile.read(length)
        form = parse_form(raw)

        raw_targets = form.get("targets", [""])[0]
        lines = [line.strip() for line in raw_targets.splitlines()]
        non_empty = [l for l in lines if l]

        if not non_empty:
            return self._send_html(
                400,
                render_index(
                    error="Please enter at least one target URL.",
                    preserved={
                        "targets_text": raw_targets,
                        "checked": {
                            "check_paths": "check_paths" in form,
                            "check_ports": "check_ports" in form,
                            "fetch_evidence": "fetch_evidence" in form,
                            "active": "active" in form,
                            "scan_subdomains": "scan_subdomains" in form,
                        },
                    },
                ),
            )

        seen = set()
        deduped: List[str] = []
        for x in non_empty:
            if x not in seen:
                seen.add(x)
                deduped.append(x)

        if len(deduped) > MAX_TARGETS:
            return self._send_html(
                400,
                render_index(
                    error=f"Too many targets after deduplication ({len(deduped)}). Max {MAX_TARGETS}.",
                    preserved={"targets_text": raw_targets},
                ),
            )

        validated: List[str] = []
        invalid: List[str] = []
        for t in deduped:
            norm, err = validate_target(t)
            if norm:
                validated.append(norm)
            else:
                invalid.append(f"{t} — {err}")

        if not validated:
            return self._send_html(
                400,
                render_index(
                    error="All targets were invalid.",
                    invalid=invalid,
                    preserved={
                        "targets_text": raw_targets,
                        "checked": {
                            "check_paths": "check_paths" in form,
                            "check_ports": "check_ports" in form,
                            "fetch_evidence": "fetch_evidence" in form,
                            "active": "active" in form,
                            "scan_subdomains": "scan_subdomains" in form,
                        },
                    },
                ),
            )

        extra_ports_raw = form.get("extra_ports", [""])[0]
        extra_ports: List[int] = []
        for p in extra_ports_raw.split(","):
            p = p.strip()
            if p.isdigit():
                val = int(p)
                if 1 <= val <= 65535:
                    extra_ports.append(val)

        try:
            timeout = int(form.get("timeout", ["30"])[0])
        except ValueError:
            timeout = 30
        timeout = max(2, min(timeout, 120))

        options = {
            "check_paths": "check_paths" in form,
            "check_ports": "check_ports" in form,
            "fetch_evidence": "fetch_evidence" in form,
            "active": "active" in form,
            "scan_subdomains": "scan_subdomains" in form,
            "timeout": timeout,
            "concurrency": 6,
            "extra_ports": extra_ports,
        }

        try:
            results, totals, elapsed = run_scan(validated, options)
        except Exception as exc:
            return self._send_html(
                500,
                render_index(
                    error=f"Scan crashed: {exc}",
                    preserved={"targets_text": raw_targets},
                ),
            )

        scan_id = save_scan(validated, options, results, totals, elapsed)

        self.send_response(303)
        self.send_header("Location", f"/scan_results/{scan_id}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"Security Scanner Web Console running at {url}")
    print(f"Reports directory: {RESULTS_DIR}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
