#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import html
import http.cookies
import json
import re
import socket
import ssl
import sys
import time
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib import error, parse, request


SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

SEVERITY_ORDER = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

DEFAULT_USER_AGENT = "Security-Scanner/2.0 (+authorized-testing-only)"

COMMON_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.DS_Store",
    "/config.php",
    "/config.json",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/admin",
    "/administrator",
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/graphql",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/sitemap.xml",
    "/robots.txt",
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

SENSITIVE_PATH_KEYWORDS = {
    "/.git/": "Exposed Git repository metadata",
    "/.env": "Exposed environment file (credentials likely)",
    "/phpinfo": "PHP info page exposed",
    "/server-status": "Apache server-status page exposed",
    "/server-info": "Apache server-info page exposed",
    "/.DS_Store": "macOS DS_Store file exposed",
    "/actuator/env": "Spring actuator env exposed",
    "/backup": "Backup archive exposed",
    "/dump.sql": "SQL dump exposed",
    "/db.sql": "SQL dump exposed",
    "/wp-admin": "WordPress admin reachable",
    "/wp-login.php": "WordPress login reachable",
    "/xmlrpc.php": "WordPress XML-RPC reachable",
    "/crossdomain.xml": "Flash crossdomain policy exposed",
}

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch_",
    r"mariadb server version for the right syntax",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\):",
    r"postgresql query failed",
    r"psql: error",
    r"sqlite_error",
    r"sqlite\.error",
    r"sqlite3\.operationalerror",
    r"sqlstate\[",
    r"ora-\d{5}",
    r"odbc sql server driver",
    r"microsoft ole db provider for sql server",
    r"system\.data\.sqlclient\.sqlexception",
    r"sql syntax.*near",
    r"syntax error at or near",
    r"unexpected end of sql command",
    r"db2 sql error",
    r"cli driver.*db2",
    r"sybase.*server message",
    r"informix.*error",
]

DANGEROUS_HEADERS_REVEAL = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
]

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


@dataclass
class Finding:
    target: str
    severity: str
    category: str
    title: str
    detail: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class FetchResult:
    status: Optional[int]
    headers: Dict[str, str]
    set_cookies: List[str]
    body: str
    final_url: str
    error: Optional[str]
    elapsed_ms: int


class HTMLAnalyzer(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[Dict[str, object]] = []
        self._current_form: Optional[Dict[str, object]] = None
        self.inline_scripts = 0
        self.inline_styles = 0
        self.external_scripts: List[str] = []
        self.external_styles: List[str] = []
        self.external_resources: List[str] = []
        self.resources_with_integrity: Set[str] = set()
        self.links: List[str] = []
        self._in_script = False
        self._in_style = False
        self._script_buffer: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        tag_lower = tag.lower()
        if tag_lower == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": a.get("method", "get").lower(),
                "autocomplete": a.get("autocomplete", "").lower(),
                "enctype": a.get("enctype", "").lower(),
                "inputs": [],
            }
        if tag_lower == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "type": a.get("type", "text").lower(),
                    "name": a.get("name", "").lower(),
                    "autocomplete": a.get("autocomplete", "").lower(),
                    "accept": a.get("accept", "").lower(),
                }
            )
        if tag_lower == "script":
            src = a.get("src", "")
            if src:
                self.external_scripts.append(src)
                self.external_resources.append(src)
                if a.get("integrity"):
                    self.resources_with_integrity.add(src)
            else:
                self._in_script = True
        if tag_lower == "link":
            rel = a.get("rel", "").lower()
            href = a.get("href", "")
            if href and "stylesheet" in rel:
                self.external_styles.append(href)
                self.external_resources.append(href)
                if a.get("integrity"):
                    self.resources_with_integrity.add(href)
        if tag_lower == "img":
            src = a.get("src", "")
            if src:
                self.external_resources.append(src)
        if tag_lower == "iframe":
            src = a.get("src", "")
            if src:
                self.external_resources.append(src)
        if tag_lower == "style":
            self._in_style = True
        if tag_lower == "a":
            href = a.get("href", "")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        if tag_lower == "script" and self._in_script:
            content = "".join(self._script_buffer).strip()
            if content:
                self.inline_scripts += 1
            self._in_script = False
            self._script_buffer = []
        if tag_lower == "style" and self._in_style:
            self.inline_styles += 1
            self._in_style = False

    def handle_data(self, data):
        if self._in_script:
            self._script_buffer.append(data)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    parsed = parse.urlparse(raw)
    if not parsed.scheme:
        return "http://" + raw
    return raw


def fetch(url: str, timeout: int, method: str = "GET", headers: Optional[Dict[str, str]] = None, data: Optional[bytes] = None, allow_redirects: bool = True) -> FetchResult:
    req_headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"}
    if headers:
        req_headers.update(headers)

    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None

    opener = request.build_opener() if allow_redirects else request.build_opener(NoRedirect)
    req = request.Request(url, data=data, headers=req_headers, method=method)
    start = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            elapsed = int((time.time() - start) * 1000)
            status = resp.getcode()
            hdr_items = list(resp.headers.items())
            set_cookies = [v for k, v in hdr_items if k.lower() == "set-cookie"]
            headers_dict = {k.lower(): v for k, v in hdr_items}
            content_type = headers_dict.get("content-type", "").lower()
            body = ""
            if any(t in content_type for t in ["text/", "application/json", "application/xml", "application/xhtml", "application/javascript"]):
                raw = resp.read(500000)
                body = raw.decode("utf-8", errors="ignore")
            return FetchResult(status, headers_dict, set_cookies, body, resp.geturl(), None, elapsed)
    except error.HTTPError as exc:
        elapsed = int((time.time() - start) * 1000)
        hdr_items = list(exc.headers.items()) if exc.headers else []
        set_cookies = [v for k, v in hdr_items if k.lower() == "set-cookie"]
        headers_dict = {k.lower(): v for k, v in hdr_items}
        body = ""
        try:
            body = exc.read(200000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return FetchResult(exc.code, headers_dict, set_cookies, body, url, str(exc), elapsed)
    except Exception as exc:
        elapsed = int((time.time() - start) * 1000)
        return FetchResult(None, {}, [], "", url, str(exc), elapsed)


def resolve_host(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_tls(hostname: str, port: int, timeout: int) -> Dict[str, object]:
    info: Dict[str, object] = {
        "enabled": False,
        "version": None,
        "cipher": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "san": [],
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["enabled"] = True
                info["version"] = ssock.version()
                info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["not_before"] = cert.get("notBefore")
                info["not_after"] = cert.get("notAfter")
                san = cert.get("subjectAltName", [])
                info["san"] = [v for t, v in san if t.lower() == "dns"]
                if cert.get("notAfter"):
                    try:
                        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        info["days_until_expiry"] = (expiry - datetime.now(timezone.utc)).days
                    except Exception:
                        pass
    except Exception as exc:
        info["error"] = str(exc)
    return info


def analyze_csp(csp: str) -> List[str]:
    issues: List[str] = []
    if not csp:
        return issues
    directives: Dict[str, List[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        values = tokens[1:]
        directives[name] = [v.lower() for v in values]

    def has(name: str, token: str) -> bool:
        return token in directives.get(name, [])

    if has("script-src", "'unsafe-inline'") or has("default-src", "'unsafe-inline'"):
        issues.append("CSP allows 'unsafe-inline' for scripts")
    if has("script-src", "'unsafe-eval'") or has("default-src", "'unsafe-eval'"):
        issues.append("CSP allows 'unsafe-eval'")
    for d in ["script-src", "default-src", "style-src", "img-src", "connect-src"]:
        if "*" in directives.get(d, []):
            issues.append(f"CSP uses wildcard '*' in {d}")
    if "default-src" not in directives and "script-src" not in directives:
        issues.append("CSP has no default-src or script-src")
    if "object-src" not in directives:
        issues.append("CSP missing object-src (should be 'none')")
    if "base-uri" not in directives:
        issues.append("CSP missing base-uri")
    if "frame-ancestors" not in directives:
        issues.append("CSP missing frame-ancestors (consider 'none' or 'self')")
    if "form-action" not in directives:
        issues.append("CSP missing form-action")
    if "report-uri" not in directives and "report-to" not in directives:
        issues.append("CSP has no reporting endpoint (report-uri/report-to)")
    return issues


def analyze_cookies(set_cookies: List[str], target: str) -> List[Finding]:
    findings: List[Finding] = []
    for raw in set_cookies:
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            lowered = raw.lower()
            sensitive = any(kw in name.lower() for kw in ["sess", "auth", "token", "jwt", "sid", "login", "csrf"])
            if sensitive:
                if not (name.startswith("__Host-") or name.startswith("__Secure-")):
                    findings.append(
                        Finding(
                            target=target,
                            severity=SEVERITY_LOW,
                            category="Cookies",
                            title=f"Sensitive cookie `{name}` lacks `__Host-`/`__Secure-` prefix",
                            detail="Cookie-prefix opt-ins enforce Secure/Path/Host scoping at the browser.",
                            evidence=raw,
                            recommendation="Rename to `__Host-<name>` (preferred) or `__Secure-<name>` for session/auth cookies.",
                        )
                    )
                if "secure" not in lowered:
                    findings.append(
                        Finding(
                            target=target,
                            severity=SEVERITY_HIGH,
                            category="Cookies",
                            title=f"Sensitive cookie `{name}` missing Secure",
                            detail="Session-like cookie sent without Secure flag.",
                            evidence=raw,
                            recommendation="Set `Secure` on session cookies.",
                        )
                    )
                if "httponly" not in lowered:
                    findings.append(
                        Finding(
                            target=target,
                            severity=SEVERITY_HIGH,
                            category="Cookies",
                            title=f"Sensitive cookie `{name}` missing HttpOnly",
                            detail="Session-like cookie is accessible from JavaScript.",
                            evidence=raw,
                            recommendation="Set `HttpOnly` on session cookies.",
                        )
                    )
                if "samesite" not in lowered:
                    findings.append(
                        Finding(
                            target=target,
                            severity=SEVERITY_MEDIUM,
                            category="Cookies",
                            title=f"Sensitive cookie `{name}` missing SameSite",
                            detail="Session cookies should restrict cross-site sending.",
                            evidence=raw,
                            recommendation="Set `SameSite=Lax` or `SameSite=Strict`.",
                        )
                    )
            else:
                if "samesite" not in lowered:
                    findings.append(
                        Finding(
                            target=target,
                            severity=SEVERITY_LOW,
                            category="Cookies",
                            title=f"Cookie `{name}` missing SameSite",
                            detail="Cookie lacks SameSite attribute.",
                            evidence=raw,
                        )
                    )
    return findings


def check_headers(target: str, parsed: parse.ParseResult, res: FetchResult) -> List[Finding]:
    findings: List[Finding] = []
    headers = res.headers

    required = {
        "content-security-policy": SEVERITY_MEDIUM,
        "x-content-type-options": SEVERITY_MEDIUM,
        "x-frame-options": SEVERITY_MEDIUM,
        "referrer-policy": SEVERITY_LOW,
        "permissions-policy": SEVERITY_LOW,
    }
    for h, sev in required.items():
        if h not in headers:
            findings.append(
                Finding(
                    target=target,
                    severity=sev,
                    category="Headers",
                    title=f"Missing `{h}`",
                    detail=f"Response header `{h}` is not set.",
                    recommendation=f"Add `{h}` with restrictive values.",
                )
            )

    if parsed.scheme == "https" and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_MEDIUM,
                category="Headers",
                title="Missing HSTS",
                detail="HTTPS endpoint missing `Strict-Transport-Security`.",
                recommendation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
            )
        )

    xcto = headers.get("x-content-type-options", "").lower()
    if xcto and xcto != "nosniff":
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_LOW,
                category="Headers",
                title="Invalid X-Content-Type-Options",
                detail=f"Value `{xcto}` should be `nosniff`.",
            )
        )

    xfo = headers.get("x-frame-options", "").lower()
    if xfo and xfo not in {"deny", "sameorigin"}:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_LOW,
                category="Headers",
                title="Weak X-Frame-Options",
                detail=f"Value `{xfo}` should be `DENY` or `SAMEORIGIN`.",
            )
        )

    csp = headers.get("content-security-policy", "")
    for issue in analyze_csp(csp):
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_MEDIUM,
                category="CSP",
                title="CSP weakness",
                detail=issue,
                evidence=csp[:400] if csp else None,
            )
        )

    for h in DANGEROUS_HEADERS_REVEAL:
        if h in headers and headers[h]:
            value = headers[h]
            if re.search(r"[\d.]+", value):
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_LOW,
                        category="Info Disclosure",
                        title=f"Version disclosure in `{h}`",
                        detail=f"Header reveals software/version: {value}",
                        recommendation="Strip or generalize banner headers in production.",
                    )
                )

    coop = headers.get("cross-origin-opener-policy")
    if not coop:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_INFO,
                category="Headers",
                title="Missing COOP",
                detail="Consider `Cross-Origin-Opener-Policy: same-origin`.",
            )
        )
    corp = headers.get("cross-origin-resource-policy")
    if not corp:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_INFO,
                category="Headers",
                title="Missing CORP",
                detail="Consider `Cross-Origin-Resource-Policy: same-origin`.",
            )
        )

    cache = headers.get("cache-control", "").lower()
    if parsed.path and any(k in parsed.path.lower() for k in ["login", "auth", "account", "admin", "password"]):
        if "no-store" not in cache:
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_LOW,
                    category="Headers",
                    title="Sensitive page may be cacheable",
                    detail="Auth-related page is missing `Cache-Control: no-store`.",
                )
            )

    return findings


def check_cors(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    evil_origin = "https://evil.example.com"
    res = fetch(target, timeout, method="GET", headers={"Origin": evil_origin})
    allow_origin = res.headers.get("access-control-allow-origin")
    allow_cred = res.headers.get("access-control-allow-credentials", "").lower()
    if allow_origin:
        if allow_origin == "*" and allow_cred == "true":
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_HIGH,
                    category="CORS",
                    title="CORS wildcard with credentials",
                    detail="`Access-Control-Allow-Origin: *` combined with credentials=true.",
                )
            )
        elif allow_origin == evil_origin:
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_HIGH,
                    category="CORS",
                    title="CORS reflects arbitrary Origin",
                    detail=f"Server reflects the attacker-controlled origin `{evil_origin}`.",
                    recommendation="Allowlist trusted origins server-side.",
                )
            )
            if allow_cred == "true":
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_CRITICAL,
                        category="CORS",
                        title="CORS reflection with credentials",
                        detail="Reflected origin combined with credentials=true allows cross-site data theft.",
                    )
                )
        elif allow_origin == "null":
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_MEDIUM,
                    category="CORS",
                    title="CORS allows null origin",
                    detail="`null` origin can be produced by sandboxed iframes and data: URLs.",
                )
            )
    return findings


def check_allowed_methods(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    res = fetch(target, timeout, method="OPTIONS")
    allow = res.headers.get("allow", "") or res.headers.get("access-control-allow-methods", "")
    if not allow:
        return findings
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    dangerous = methods & {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}
    if dangerous:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_MEDIUM,
                category="HTTP Methods",
                title=f"Dangerous HTTP methods allowed: {', '.join(sorted(dangerous))}",
                detail=f"Server advertises: {allow}",
                recommendation="Disable TRACE/TRACK; restrict PUT/DELETE via auth/ACL.",
            )
        )
    return findings


def check_redirects(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    res = fetch(target, timeout, allow_redirects=False)
    if res.status and 300 <= res.status < 400:
        location = res.headers.get("location", "")
        if location:
            parsed_loc = parse.urlparse(location)
            parsed_tgt = parse.urlparse(target)
            if parsed_loc.scheme and parsed_loc.hostname and parsed_loc.hostname != parsed_tgt.hostname:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_INFO,
                        category="Redirect",
                        title="Cross-origin redirect",
                        detail=f"Redirects to external host: {location}",
                    )
                )
    return findings


OPEN_REDIRECT_PAYLOADS = [
    "https://vibesec-redirect-check.example.invalid/canary",
    "//vibesec-redirect-check.example.invalid/canary",
    "\\/\\/vibesec-redirect-check.example.invalid/canary",
    "/\\/vibesec-redirect-check.example.invalid/canary",
    "https://trusted.example.com@vibesec-redirect-check.example.invalid/",
    "https://vibesec-redirect-check.example.invalid%2f@trusted.example.com/",
    "%2F%2Fvibesec-redirect-check.example.invalid/",
    "javascript:alert('vibesec-xss-canary')",
    "data:text/html,<script>alert('vibesec-xss-canary')</script>",
    "https://169.254.169.254/latest/meta-data/",
]

SSRF_PARAM_CANDIDATES = {
    "url", "uri", "link", "href", "src", "image", "img", "file",
    "redirect", "redir", "return", "returnto", "return_to",
    "continue", "next", "dest", "destination", "target", "proxy",
    "callback", "callback_url", "webhook", "feed", "rss", "open",
    "to", "fetch", "path", "page", "resource", "uri_target",
}

REDIRECT_CANDIDATES = {
    "next", "url", "redirect", "redir", "return", "returnto", "return_to",
    "dest", "destination", "continue", "target", "checkout_url", "callback",
    "back", "goto", "to",
}


def check_open_redirect_params(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(target)
    qs = parse.parse_qs(parsed.query, keep_blank_values=True)
    to_probe = [k for k in qs.keys() if k.lower() in REDIRECT_CANDIDATES]
    reported_keys: Set[str] = set()
    for key in to_probe:
        for payload in OPEN_REDIRECT_PAYLOADS:
            if key in reported_keys:
                break
            new_qs = {k: v[:] for k, v in qs.items()}
            new_qs[key] = [payload]
            new_query = parse.urlencode([(k, v) for k, values in new_qs.items() for v in values])
            probe_url = parsed._replace(query=new_query).geturl()
            try:
                res = fetch(probe_url, timeout, allow_redirects=False)
            except Exception:
                continue
            location = res.headers.get("location", "") if res.headers else ""
            location_lc = location.lower()
            suspicious = (
                "vibesec-redirect-check" in location_lc
                or "vibesec-xss-canary" in location_lc
                or location_lc.startswith("javascript:")
                or location_lc.startswith("data:")
                or "169.254.169.254" in location_lc
            )
            if res.status and 300 <= res.status < 400 and suspicious:
                severity = SEVERITY_HIGH
                title = f"Open redirect via `{key}`"
                if location_lc.startswith("javascript:") or location_lc.startswith("data:"):
                    severity = SEVERITY_CRITICAL
                    title = f"Open redirect → client-side code execution via `{key}`"
                elif "169.254.169.254" in location_lc:
                    severity = SEVERITY_CRITICAL
                    title = f"Open redirect → cloud metadata (SSRF) via `{key}`"
                findings.append(
                    Finding(
                        target=target,
                        severity=severity,
                        category="Open Redirect",
                        title=title,
                        detail=f"Payload `{payload}` caused redirect with reflected destination.",
                        evidence=f"Location: {location}",
                        recommendation="Validate against an allowlist of domains; only accept relative paths; reject `javascript:`/`data:` schemes and cloud-metadata IPs.",
                    )
                )
                reported_keys.add(key)
    return findings


def check_ssrf_parameters(target: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(target)
    qs = parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    hits = []
    for key, values in qs.items():
        name = key.lower()
        looks_like_url_value = any(
            isinstance(v, str) and (v.startswith("http://") or v.startswith("https://") or v.startswith("//"))
            for v in values
        )
        if name in SSRF_PARAM_CANDIDATES or looks_like_url_value:
            hits.append((key, values[0] if values else ""))
    if hits:
        keys_preview = ", ".join(sorted({k for k, _ in hits}))
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_MEDIUM,
                category="SSRF",
                title="URL-accepting parameter(s) detected",
                detail=f"Parameters likely carry URLs/paths (`{keys_preview}`). If server fetches them, validate with allowlist, block internal IPs (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254.169.254), and disable redirect following.",
                evidence="; ".join(f"{k}={v[:80]}" for k, v in hits[:4]),
                recommendation="Resolve/validate URLs server-side. Deny internal ranges & cloud metadata endpoints. See SSRF section of the Security Scanner skill.",
            )
        )
    return findings


PATH_TRAVERSAL_PARAMS = {"file", "path", "page", "include", "template", "doc", "download", "filename", "name", "image"}
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]
PATH_TRAVERSAL_SIGNATURES = [
    re.compile(r"root:[x*]:0:0:", re.MULTILINE),
    re.compile(r"daemon:[x*]:", re.MULTILINE),
    re.compile(r"\[fonts\][\s\S]{0,200}for 16-bit app support", re.IGNORECASE),
]


def check_path_traversal(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(target)
    qs = parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    keys_to_probe = [k for k in qs.keys() if k.lower() in PATH_TRAVERSAL_PARAMS]
    if not keys_to_probe:
        return findings
    hit_reported = False
    for key in keys_to_probe:
        if hit_reported:
            break
        for payload in PATH_TRAVERSAL_PAYLOADS:
            new_qs = {k: v[:] for k, v in qs.items()}
            new_qs[key] = [payload]
            new_query = parse.urlencode([(k, v) for k, values in new_qs.items() for v in values])
            probe_url = parsed._replace(query=new_query).geturl()
            try:
                res = fetch(probe_url, timeout)
            except Exception:
                continue
            body = res.body or ""
            if any(sig.search(body) for sig in PATH_TRAVERSAL_SIGNATURES):
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_CRITICAL,
                        category="Path Traversal",
                        title=f"Path traversal confirmed via `{key}`",
                        detail=f"Payload `{payload}` returned OS file contents.",
                        evidence=body[:400],
                        recommendation="Never join user input into filesystem paths. Use indirect mapping or canonicalize + enforce base-dir containment.",
                    )
                )
                hit_reported = True
                break
    return findings


SSTI_MARKER = "vibesec-ssti"
SSTI_PAYLOADS = [
    ("{{7*7}}{{'" + SSTI_MARKER + "'.upper()}}", SSTI_MARKER.upper()),
    ("${7*7}" + SSTI_MARKER, "49" + SSTI_MARKER),
    ("<%= 7*7 %>" + SSTI_MARKER, "49" + SSTI_MARKER),
    ("#{7*7}" + SSTI_MARKER, "49" + SSTI_MARKER),
]


def check_ssti(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(target)
    qs = parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    hit = False
    for key in list(qs.keys()):
        if hit:
            break
        for payload, expected in SSTI_PAYLOADS:
            new_qs = {k: v[:] for k, v in qs.items()}
            new_qs[key] = [payload]
            new_query = parse.urlencode([(k, v) for k, values in new_qs.items() for v in values])
            probe_url = parsed._replace(query=new_query).geturl()
            try:
                res = fetch(probe_url, timeout)
            except Exception:
                continue
            body = res.body or ""
            if expected and expected in body and payload not in body:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_CRITICAL,
                        category="SSTI",
                        title=f"Server-side template injection via `{key}`",
                        detail=f"Payload `{payload}` was evaluated server-side (expected marker `{expected}` found).",
                        evidence=body[:300],
                        recommendation="Never pass untrusted input to template engines. Use auto-escaping and keep templates/data strictly separated.",
                    )
                )
                hit = True
                break
    return findings


def _rebuild_query(parsed: parse.ParseResult, new_qs: Dict[str, List[str]]) -> str:
    return parsed._replace(
        query=parse.urlencode([(k, v) for k, values in new_qs.items() for v in values])
    ).geturl()


XSS_PAYLOADS: List[Tuple[str, str, str]] = [
    ("html", "<svg/onload=confirm(1)>", "<svg/onload=confirm(1)>"),
    ("html_img", "\"><img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>"),
    ("attr", "\" autofocus onfocus=alert(1) x=\"", "onfocus=alert(1)"),
    ("js_string", "';alert(1);//", "';alert(1);//"),
    ("js_template", "${alert(1)}", "${alert(1)}"),
    ("url_js", "javascript:alert(1)", "javascript:alert(1)"),
]


def check_reflection_xss(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(target)
    qs = parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    reported: Set[str] = set()
    for key in list(qs.keys()):
        if key in reported:
            continue
        for ctx, payload, needle in XSS_PAYLOADS:
            marker = f"vibesec{uuid.uuid4().hex[:6]}"
            probe_value = marker + payload
            new_qs = {k: v[:] for k, v in qs.items()}
            new_qs[key] = [probe_value]
            probe_url = _rebuild_query(parsed, new_qs)
            try:
                res = fetch(probe_url, timeout)
            except Exception:
                continue
            body = res.body or ""
            if not body or marker not in body:
                continue
            lowered = body.lower()
            if needle.lower() in lowered:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_HIGH,
                        category="XSS (Reflected)",
                        title=f"Unencoded reflection via `{key}` ({ctx} context)",
                        detail=f"Payload `{payload}` survived unencoded in response body.",
                        evidence=body[max(0, body.find(marker) - 40): body.find(marker) + 120],
                        recommendation="Apply context-aware output encoding (HTML, attribute, JS, URL). Prefer framework-native escaping.",
                    )
                )
                reported.add(key)
                break
            if html.escape(probe_value) in body or probe_value.replace("<", "&lt;").replace(">", "&gt;") in body:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_INFO,
                        category="XSS (Reflected)",
                        title=f"Parameter `{key}` reflected and encoded ({ctx} context)",
                        detail="Input is reflected but appears HTML-encoded.",
                    )
                )
                reported.add(key)
                break
    return findings


SQLI_PAYLOAD_SETS = [
    {"suffix": "'", "label": "single-quote"},
    {"suffix": "\"", "label": "double-quote"},
    {"suffix": "')", "label": "paren-break"},
    {"suffix": "\\", "label": "backslash"},
    {"suffix": ";--", "label": "comment"},
]

SQLI_BOOLEAN_PAIRS = [
    (" AND 1=1-- -", " AND 1=2-- -"),
    ("' AND '1'='1", "' AND '1'='2"),
    (") AND 1=1-- -", ") AND 1=2-- -"),
]


def _body_signature(body: str) -> Tuple[int, int]:
    if not body:
        return (0, 0)
    return (len(body), sum(ord(c) for c in body[:512]) & 0xFFFF)


def check_sql_injection(target: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(target)
    qs = parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings

    try:
        baseline_res = fetch(target, timeout)
    except Exception:
        baseline_res = None
    baseline_sig = _body_signature(baseline_res.body if baseline_res else "")
    baseline_status = baseline_res.status if baseline_res else None

    reported: Set[str] = set()

    for key in list(qs.keys()):
        if key in reported:
            continue
        original = qs[key][0] if qs[key] else ""

        error_hit = False
        for payload in SQLI_PAYLOAD_SETS:
            new_qs = {k: v[:] for k, v in qs.items()}
            new_qs[key] = [original + payload["suffix"]]
            try:
                res = fetch(_rebuild_query(parsed, new_qs), timeout)
            except Exception:
                continue
            body_lower = (res.body or "").lower()
            matched = next((pat for pat in SQL_ERROR_PATTERNS if re.search(pat, body_lower)), None)
            if matched:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_HIGH,
                        category="SQL Injection",
                        title=f"Error-based SQLi via `{key}` ({payload['label']})",
                        detail=f"Payload surfaced DB error pattern `{matched}`.",
                        recommendation="Use parameterized queries; never concatenate user input into SQL; return generic 500s.",
                    )
                )
                reported.add(key)
                error_hit = True
                break
        if error_hit:
            continue

        for true_s, false_s in SQLI_BOOLEAN_PAIRS:
            new_qs_t = {k: v[:] for k, v in qs.items()}
            new_qs_f = {k: v[:] for k, v in qs.items()}
            new_qs_t[key] = [original + true_s]
            new_qs_f[key] = [original + false_s]
            try:
                res_t = fetch(_rebuild_query(parsed, new_qs_t), timeout)
                res_f = fetch(_rebuild_query(parsed, new_qs_f), timeout)
            except Exception:
                continue
            sig_t = _body_signature(res_t.body or "")
            sig_f = _body_signature(res_f.body or "")
            if not (res_t.status and res_f.status):
                continue
            len_t, len_f, len_base = sig_t[0], sig_f[0], baseline_sig[0]
            status_t, status_f = res_t.status, res_f.status
            close_to_baseline = abs(len_t - len_base) < max(80, int(len_base * 0.02))
            diff_t_f = abs(len_t - len_f) > max(100, int(max(len_t, len_f) * 0.05))
            status_diff = status_t != status_f and (status_t == 200 or status_f == 200)
            if (close_to_baseline and diff_t_f) or status_diff:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_HIGH,
                        category="SQL Injection",
                        title=f"Boolean-based SQLi suspected via `{key}`",
                        detail=f"TRUE vs FALSE responses diverged (status {status_t}/{status_f}, length {len_t}/{len_f}; baseline {len_base}).",
                        recommendation="Use parameterized queries. Validate data types server-side.",
                    )
                )
                reported.add(key)
                break
    return findings


def check_idor_heuristic(target: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(target)
    path_ids = re.findall(r"/(\d{1,10})(?=/|$)", parsed.path or "")
    qs = parse.parse_qs(parsed.query, keep_blank_values=True)
    qs_int_params = [
        k for k, vs in qs.items()
        if k.lower() in {"id", "user", "user_id", "uid", "account", "account_id", "order", "order_id", "invoice", "invoice_id", "doc", "doc_id", "record", "record_id", "post", "post_id", "notice_id"}
        and vs and any(v.isdigit() for v in vs)
    ]
    if path_ids or qs_int_params:
        details = []
        if path_ids:
            details.append(f"sequential path IDs: {', '.join(path_ids[:5])}")
        if qs_int_params:
            details.append(f"numeric ID query params: {', '.join(qs_int_params)}")
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_LOW,
                category="Access Control",
                title="Sequential integer IDs in URL — possible IDOR vector",
                detail="; ".join(details) + ". Verify server-side ownership checks. Prefer UUIDs.",
                recommendation="Validate resource ownership at the data layer. Return 404 (not 403) when unauthorized to avoid enumeration.",
            )
        )
    return findings


XXE_ECHO_MARKER = "VIBESEC-XXE-CANARY-7731"
XXE_PAYLOAD = (
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE x [<!ENTITY xx \"" + XXE_ECHO_MARKER + "\">]>"
    "<methodCall><methodName>&xx;</methodName></methodCall>"
).encode("utf-8")
XXE_CANDIDATE_PATHS = ["/xmlrpc.php", "/soap", "/api/xml", "/ws", "/ws/", "/services", "/wsdl"]


def check_xxe(base_url: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    reported = False
    for path in XXE_CANDIDATE_PATHS:
        if reported:
            break
        url = root + path
        try:
            res = fetch(url, timeout, method="POST", headers={"Content-Type": "application/xml"}, data=XXE_PAYLOAD)
        except Exception:
            continue
        body = res.body or ""
        if XXE_ECHO_MARKER in body:
            findings.append(
                Finding(
                    target=base_url,
                    severity=SEVERITY_HIGH,
                    category="XXE",
                    title=f"XML entity expansion active at {path}",
                    detail=f"Internal entity echoed back — parser expands DOCTYPE entities. External-entity variants may allow SSRF/file read.",
                    evidence=body[:300],
                    recommendation="Disable DTD processing and external entity resolution (defusedxml / libxml2 NO_NET/NO_EXT).",
                )
            )
            reported = True
    return findings


def fingerprint(target: str, headers: Dict[str, str], cookies: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    tech: List[str] = []
    server = headers.get("server", "")
    xpb = headers.get("x-powered-by", "")
    if server:
        tech.append(f"Server: {server}")
    if xpb:
        tech.append(f"X-Powered-By: {xpb}")
    cookie_names = []
    for raw in cookies:
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw)
            cookie_names.extend(list(jar.keys()))
        except Exception:
            continue
    for name in cookie_names:
        lname = name.lower()
        if "phpsessid" in lname:
            tech.append("PHP session cookie")
        if "jsessionid" in lname:
            tech.append("Java servlet (JSESSIONID)")
        if "asp.net_sessionid" in lname:
            tech.append("ASP.NET session cookie")
        if "laravel_session" in lname:
            tech.append("Laravel framework cookie")
        if "ci_session" in lname:
            tech.append("CodeIgniter session cookie")
        if "connect.sid" in lname:
            tech.append("Express (connect.sid)")
    if tech:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_INFO,
                category="Fingerprint",
                title="Technology fingerprint",
                detail="; ".join(tech),
            )
        )
    return findings


JWT_LEAK_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")


def _decode_jwt(token: str) -> Optional[Tuple[Dict[str, object], Dict[str, object]]]:
    try:
        header_b64, payload_b64, _sig = token.split(".", 2)
        def b64url(s: str) -> bytes:
            pad = "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s + pad)
        header = json.loads(b64url(header_b64).decode("utf-8", errors="replace"))
        payload = json.loads(b64url(payload_b64).decode("utf-8", errors="replace"))
        return header, payload
    except Exception:
        return None


def _audit_jwt(target: str, token: str, where: str) -> List[Finding]:
    out: List[Finding] = []
    decoded = _decode_jwt(token)
    if not decoded:
        return out
    header, payload = decoded
    alg = str(header.get("alg", "")).lower()
    redacted = f"{token[:16]}...{token[-8:]}"

    if alg in {"none", ""}:
        out.append(
            Finding(
                target=target,
                severity=SEVERITY_CRITICAL,
                category="JWT",
                title=f"JWT uses `alg: {alg or 'missing'}` ({where})",
                detail="Any token with `alg: none` is trivially forgeable — full auth bypass if accepted.",
                evidence=redacted,
                recommendation="Server must whitelist the expected algorithm (e.g. `HS256`/`RS256`) and reject `none`.",
            )
        )
    elif alg.startswith("hs") and len(alg) >= 5:
        out.append(
            Finding(
                target=target,
                severity=SEVERITY_MEDIUM,
                category="JWT",
                title=f"JWT uses HMAC `{alg.upper()}` — key-confusion risk ({where})",
                detail="If the server also accepts RS256 without explicit algorithm whitelisting, the public key can be abused as HMAC secret.",
                evidence=redacted,
                recommendation="Pin the expected algorithm on verification; reject any token whose header `alg` differs.",
            )
        )

    if "exp" not in payload:
        out.append(
            Finding(
                target=target,
                severity=SEVERITY_HIGH,
                category="JWT",
                title=f"JWT missing `exp` claim ({where})",
                detail="Token never expires — a leaked token remains valid forever.",
                evidence=redacted,
                recommendation="Always set a short `exp` (minutes–hours) and rotate via refresh tokens.",
            )
        )
    if "iat" not in payload:
        out.append(
            Finding(
                target=target,
                severity=SEVERITY_LOW,
                category="JWT",
                title=f"JWT missing `iat` claim ({where})",
                detail="Without `iat`, token age cannot be validated.",
                evidence=redacted,
            )
        )
    sensitive_payload_keys = [k for k in payload.keys() if any(s in str(k).lower() for s in ("password", "secret", "private", "ssn"))]
    if sensitive_payload_keys:
        out.append(
            Finding(
                target=target,
                severity=SEVERITY_HIGH,
                category="JWT",
                title=f"JWT payload contains sensitive claim(s): {', '.join(sensitive_payload_keys)}",
                detail="JWT payloads are only base64url — they are readable by any holder.",
                evidence=redacted,
                recommendation="Never put passwords/secrets in JWT payloads. Use opaque session IDs with server-side lookup.",
            )
        )
    return out


def detect_jwt_leaks(target: str, body: str, cookies: List[str], headers: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    tokens: List[Tuple[str, str]] = []

    if body:
        m = JWT_LEAK_RE.search(body)
        if m:
            tokens.append((m.group(0), "response body/JS"))

    for cookie in cookies or []:
        m = JWT_LEAK_RE.search(cookie)
        if m:
            tokens.append((m.group(0), "Set-Cookie"))

    for h, v in (headers or {}).items():
        if h.lower() in {"authorization", "x-access-token", "x-auth-token"}:
            m = JWT_LEAK_RE.search(v or "")
            if m:
                tokens.append((m.group(0), f"{h} header"))

    seen_tokens: Set[str] = set()
    for token, where in tokens:
        if token in seen_tokens:
            continue
        seen_tokens.add(token)
        redacted = f"{token[:16]}...{token[-8:]}"
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_HIGH,
                category="Sensitive Exposure",
                title=f"JWT present in client-accessible response ({where})",
                detail="JWTs reachable from JS are XSS-exfiltratable and long-lived if not rotated.",
                evidence=f"jwt: {redacted}",
                recommendation="Store session JWTs in HttpOnly+Secure+SameSite cookies; never in HTML/JS/localStorage.",
            )
        )
        findings.extend(_audit_jwt(target, token, where))
    return findings


def analyze_html(target: str, parsed: parse.ParseResult, body: str) -> Tuple[HTMLAnalyzer, List[Finding]]:
    findings: List[Finding] = []
    analyzer = HTMLAnalyzer()
    try:
        analyzer.feed(body)
    except Exception:
        return analyzer, findings

    if parsed.scheme == "https":
        for res_url in analyzer.external_resources:
            if res_url.lower().startswith("http://"):
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_MEDIUM,
                        category="Mixed Content",
                        title="Insecure resource on HTTPS page",
                        detail=f"Resource loaded over HTTP: {res_url}",
                    )
                )
                break

    page_host = (parsed.hostname or "").lower()
    missing_sri: List[str] = []
    for url_item in list(analyzer.external_scripts) + list(analyzer.external_styles):
        if not url_item:
            continue
        low = url_item.lower()
        if low.startswith(("http://", "https://", "//")):
            host = parse.urlparse("https:" + url_item if low.startswith("//") else url_item).hostname or ""
            if host and host.lower() != page_host:
                if url_item not in getattr(analyzer, "resources_with_integrity", set()):
                    missing_sri.append(url_item)
    if missing_sri:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_LOW,
                category="Supply Chain",
                title=f"Cross-origin resources without Subresource Integrity ({len(missing_sri)})",
                detail="External scripts/styles are loaded from third-party origins without `integrity=` — CDN compromise would ship malicious code directly.",
                evidence="; ".join(missing_sri[:5]),
                recommendation="Add `integrity=\"sha384-...\"` and `crossorigin=\"anonymous\"` to all cross-origin <script>/<link> tags, or self-host.",
            )
        )

    if analyzer.inline_scripts:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_INFO,
                category="CSP",
                title=f"Inline scripts detected ({analyzer.inline_scripts})",
                detail="Inline scripts require `'unsafe-inline'` or nonces/hashes in CSP.",
            )
        )

    for form in analyzer.forms:
        action = form.get("action", "") or target
        method = form.get("method", "get")
        inputs = form.get("inputs", [])
        enctype = form.get("enctype", "")
        has_password = any(i["type"] == "password" for i in inputs)
        has_csrf = any(("csrf" in i["name"]) or ("token" in i["name"]) for i in inputs)
        has_file = any(i["type"] == "file" for i in inputs)
        mass_assign_names = {"role", "is_admin", "admin", "permissions", "permission", "plan", "status", "owner", "account_id", "user_id", "group_id", "is_superuser", "is_staff", "active"}
        hidden_mass_assign = [i["name"] for i in inputs if i["type"] == "hidden" and i["name"] in mass_assign_names]
        form_action_url = parse.urljoin(target, action) if action else target
        action_parsed = parse.urlparse(form_action_url)

        if has_file:
            file_inputs_without_accept = [i["name"] or "(unnamed)" for i in inputs if i["type"] == "file" and not i["accept"]]
            if enctype != "multipart/form-data":
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_LOW,
                        category="File Upload",
                        title="File input without `enctype=multipart/form-data`",
                        detail=f"Form at action `{action or '/'}` has a file input but enctype=`{enctype or 'default'}`.",
                        recommendation="Set `enctype=\"multipart/form-data\"` so binary uploads reach the server intact.",
                    )
                )
            if method == "get":
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_MEDIUM,
                        category="File Upload",
                        title="File upload form uses GET",
                        detail=f"Form at `{action or '/'}` uses GET with a file input.",
                        recommendation="Use POST for uploads and protect with CSRF token + server-side file validation.",
                    )
                )
            if not has_csrf:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_MEDIUM,
                        category="File Upload",
                        title="File upload form missing CSRF token",
                        detail=f"Form at `{action or '/'}` accepts files but has no hidden csrf/token input.",
                        recommendation="Require a CSRF token, validate type/magic-bytes/size server-side, store files outside webroot.",
                    )
                )
            if file_inputs_without_accept:
                findings.append(
                    Finding(
                        target=target,
                        severity=SEVERITY_LOW,
                        category="File Upload",
                        title="File input without `accept=` attribute",
                        detail=f"Inputs lacking type hints: {', '.join(file_inputs_without_accept[:5])}.",
                        recommendation="Set `accept` to restrict the file picker and validate extension + magic bytes on the server.",
                    )
                )

        if hidden_mass_assign:
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_MEDIUM,
                    category="Mass Assignment",
                    title="Privileged field(s) present as hidden input",
                    detail=f"Hidden inputs that can be tampered with: {', '.join(hidden_mass_assign)}.",
                    evidence=f"form action={action or '/'} method={method}",
                    recommendation="Do not accept privilege/ownership fields from request bodies. Whitelist updatable fields server-side.",
                )
            )

        if has_password and action_parsed.scheme == "http":
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_HIGH,
                    category="Authentication",
                    title="Password form posts over HTTP",
                    detail=f"Form action `{form_action_url}` uses HTTP.",
                )
            )
        if method in {"post", "put", "patch", "delete"} and not has_csrf:
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_MEDIUM,
                    category="CSRF",
                    title="Form missing CSRF token",
                    detail=f"`{method.upper()}` form with no hidden csrf/token input (action={action or '/'}).",
                    recommendation="Add a server-validated CSRF token (or per-form token).",
                )
            )
        if has_password:
            autocomplete = form.get("autocomplete", "")
            if autocomplete and autocomplete not in {"off", "new-password"}:
                for i in inputs:
                    if i["type"] == "password" and i["autocomplete"] not in {"off", "new-password", "current-password"}:
                        findings.append(
                            Finding(
                                target=target,
                                severity=SEVERITY_LOW,
                                category="Authentication",
                                title="Password field autocomplete not set",
                                detail="Consider `autocomplete=new-password` for signup and `current-password` for login.",
                            )
                        )
                        break

    return analyzer, findings


EVIDENCE_BYTE_LIMIT = 8192

GIT_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/logs/HEAD",
    "/.git/index",
    "/.git/packed-refs",
    "/.git/objects/info/packs",
    "/.git/info/refs",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/description",
    "/.git/FETCH_HEAD",
    "/.git/ORIG_HEAD",
    "/.git/COMMIT_EDITMSG",
]

GIT_SIGNATURES = {
    "/.git/HEAD": re.compile(r"^\s*ref:\s+refs/", re.IGNORECASE | re.MULTILINE),
    "/.git/config": re.compile(r"\[core\]|repositoryformatversion|bare\s*=", re.IGNORECASE),
    "/.git/logs/HEAD": re.compile(r"^[0-9a-f]{40}\s+[0-9a-f]{40}", re.MULTILINE),
    "/.git/index": re.compile(r"^DIRC"),
    "/.git/packed-refs": re.compile(r"#\s*pack-refs|^[0-9a-f]{40}\s+refs/", re.MULTILINE),
    "/.git/objects/info/packs": re.compile(r"^P\s+pack-[0-9a-f]{40}\.pack", re.MULTILINE),
    "/.git/info/refs": re.compile(r"^[0-9a-f]{40}\s+refs/", re.MULTILINE),
    "/.git/refs/heads/master": re.compile(r"^[0-9a-f]{40}\s*$"),
    "/.git/refs/heads/main": re.compile(r"^[0-9a-f]{40}\s*$"),
}

ENV_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.staging",
    "/.env.backup",
    "/.env.bak",
    "/.env.example",
    "/.env.dist",
    "/.env.prod",
    "/.env.dev",
    "/.env.save",
    "/.env~",
    "/config/.env",
    "/app/.env",
    "/src/.env",
    "/web/.env",
    "/application/.env",
    "/api/.env",
    "/backend/.env",
    "/server/.env",
]

ENV_SENSITIVE_KEY_RE = re.compile(
    r"\b("
    r"DB_[A-Z_]*|DATABASE_[A-Z_]*|"
    r"PASSWORD|PASSWD|PASS|SECRET|APP_KEY|APP_SECRET|"
    r"JWT_[A-Z_]*|MAIL_[A-Z_]*|SMTP_[A-Z_]*|"
    r"AWS_[A-Z_]*|S3_[A-Z_]*|AZURE_[A-Z_]*|GCP_[A-Z_]*|GOOGLE_[A-Z_]*|"
    r"API_KEY|APIKEY|API_SECRET|ACCESS_KEY|ACCESS_TOKEN|AUTH_TOKEN|"
    r"STRIPE_[A-Z_]*|TWILIO_[A-Z_]*|SENDGRID_[A-Z_]*|MAILGUN_[A-Z_]*|"
    r"REDIS_[A-Z_]*|MONGO_[A-Z_]*|POSTGRES_[A-Z_]*|MYSQL_[A-Z_]*|"
    r"ENCRYPTION_[A-Z_]*|PRIVATE_KEY|SECRET_KEY|CLIENT_SECRET|"
    r"BEARER|TOKEN|RECAPTCHA_[A-Z_]*|PUSHER_[A-Z_]*|ALGOLIA_[A-Z_]*|"
    r"FIREBASE_[A-Z_]*|OKTA_[A-Z_]*|OAUTH_[A-Z_]*"
    r")\b",
    re.IGNORECASE,
)

ESCALATION_PATHS = [
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db_backup.sql",
    "/database.sql",
    "/dump.sql",
    "/db.sql",
    "/wp-config.php",
    "/wp-config.php~",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/config.php",
    "/config.php.bak",
    "/config.php~",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/configuration.php",
    "/settings.py",
    "/local_settings.py",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/composer.lock",
    "/package-lock.json",
    "/yarn.lock",
    "/Gemfile.lock",
    "/debug.log",
    "/error.log",
    "/laravel.log",
    "/storage/logs/laravel.log",
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/configprops",
    "/actuator/mappings",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/.htaccess",
    "/.htpasswd",
    "/id_rsa",
    "/id_rsa.pub",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Dockerfile",
    "/.dockerenv",
    "/.vscode/settings.json",
    "/.idea/workspace.xml",
    "/nginx.conf",
    "/httpd.conf",
    "/web.config",
    "/.aws/credentials",
    "/.npmrc",
    "/.pypirc",
    "/credentials.json",
    "/secrets.json",
]

SOFT_404_INDICATORS = [
    "un-athorized",
    "unauthorized access",
    "unauthorized-access",
    "404 not found",
    "page not found",
    "page cannot be found",
    "nothing here",
    "access denied",
    "forbidden access",
    "not permitted",
    "the page you are looking for",
    "sorry, this page",
    "error 404",
    "moved permanently",
]

SUBDOMAIN_WORDLIST = [
    "www",
    "admin",
    "api",
    "app",
    "beta",
    "dev",
    "hr",
    "hrd",
    "portal",
    "staging",
    "stage",
    "test",
    "backup",
    "old",
    "new",
    "git",
    "gitlab",
    "mail",
    "webmail",
    "cpanel",
    "vpn",
    "cms",
    "demo",
]


def is_soft_404(body: str) -> bool:
    if not body:
        return False
    sample = body[:4000].lower()
    return any(s in sample for s in SOFT_404_INDICATORS)


def validate_git_content(path: str, body: str) -> bool:
    sig = GIT_SIGNATURES.get(path)
    if not sig or not body:
        return False
    return bool(sig.search(body[:4000]))


def find_env_secret_keys(body: str) -> List[str]:
    if not body:
        return []
    matched: List[str] = []
    for line in body.splitlines()[:200]:
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, _, val = raw.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if not val:
            continue
        m = ENV_SENSITIVE_KEY_RE.search(key)
        if m:
            matched.append(key)
    seen: Set[str] = set()
    ordered: List[str] = []
    for k in matched:
        if k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered


def redact_env_line(line: str) -> str:
    raw = line.rstrip("\n")
    if "=" not in raw or raw.lstrip().startswith("#"):
        return raw
    key, _, val = raw.partition("=")
    key_clean = key.strip()
    val_clean = val.strip().strip('"').strip("'")
    if ENV_SENSITIVE_KEY_RE.search(key_clean) and val_clean:
        visible = val_clean[:4] if len(val_clean) > 4 else val_clean[:1]
        masked = visible + ("*" * max(3, len(val_clean) - len(visible)))
        return f"{key}={masked}"
    return raw


def fetch_file_content(url: str, timeout: int, redact: bool = False) -> Optional[str]:
    req_headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"}
    req = request.Request(url, headers=req_headers)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            if resp.getcode() != 200:
                return None
            raw = resp.read(EVIDENCE_BYTE_LIMIT)
            text = raw.decode("utf-8", errors="replace")
            if redact:
                text = "\n".join(redact_env_line(l) for l in text.splitlines())
            return text
    except Exception:
        return None


def _base_domain(hostname: str) -> Optional[str]:
    if not hostname or hostname.replace(".", "").isdigit():
        return None
    parts = hostname.split(".")
    if len(parts) < 2:
        return None
    multi_tlds = {"ac.bd", "co.uk", "co.in", "com.bd", "com.pk", "gov.bd", "edu.bd", "org.bd"}
    tail2 = ".".join(parts[-2:])
    tail3 = ".".join(parts[-3:]) if len(parts) >= 3 else ""
    if tail3 and any(tail3.endswith(suf) for suf in multi_tlds) is False and any(tail2 == suf for suf in multi_tlds):
        if len(parts) >= 3:
            return ".".join(parts[-3:])
    return tail2


def probe_git_exposure(base_url: str, timeout: int, fetch_evidence: bool) -> Tuple[List[Finding], bool]:
    findings: List[Finding] = []
    parsed = parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    confirmed = False
    unverified_200 = 0
    for path in GIT_PATHS:
        url = root + path
        res = fetch(url, timeout, allow_redirects=False)
        if res.status != 200:
            continue
        body = res.body or ""
        if is_soft_404(body):
            continue
        if validate_git_content(path, body):
            confirmed = True
            snippet = body[:EVIDENCE_BYTE_LIMIT] if fetch_evidence else (body[:500] if body else None)
            findings.append(
                Finding(
                    target=base_url,
                    severity=SEVERITY_CRITICAL,
                    category="Sensitive Exposure",
                    title=f"Exposed Git repository - full source code + history leak possible ({path})",
                    detail=f"Verified git metadata served at {url}. Attackers can reconstruct the full repository.",
                    evidence=snippet,
                    recommendation="Block `/.git/` at the web server (nginx/Apache). Use git-dumper or GitTools/Dumper to assess impact: https://github.com/arthaud/git-dumper",
                )
            )
        else:
            unverified_200 += 1
    if unverified_200 and not confirmed:
        findings.append(
            Finding(
                target=base_url,
                severity=SEVERITY_INFO,
                category="Discovery",
                title=".git paths return HTTP 200 but content looks like a soft-404",
                detail=f"{unverified_200} `/.git/*` path(s) responded 200 without valid git signatures.",
                recommendation="Still consider returning proper 403/404 for these paths.",
            )
        )
    return findings, confirmed


def probe_env_exposure(base_url: str, timeout: int, fetch_evidence: bool) -> Tuple[List[Finding], bool]:
    findings: List[Finding] = []
    parsed = parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    confirmed = False
    for path in ENV_PATHS:
        url = root + path
        res = fetch(url, timeout, allow_redirects=False)
        if res.status != 200:
            continue
        body = res.body or ""
        if is_soft_404(body) or not body.strip():
            continue
        secret_keys = find_env_secret_keys(body)
        if secret_keys:
            confirmed = True
            snippet_lines = body.splitlines()[:15]
            snippet = "\n".join(redact_env_line(l) for l in snippet_lines)
            findings.append(
                Finding(
                    target=base_url,
                    severity=SEVERITY_CRITICAL,
                    category="Sensitive Exposure",
                    title=f"Exposed environment file with credentials ({path})",
                    detail=f"Sensitive keys detected: {', '.join(secret_keys[:10])}{' …' if len(secret_keys) > 10 else ''}",
                    evidence=snippet,
                    recommendation="Remove file from webroot immediately. Rotate ALL leaked credentials. Block dotfiles at the web server level.",
                )
            )
        elif "=" in body and len(body) < 100_000:
            snippet = body[:800] if fetch_evidence else None
            findings.append(
                Finding(
                    target=base_url,
                    severity=SEVERITY_HIGH,
                    category="Sensitive Exposure",
                    title=f"Exposed environment file ({path})",
                    detail="HTTP 200 with key=value content but no obvious secret keys matched.",
                    evidence=snippet,
                    recommendation="Remove from webroot and verify contents are not sensitive.",
                )
            )
    return findings, confirmed


def probe_escalation_paths(base_url: str, timeout: int, fetch_evidence: bool) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    critical_markers = [
        "wp-config", "id_rsa", "backup.sql", "dump.sql", "database.sql",
        "db_backup.sql", "heapdump", "credentials.json", "secrets.json",
        ".aws/credentials", ".htpasswd",
    ]
    for path in ESCALATION_PATHS:
        url = root + path
        res = fetch(url, timeout, allow_redirects=False)
        if res.status != 200:
            continue
        body = res.body or ""
        if is_soft_404(body):
            continue
        severity = SEVERITY_CRITICAL if any(m in path for m in critical_markers) else SEVERITY_HIGH
        snippet = None
        if fetch_evidence and body:
            if "/.env" in path or path.endswith(".env") or path.endswith(".env~"):
                snippet = "\n".join(redact_env_line(l) for l in body.splitlines()[:15])
            else:
                snippet = body[:800]
        findings.append(
            Finding(
                target=base_url,
                severity=severity,
                category="Sensitive Exposure",
                title=f"Escalation hit: {path}",
                detail=f"HTTP 200 at {url}",
                evidence=snippet,
                recommendation="Block or remove from production.",
            )
        )
    return findings


def probe_subdomain_pivot(base_url: str, timeout: int, fetch_evidence: bool, seen_hosts: Set[str]) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(base_url)
    hostname = parsed.hostname or ""
    base = _base_domain(hostname)
    if not base:
        return findings
    for sub in SUBDOMAIN_WORDLIST:
        host = f"{sub}.{base}"
        if host == hostname or host in seen_hosts:
            continue
        try:
            socket.gethostbyname(host)
        except Exception:
            continue
        seen_hosts.add(host)
        sub_root = f"{parsed.scheme}://{host}"
        for path in ["/.git/HEAD", "/.env"]:
            url = sub_root + path
            res = fetch(url, timeout, allow_redirects=False)
            if res.status != 200:
                continue
            body = res.body or ""
            if is_soft_404(body):
                continue
            if path == "/.git/HEAD" and validate_git_content("/.git/HEAD", body):
                findings.append(
                    Finding(
                        target=base_url,
                        severity=SEVERITY_CRITICAL,
                        category="Sensitive Exposure",
                        title=f"Subdomain pivot: {host} also exposes /.git/HEAD",
                        detail=f"Related host {host} exposes verified git metadata.",
                        evidence=(body[:500] if fetch_evidence else None),
                        recommendation="Audit the entire domain, not just the original target.",
                    )
                )
            elif path == "/.env":
                keys = find_env_secret_keys(body)
                if keys:
                    snippet = "\n".join(redact_env_line(l) for l in body.splitlines()[:15])
                    findings.append(
                        Finding(
                            target=base_url,
                            severity=SEVERITY_CRITICAL,
                            category="Sensitive Exposure",
                            title=f"Subdomain pivot: {host}/.env exposes credentials",
                            detail=f"Keys: {', '.join(keys[:10])}",
                            evidence=snippet,
                            recommendation="Audit the entire domain, rotate credentials.",
                        )
                    )
    return findings


def probe_graphql(endpoint: str, timeout: int) -> List[Finding]:
    findings: List[Finding] = []
    introspection_query = b'{"query":"{__schema{types{name}}}"}'
    try:
        res = fetch(endpoint, timeout, method="POST", headers={"Content-Type": "application/json"}, data=introspection_query)
    except Exception:
        return findings
    body = (res.body or "") if res else ""
    if not body:
        return findings
    lowered = body.lower()
    looks_json = lowered.lstrip().startswith("{") or lowered.lstrip().startswith("[")
    is_graphql_like = looks_json and ("graphql" in lowered or "__schema" in lowered or "errors" in lowered or "__typename" in lowered)
    if not is_graphql_like:
        return findings

    introspection_hit = ('"__schema"' in body) or ('"types"' in body and '"name"' in body)
    if introspection_hit and '"errors"' not in body[:400]:
        findings.append(
            Finding(
                target=endpoint,
                severity=SEVERITY_HIGH,
                category="Sensitive Exposure",
                title="GraphQL introspection enabled",
                detail=f"Introspection query returned schema types from {endpoint}. Maps the full API surface for attackers.",
                evidence=body[:500],
                recommendation="Disable introspection in production (Apollo: `introspection: false`). Enforce query depth and cost limits.",
            )
        )
    else:
        findings.append(
            Finding(
                target=endpoint,
                severity=SEVERITY_INFO,
                category="Discovery",
                title="GraphQL endpoint responds (introspection appears disabled)",
                detail=f"{endpoint} returned GraphQL-style JSON without a full schema.",
                evidence=body[:300],
            )
        )

    depth_query = b'{"query":"{a:__typename b:__typename c:__typename d:__typename e:__typename f:__typename g:__typename h:__typename i:__typename j:__typename k:__typename l:__typename m:__typename n:__typename o:__typename}"}'
    try:
        depth_res = fetch(endpoint, timeout, method="POST", headers={"Content-Type": "application/json"}, data=depth_query)
        depth_body = (depth_res.body or "") if depth_res else ""
        if depth_res.status == 200 and '"data"' in depth_body and '"errors"' not in depth_body[:400]:
            findings.append(
                Finding(
                    target=endpoint,
                    severity=SEVERITY_MEDIUM,
                    category="GraphQL",
                    title="GraphQL accepts wide alias expansion (no cost/complexity limit detected)",
                    detail="Server executed a query with 15 aliases without error; depth/cost attacks may be possible.",
                    evidence=depth_body[:250],
                    recommendation="Implement `depthLimit` and `costAnalysis` (Apollo) or equivalent; cap alias expansion.",
                )
            )
    except Exception:
        pass

    batch_query = b'[' + b",".join([b'{"query":"{__typename}"}'] * 20) + b']'
    try:
        batch_res = fetch(endpoint, timeout, method="POST", headers={"Content-Type": "application/json"}, data=batch_query)
        batch_body = (batch_res.body or "") if batch_res else ""
        if batch_res.status == 200 and batch_body.lstrip().startswith("[") and batch_body.count('"__typename"') >= 5:
            findings.append(
                Finding(
                    target=endpoint,
                    severity=SEVERITY_MEDIUM,
                    category="GraphQL",
                    title="GraphQL batching accepted without limit",
                    detail="Server processed 20 batched operations in a single request — amplifies brute-force/rate-limit bypass.",
                    evidence=batch_body[:250],
                    recommendation="Disable batching or cap operations per request (e.g. maxOperationsPerRequest = 1 for auth endpoints).",
                )
            )
    except Exception:
        pass

    return findings


def probe_common_paths(
    base_url: str,
    timeout: int,
    max_paths: int = 25,
    fetch_evidence: bool = False,
    scan_subdomains: bool = False,
    seen_hosts: Optional[Set[str]] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    parsed = parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    seen_hosts = seen_hosts if seen_hosts is not None else set()

    git_findings, git_confirmed = probe_git_exposure(base_url, timeout, fetch_evidence)
    findings.extend(git_findings)

    env_findings, env_confirmed = probe_env_exposure(base_url, timeout, fetch_evidence)
    findings.extend(env_findings)

    skip_paths = set(GIT_PATHS) | set(ENV_PATHS)
    for path in COMMON_PATHS[:max_paths]:
        if path in skip_paths:
            continue
        url = root + path
        res = fetch(url, timeout, allow_redirects=False)
        if res.status is None:
            continue
        if res.status not in {200, 401, 403}:
            continue
        if res.status == 200 and is_soft_404(res.body or ""):
            continue
        interesting = False
        label = ""
        for kw, kw_label in SENSITIVE_PATH_KEYWORDS.items():
            if kw in path:
                interesting = True
                label = kw_label
                break
        if path.endswith("robots.txt") or path.endswith("security.txt") or path.endswith("sitemap.xml"):
            if res.status == 200 and res.body:
                findings.append(
                    Finding(
                        target=base_url,
                        severity=SEVERITY_INFO,
                        category="Discovery",
                        title=f"{path} found",
                        detail=f"HTTP {res.status} at {url}",
                        evidence=(res.body[:400] if res.body else None),
                    )
                )
                if path.endswith("robots.txt"):
                    disallows: List[str] = []
                    for line in res.body.splitlines()[:200]:
                        stripped = line.strip()
                        if stripped.lower().startswith("disallow:"):
                            val = stripped.split(":", 1)[1].strip()
                            if val and val != "/" and val not in disallows:
                                disallows.append(val)
                    sensitive_hints = [d for d in disallows if any(h in d.lower() for h in ("admin", "login", "config", "backup", "private", "secret", "api", "tmp", "debug", "internal"))]
                    if sensitive_hints:
                        findings.append(
                            Finding(
                                target=base_url,
                                severity=SEVERITY_LOW,
                                category="Discovery",
                                title="robots.txt advertises sensitive paths",
                                detail=f"Disallow entries hint at internal areas: {', '.join(sensitive_hints[:8])}",
                                evidence="\n".join(sensitive_hints[:20]),
                                recommendation="Avoid listing secret paths in robots.txt; require authentication instead.",
                            )
                        )
            continue
        if path.rstrip("/").endswith("graphql") or path.rstrip("/").endswith("graphiql"):
            findings.extend(probe_graphql(url, timeout))
            continue
        content: Optional[str] = None
        if fetch_evidence and res.status == 200 and res.body:
            content = res.body[:EVIDENCE_BYTE_LIMIT]
        if interesting and res.status == 200:
            findings.append(
                Finding(
                    target=base_url,
                    severity=SEVERITY_HIGH,
                    category="Sensitive Exposure",
                    title=label or f"Sensitive path accessible: {path}",
                    detail=f"HTTP {res.status} at {url}",
                    evidence=content,
                    recommendation="Block or remove this resource in production.",
                )
            )
        elif res.status == 200:
            findings.append(
                Finding(
                    target=base_url,
                    severity=SEVERITY_LOW,
                    category="Discovery",
                    title=f"Path reachable: {path}",
                    detail=f"HTTP {res.status} at {url}",
                    evidence=content,
                )
            )

    if git_confirmed or env_confirmed:
        findings.append(
            Finding(
                target=base_url,
                severity=SEVERITY_INFO,
                category="Escalation",
                title="Auto-escalation triggered",
                detail=(
                    "Verified exposure of "
                    + (" & ".join([x for x, ok in [("git", git_confirmed), ("env", env_confirmed)] if ok]))
                    + ". Running extended sensitive-file brute and (optionally) subdomain pivot."
                ),
            )
        )
        findings.extend(probe_escalation_paths(base_url, timeout, fetch_evidence))
        if scan_subdomains:
            findings.extend(probe_subdomain_pivot(base_url, timeout, fetch_evidence, seen_hosts))

    return findings


def tls_findings(target: str, tls: Dict[str, object]) -> List[Finding]:
    findings: List[Finding] = []
    if not tls.get("enabled"):
        if tls.get("error"):
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_MEDIUM,
                    category="TLS",
                    title="TLS handshake failed",
                    detail=str(tls.get("error")),
                )
            )
        return findings
    version = tls.get("version") or ""
    if version in WEAK_TLS_VERSIONS:
        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_HIGH,
                category="TLS",
                title=f"Weak TLS version: {version}",
                detail="Server negotiated a deprecated TLS version.",
                recommendation="Disable SSLv3/TLS1.0/1.1, enable TLS1.2+ with modern ciphers.",
            )
        )
    days = tls.get("days_until_expiry")
    if isinstance(days, int):
        if days < 0:
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_CRITICAL,
                    category="TLS",
                    title="Certificate expired",
                    detail=f"Expired {-days} day(s) ago.",
                )
            )
        elif days < 14:
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_HIGH,
                    category="TLS",
                    title=f"Certificate expires in {days} days",
                    detail="Renew soon to avoid outage and browser warnings.",
                )
            )
        elif days < 30:
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_MEDIUM,
                    category="TLS",
                    title=f"Certificate expires in {days} days",
                    detail="Plan renewal.",
                )
            )
    return findings


DB_PORTS: Dict[int, Tuple[str, str]] = {
    3306: ("MySQL", "MySQL exposed to internet - direct database access possible"),
    5432: ("PostgreSQL", "PostgreSQL exposed to internet - direct database access possible"),
    1433: ("Microsoft SQL Server", "MSSQL exposed to internet - direct database access possible"),
    1521: ("Oracle", "Oracle DB exposed to internet - direct database access possible"),
    27017: ("MongoDB", "MongoDB exposed to internet - direct database access possible"),
    27018: ("MongoDB shard", "MongoDB shard exposed to internet - direct database access possible"),
    6379: ("Redis", "Redis exposed to internet - direct database access possible"),
    9200: ("Elasticsearch", "Elasticsearch exposed to internet - direct index access possible"),
    9300: ("Elasticsearch transport", "Elasticsearch transport port exposed"),
    11211: ("Memcached", "Memcached exposed to internet - cache access possible"),
    5984: ("CouchDB", "CouchDB exposed to internet - direct database access possible"),
    2375: ("Docker daemon", "Docker daemon exposed unauthenticated - full host takeover possible"),
    2376: ("Docker daemon (TLS)", "Docker daemon TLS endpoint exposed"),
}

DEV_PORTS: Dict[int, Tuple[str, str]] = {
    3000: ("Development server", "Development server (Node/React/etc.) exposed - debug endpoints/secrets possible"),
    5000: ("Dev service", "Port 5000 exposed - often Flask/Node dev server"),
    8000: ("Dev service", "Port 8000 exposed - often Django/dev HTTP server"),
    8080: ("Admin/proxy", "Port 8080 exposed - often admin panel/proxy/Jenkins"),
    8081: ("Admin/proxy", "Port 8081 exposed - often admin panel/proxy"),
    8443: ("Alt HTTPS", "Alternate HTTPS port exposed"),
    8888: ("Admin/Jupyter", "Port 8888 exposed - often Jupyter/admin service"),
    9000: ("Admin service", "Port 9000 exposed - often Portainer/SonarQube/PHP-FPM"),
    5601: ("Kibana", "Kibana exposed - Elasticsearch UI possibly reachable"),
    15672: ("RabbitMQ UI", "RabbitMQ management UI port exposed"),
}

PROXY_PORTS: Dict[int, Tuple[str, str]] = {
    3128: ("HTTP proxy (Squid)", "HTTP proxy exposed on 3128 (Squid default) - can be abused for scanning/bypassing restrictions"),
    8118: ("Privoxy", "Privoxy port exposed"),
    1080: ("SOCKS proxy", "SOCKS proxy port exposed"),
}

INFRA_PORTS: Dict[int, Tuple[str, str, str]] = {
    21: (SEVERITY_HIGH, "FTP", "FTP service exposed"),
    22: (SEVERITY_LOW, "SSH", "SSH service exposed"),
    23: (SEVERITY_HIGH, "Telnet", "Telnet exposed - unencrypted"),
    25: (SEVERITY_INFO, "SMTP", "SMTP service exposed"),
    53: (SEVERITY_INFO, "DNS", "DNS service exposed"),
    80: (SEVERITY_INFO, "HTTP", "HTTP service"),
    110: (SEVERITY_LOW, "POP3", "POP3 exposed"),
    143: (SEVERITY_LOW, "IMAP", "IMAP exposed"),
    443: (SEVERITY_INFO, "HTTPS", "HTTPS service"),
    445: (SEVERITY_HIGH, "SMB", "SMB exposed"),
    3389: (SEVERITY_HIGH, "RDP", "RDP exposed"),
}


def banner_grab(host: str, port: int, timeout: int) -> Optional[str]:
    try:
        if port == 3306:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                data = sock.recv(1024)
                if len(data) >= 6 and data[4] in (9, 10):
                    payload = data[5:]
                    end = payload.find(b"\x00")
                    if 0 < end < 200:
                        return f"MySQL {payload[:end].decode('utf-8', errors='replace')}"
                return "MySQL (handshake failed to parse)"
        if port == 6379:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(b"*1\r\n$4\r\nPING\r\n")
                data = sock.recv(256).decode("utf-8", errors="replace").strip()
                if data.startswith("+PONG") or data.startswith("-"):
                    auth_required = data.startswith("-NOAUTH") or "auth" in data.lower()
                    try:
                        sock.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
                        more = sock.recv(4096).decode("utf-8", errors="replace")
                        m = re.search(r"redis_version:([^\r\n]+)", more)
                        if m:
                            return f"Redis {m.group(1)}" + (" (auth required)" if auth_required else " (NO AUTH)")
                    except Exception:
                        pass
                    return "Redis" + (" (auth required)" if auth_required else " (NO AUTH)")
                return None
        if port == 11211:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(b"version\r\n")
                data = sock.recv(256).decode("utf-8", errors="replace").strip()
                m = re.match(r"VERSION\s+(\S+)", data)
                if m:
                    return f"Memcached {m.group(1)}"
                return "Memcached (unparsed response)"
        if port in {9200, 9300}:
            res = fetch(f"http://{host}:{port}/", timeout)
            if res.body:
                try:
                    data = json.loads(res.body)
                    ver = (data.get("version") or {}).get("number")
                    name = data.get("name") or data.get("cluster_name")
                    if ver:
                        return f"Elasticsearch {ver}" + (f" (cluster: {name})" if name else "")
                except Exception:
                    pass
            return "Elasticsearch-like service"
        if port in {2375, 2376}:
            scheme = "https" if port == 2376 else "http"
            res = fetch(f"{scheme}://{host}:{port}/version", timeout)
            if res.body:
                try:
                    data = json.loads(res.body)
                    v = data.get("Version", "?")
                    api = data.get("ApiVersion", "?")
                    return f"Docker API v{v} (ApiVersion {api})"
                except Exception:
                    pass
            return "Docker daemon"
        if port == 5432:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                resp = sock.recv(1)
                if resp == b"S":
                    return "PostgreSQL (SSL offered)"
                if resp == b"N":
                    return "PostgreSQL (plaintext accepted)"
                return "PostgreSQL"
        if port == 1433:
            with socket.create_connection((host, port), timeout=timeout):
                return "Microsoft SQL Server (accepting connections)"
        if port in {27017, 27018}:
            with socket.create_connection((host, port), timeout=timeout):
                return "MongoDB (accepting connections)"
        if port == 5984:
            res = fetch(f"http://{host}:{port}/", timeout)
            if res.body:
                try:
                    data = json.loads(res.body)
                    ver = data.get("version")
                    if ver:
                        return f"CouchDB {ver}"
                except Exception:
                    pass
            return "CouchDB-like service"
        if port in {80, 443, 3000, 3128, 5000, 5601, 8000, 8080, 8081, 8443, 8888, 9000}:
            scheme = "https" if port in {443, 8443} else "http"
            res = fetch(f"{scheme}://{host}:{port}/", timeout)
            server = res.headers.get("server") if res.headers else None
            via = res.headers.get("via") if res.headers else None
            parts = []
            if server:
                parts.append(f"Server: {server}")
            if via:
                parts.append(f"Via: {via}")
            if parts:
                return " | ".join(parts) + (f" (HTTP {res.status})" if res.status else "")
            if res.status:
                return f"HTTP service (status {res.status})"
            return None
        if port == 22:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                data = sock.recv(256).decode("utf-8", errors="replace").strip()
                if data.startswith("SSH-"):
                    return data.splitlines()[0][:120]
            return None
        if port == 21:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                data = sock.recv(256).decode("utf-8", errors="replace").strip()
                return data.splitlines()[0][:120] if data else None
    except Exception:
        return None
    return None


def port_findings(target: str, hostname: str, timeout: int, extra_ports: List[int]) -> Tuple[List[int], List[Finding]]:
    findings: List[Finding] = []
    base_ports = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 465, 587, 993, 995, 1080, 1433, 1521, 1883, 2049, 2375, 2376, 3000, 3128, 3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6667, 8000, 8080, 8081, 8086, 8118, 8443, 8888, 9000, 9092, 9200, 9300, 11211, 15672, 27017, 27018]
    ports = sorted(set(base_ports + extra_ports))
    open_ports: List[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        future_to_port = {pool.submit(check_port, hostname, p, min(timeout, 3)): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    open_ports.sort()

    for port in open_ports:
        banner = banner_grab(hostname, port, min(timeout, 4))
        banner_suffix = f" Banner: {banner}" if banner else ""

        if port in DB_PORTS:
            label, title = DB_PORTS[port]
            severity = SEVERITY_CRITICAL if banner else SEVERITY_HIGH
            findings.append(
                Finding(
                    target=target,
                    severity=severity,
                    category="Critical Exposure",
                    title=title,
                    detail=f"{label} reachable on {hostname}:{port} from scanner.{banner_suffix}",
                    evidence=banner,
                    recommendation="Block this port with firewall. Never expose databases directly to the internet.",
                )
            )
            continue

        if port in PROXY_PORTS:
            label, title = PROXY_PORTS[port]
            is_squid = bool(banner and "squid" in banner.lower())
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_HIGH,
                    category="Critical Exposure",
                    title=title + (" (Squid detected - version disclosed)" if is_squid else ""),
                    detail=f"HTTP proxy on {hostname}:{port}. Open proxy risk - can be abused for scanning or bypassing restrictions.{banner_suffix}",
                    evidence=banner,
                    recommendation="Require authentication and restrict proxy to internal clients, or take it offline.",
                )
            )
            continue

        if port in DEV_PORTS:
            label, title = DEV_PORTS[port]
            findings.append(
                Finding(
                    target=target,
                    severity=SEVERITY_HIGH,
                    category="Exposed Service",
                    title=title,
                    detail=f"{label} reachable on {hostname}:{port}.{banner_suffix}",
                    evidence=banner,
                    recommendation="Confirm hardening/auth. Restrict to trusted networks for dev/admin endpoints.",
                )
            )
            continue

        if port in INFRA_PORTS:
            sev, label, title = INFRA_PORTS[port]
            findings.append(
                Finding(
                    target=target,
                    severity=sev,
                    category="Exposed Service",
                    title=f"{title} (port {port})",
                    detail=f"{label} reachable on {hostname}:{port}.{banner_suffix}",
                    evidence=banner,
                    recommendation="Restrict exposure via firewall/ACL or bind to localhost.",
                )
            )
            continue

        findings.append(
            Finding(
                target=target,
                severity=SEVERITY_INFO,
                category="Exposed Service",
                title=f"Port {port} reachable",
                detail=f"{hostname}:{port} is reachable from scanner.{banner_suffix}",
                evidence=banner,
                recommendation="Restrict exposure if not required.",
            )
        )

    return open_ports, findings


CRITICAL_EXPOSURE_TITLE_MARKERS = [
    "Exposed Git repository",
    "environment file with credentials",
    "MySQL exposed to internet",
    "PostgreSQL exposed to internet",
    "MSSQL exposed to internet",
    "Oracle DB exposed to internet",
    "MongoDB exposed",
    "Redis exposed",
    "Elasticsearch exposed",
    "CouchDB exposed",
    "Memcached exposed",
    "Docker daemon exposed",
    "wp-config",
    "id_rsa",
    "backup.sql",
    "heapdump",
    "credentials.json",
    "Open proxy",
    "HTTP proxy exposed",
    "Escalation hit",
    "PHP info",
    "phpinfo",
]


def promote_critical_exposure(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        if f.severity in (SEVERITY_CRITICAL, SEVERITY_HIGH) and f.category != "Critical Exposure":
            title = (f.title or "").lower()
            if any(m.lower() in title for m in CRITICAL_EXPOSURE_TITLE_MARKERS):
                f.category = "Critical Exposure"
    return findings


def analyze_target(target: str, timeout: int, do_ports: bool, do_paths: bool, active_probes: bool, extra_ports: List[int], fetch_evidence: bool = False, scan_subdomains: bool = False) -> Dict[str, object]:
    findings: List[Finding] = []
    normalized = normalize_url(target)
    parsed = parse.urlparse(normalized)
    hostname = parsed.hostname
    if not parsed.scheme or not hostname:
        findings.append(
            Finding(target=target, severity=SEVERITY_HIGH, category="Input", title="Invalid URL", detail="Could not parse target.")
        )
        return {"target": target, "findings": [asdict(f) for f in findings]}

    resolved_ip = resolve_host(hostname)

    if parsed.scheme == "http":
        findings.append(
            Finding(
                target=normalized,
                severity=SEVERITY_HIGH,
                category="Transport",
                title="Plaintext HTTP in use",
                detail="Endpoint does not enforce HTTPS.",
                recommendation="Redirect all traffic to HTTPS and enable HSTS.",
            )
        )

    res = fetch(normalized, timeout)
    tls_info: Dict[str, object] = {"enabled": False}
    if parsed.scheme == "https":
        tls_info = check_tls(hostname, parsed.port or 443, timeout)
        findings.extend(tls_findings(normalized, tls_info))

    if res.status is None and res.error:
        findings.append(
            Finding(
                target=normalized,
                severity=SEVERITY_MEDIUM,
                category="Network",
                title="Fetch failed",
                detail=res.error,
            )
        )
    else:
        if res.status and res.status >= 500:
            findings.append(
                Finding(target=normalized, severity=SEVERITY_MEDIUM, category="Errors", title=f"Server error {res.status}", detail="Endpoint returning 5xx.")
            )
        findings.extend(check_headers(normalized, parsed, res))
        findings.extend(analyze_cookies(res.set_cookies, normalized))
        findings.extend(fingerprint(normalized, res.headers, res.set_cookies))
        findings.extend(check_allowed_methods(normalized, timeout))
        findings.extend(check_cors(normalized, timeout))
        findings.extend(check_redirects(normalized, timeout))
        if res.body:
            _analyzer, html_findings = analyze_html(normalized, parsed, res.body)
            findings.extend(html_findings)
        findings.extend(detect_jwt_leaks(normalized, res.body or "", res.set_cookies, res.headers))

    if parsed.query or parsed.path:
        findings.extend(check_idor_heuristic(normalized))

    if parsed.query:
        findings.extend(check_ssrf_parameters(normalized))

    if do_paths and parsed.scheme in {"http", "https"}:
        findings.extend(
            probe_common_paths(
                normalized,
                timeout,
                fetch_evidence=fetch_evidence,
                scan_subdomains=scan_subdomains,
            )
        )

    if active_probes and parsed.query:
        findings.extend(check_open_redirect_params(normalized, timeout))
        findings.extend(check_reflection_xss(normalized, timeout))
        findings.extend(check_sql_injection(normalized, timeout))
        findings.extend(check_path_traversal(normalized, timeout))
        findings.extend(check_ssti(normalized, timeout))

    if active_probes and parsed.scheme in {"http", "https"}:
        findings.extend(check_xxe(normalized, timeout))

    open_ports: List[int] = []
    if do_ports and hostname:
        open_ports, port_f = port_findings(normalized, hostname, timeout, extra_ports)
        findings.extend(port_f)

    promote_critical_exposure(findings)

    return {
        "target": target,
        "normalized_url": normalized,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "http_status": res.status,
        "final_url": res.final_url,
        "tls": tls_info,
        "open_ports": open_ports,
        "findings": [asdict(f) for f in findings],
    }


def cross_target_pivot(results: List[Dict[str, object]], timeout: int, fetch_evidence: bool) -> int:
    high_hosts: Set[str] = set()
    high_ip_prefixes: Set[str] = set()
    high_base_domains: Set[str] = set()

    trigger_markers = [
        "Exposed Git repository",
        "environment file with credentials",
        "MySQL exposed",
        "PostgreSQL exposed",
        "MSSQL exposed",
        "Oracle DB exposed",
        "MongoDB exposed",
        "Redis exposed",
        "Elasticsearch exposed",
        "CouchDB exposed",
        "Memcached exposed",
        "Docker daemon exposed",
        "phpinfo",
        "PHP info",
        "HTTP proxy exposed",
        "Open proxy",
    ]

    for r in results:
        host = (r.get("hostname") or "") if isinstance(r.get("hostname"), str) else ""
        ip = (r.get("resolved_ip") or "") if isinstance(r.get("resolved_ip"), str) else ""
        findings = r.get("findings") or []
        triggered = False
        for f in findings:
            title = (f.get("title") or "") if isinstance(f, dict) else ""
            if any(m.lower() in title.lower() for m in trigger_markers):
                triggered = True
                break
        if triggered:
            if host:
                high_hosts.add(host)
            if ip and "." in ip:
                high_ip_prefixes.add(".".join(ip.split(".")[:3]))
            bd = _base_domain(host) if host else None
            if bd:
                high_base_domains.add(bd)

    if not high_hosts and not high_ip_prefixes and not high_base_domains:
        return 0

    pivot_additions = 0
    already_pivoted: Set[str] = set()

    for r in results:
        host = (r.get("hostname") or "") if isinstance(r.get("hostname"), str) else ""
        ip = (r.get("resolved_ip") or "") if isinstance(r.get("resolved_ip"), str) else ""
        url = r.get("normalized_url")
        if not url or not isinstance(url, str):
            continue
        if host in high_hosts or host in already_pivoted:
            continue
        ip_prefix = ".".join(ip.split(".")[:3]) if ip and "." in ip else None
        bd = _base_domain(host) if host else None
        same_network = bool(ip_prefix and ip_prefix in high_ip_prefixes)
        same_domain = bool(bd and bd in high_base_domains)
        if not (same_network or same_domain):
            continue

        already_pivoted.add(host)
        extra: List[Finding] = []
        try:
            gf, _ = probe_git_exposure(url, timeout, fetch_evidence)
            extra.extend(gf)
            ef, _ = probe_env_exposure(url, timeout, fetch_evidence)
            extra.extend(ef)
            extra.extend(probe_escalation_paths(url, timeout, fetch_evidence))
        except Exception:
            continue

        pivot_reason_bits = []
        if same_network and ip_prefix:
            pivot_reason_bits.append(f"same /24 network ({ip_prefix}.0/24)")
        if same_domain and bd:
            pivot_reason_bits.append(f"same base domain ({bd})")
        reason = " & ".join(pivot_reason_bits) if pivot_reason_bits else "related host"

        tagged: List[Finding] = []
        for f in extra:
            f.category = "Cross-target Pivot"
            f.title = f"[pivot] {f.title}"
            f.detail = f"{f.detail}\nPivot reason: {reason}"
            tagged.append(f)

        if tagged:
            promote_critical_exposure(tagged)
            pivot_additions += len(tagged)
            r_findings = r.get("findings")
            if not isinstance(r_findings, list):
                r_findings = []
                r["findings"] = r_findings
            for f in tagged:
                r_findings.append(asdict(f))

    return pivot_additions


def summarize(results: List[Dict[str, object]]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for f in r.get("findings", []):
            sev = f.get("severity", SEVERITY_INFO)
            if sev in counts:
                counts[sev] += 1
    return counts


def parse_targets(args) -> List[str]:
    targets = list(args.target or [])
    if args.targets_file:
        with open(args.targets_file, "r", encoding="utf-8") as f:
            for line in f:
                v = line.strip()
                if v and not v.startswith("#"):
                    targets.append(v)
    seen: Set[str] = set()
    ordered: List[str] = []
    for t in targets:
        if t not in seen:
            ordered.append(t)
            seen.add(t)
    return ordered


def render_text_report(results: List[Dict[str, object]], totals: Dict[str, int], elapsed: float) -> str:
    lines: List[str] = []
    lines.append("=== Security Scanner Security Report ===")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Elapsed: {elapsed}s")
    lines.append("")
    lines.append("Findings summary:")
    for sev in SEVERITY_ORDER:
        lines.append(f"  {sev.upper():>8}: {totals[sev]}")
    lines.append("")
    for r in results:
        lines.append(f"Target: {r.get('target')}")
        lines.append(f"  URL:     {r.get('normalized_url')}")
        lines.append(f"  Host:    {r.get('hostname')} ({r.get('resolved_ip')})")
        lines.append(f"  Status:  {r.get('http_status')}")
        tls = r.get("tls") or {}
        if tls.get("enabled"):
            lines.append(f"  TLS:     {tls.get('version')} exp={tls.get('not_after')} days_left={tls.get('days_until_expiry')}")
        ports = r.get("open_ports") or []
        if ports:
            lines.append(f"  Ports:   {ports}")
        findings = sorted(r.get("findings", []), key=lambda x: SEVERITY_ORDER.index(x.get("severity", SEVERITY_INFO)))
        if not findings:
            lines.append("  - No findings.")
        else:
            for f in findings:
                sev = f.get("severity", "info").upper()
                cat = f.get("category", "")
                lines.append(f"  - [{sev}] [{cat}] {f.get('title')}: {f.get('detail')}")
                if f.get("evidence"):
                    ev = str(f.get("evidence"))[:180]
                    lines.append(f"      evidence: {ev}")
                if f.get("recommendation"):
                    lines.append(f"      fix: {f.get('recommendation')}")
        lines.append("")
    return "\n".join(lines)


def render_html_report(results: List[Dict[str, object]], totals: Dict[str, int], elapsed: float) -> str:
    sev_color = {
        SEVERITY_CRITICAL: "#7a0012",
        SEVERITY_HIGH: "#c0392b",
        SEVERITY_MEDIUM: "#d68910",
        SEVERITY_LOW: "#1f6feb",
        SEVERITY_INFO: "#6c757d",
    }
    rows = []
    for r in results:
        target_html = html.escape(str(r.get("target")))
        hostname = html.escape(str(r.get("hostname")))
        ip = html.escape(str(r.get("resolved_ip")))
        status = html.escape(str(r.get("http_status")))
        tls = r.get("tls") or {}
        tls_line = ""
        if tls.get("enabled"):
            tls_line = html.escape(f"{tls.get('version')} | exp {tls.get('not_after')} | days left {tls.get('days_until_expiry')}")
        ports = r.get("open_ports") or []
        ports_line = html.escape(", ".join(str(p) for p in ports))
        findings = sorted(r.get("findings", []), key=lambda x: SEVERITY_ORDER.index(x.get("severity", SEVERITY_INFO)))
        fbody = []
        for f in findings:
            sev = f.get("severity", "info")
            color = sev_color.get(sev, "#6c757d")
            fbody.append(
                f"<tr>"
                f"<td style='background:{color};color:#fff;padding:4px 8px;font-weight:600'>{html.escape(sev.upper())}</td>"
                f"<td style='padding:4px 8px'>{html.escape(str(f.get('category','')))}</td>"
                f"<td style='padding:4px 8px'><strong>{html.escape(str(f.get('title','')))}</strong><br>{html.escape(str(f.get('detail','')))}"
                + (f"<br><em>evidence:</em> <code>{html.escape(str(f.get('evidence'))[:300])}</code>" if f.get('evidence') else "")
                + (f"<br><em>fix:</em> {html.escape(str(f.get('recommendation')))}" if f.get('recommendation') else "")
                + "</td></tr>"
            )
        rows.append(
            f"<section style='margin:24px 0;padding:16px;border:1px solid #ddd;border-radius:8px'>"
            f"<h2 style='margin:0 0 8px 0'>{target_html}</h2>"
            f"<p style='margin:4px 0;color:#555'>Host {hostname} ({ip}) | HTTP {status} | TLS {tls_line}"
            + (f" | Open ports: {ports_line}" if ports_line else "")
            + "</p>"
            + (f"<table style='width:100%;border-collapse:collapse;border:1px solid #eee'>{''.join(fbody)}</table>" if fbody else "<p><em>No findings.</em></p>")
            + "</section>"
        )

    summary_html = "".join(
        f"<span style='display:inline-block;margin-right:8px;padding:4px 10px;border-radius:12px;background:{sev_color[s]};color:#fff;font-weight:600'>{s.upper()}: {totals[s]}</span>"
        for s in SEVERITY_ORDER
    )

    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Security Scanner Report</title></head>
<body style='font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:1100px;margin:40px auto;padding:0 16px'>
<h1>Security Scanner Security Report</h1>
<p>Generated {html.escape(datetime.now(timezone.utc).isoformat())} in {elapsed}s</p>
<div>{summary_html}</div>
{''.join(rows)}
</body></html>"""


def main():
    parser = argparse.ArgumentParser(description="Security Scanner advanced passive security checker (authorized use only).")
    parser.add_argument("--target", action="append", help="Target URL; repeatable.")
    parser.add_argument("--targets-file", help="File with one target URL per line.")
    parser.add_argument("--timeout", type=int, default=8, help="Per-request timeout in seconds.")
    parser.add_argument("--concurrency", type=int, default=6, help="Parallel target workers.")
    parser.add_argument("--check-ports", action="store_true", help="Probe common TCP ports on host.")
    parser.add_argument("--extra-ports", default="", help="Comma-separated extra ports to probe.")
    parser.add_argument("--check-paths", action="store_true", help="Probe common sensitive paths on host.")
    parser.add_argument("--fetch-evidence", action="store_true", help="Fetch and display content of confirmed sensitive exposures (requires --check-paths).")
    parser.add_argument("--scan-subdomains", action="store_true", help="On confirmed .git/.env exposure, probe common subdomains for the same leaks.")
    parser.add_argument("--active", action="store_true", help="Enable active safe probes (XSS reflection, SQL error, open redirect).")
    parser.add_argument("--output-json", help="Write JSON report to file.")
    parser.add_argument("--output-html", help="Write HTML report to file.")
    parser.add_argument("--quiet", action="store_true", help="Suppress stdout findings (still writes reports).")
    args = parser.parse_args()

    targets = parse_targets(args)
    if not targets:
        print("No targets provided. Use --target or --targets-file.")
        sys.exit(1)

    extra_ports: List[int] = []
    if args.extra_ports:
        for p in args.extra_ports.split(","):
            p = p.strip()
            if p.isdigit():
                extra_ports.append(int(p))

    print("Scanner starting...")
    if args.active:
        print("Active safe probes ENABLED (XSS reflection / SQL error / open redirect).")
    if getattr(args, "fetch_evidence", False):
        print("Evidence fetch ENABLED — sensitive file contents will be captured.")
    print(f"Targets: {len(targets)} | timeout={args.timeout}s | concurrency={args.concurrency}")

    do_fetch_evidence = getattr(args, "fetch_evidence", False)
    do_subdomain_pivot = getattr(args, "scan_subdomains", False)

    started = time.time()
    results: List[Dict[str, object]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = {
            pool.submit(analyze_target, t, args.timeout, args.check_ports, args.check_paths, args.active, extra_ports, do_fetch_evidence, do_subdomain_pivot): t
            for t in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({"target": futures[fut], "findings": [{"severity": SEVERITY_MEDIUM, "category": "Runner", "title": "Analysis crashed", "detail": str(exc)}]})

    results.sort(key=lambda r: targets.index(r.get("target")) if r.get("target") in targets else 999)

    pivot_count = cross_target_pivot(results, args.timeout, do_fetch_evidence)
    if pivot_count:
        print(f"Cross-target pivot added {pivot_count} findings on related hosts.")

    totals = summarize(results)
    elapsed = round(time.time() - started, 2)

    text_report = render_text_report(results, totals, elapsed)
    if not args.quiet:
        print("")
        print(text_report)

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump({"summary": totals, "results": results, "generated_at_epoch": int(time.time())}, f, indent=2)
        print(f"JSON report: {args.output_json}")
    if args.output_html:
        with open(args.output_html, "w", encoding="utf-8") as f:
            f.write(render_html_report(results, totals, elapsed))
        print(f"HTML report: {args.output_html}")


if __name__ == "__main__":
    main()
