# Web Surface Scanner
A web security scanner that checks targets for common vulnerabilities and exposures, then generates clean, actionable reports.

## Features

| Feature / Skill Area | Status | Notes |
|---|---|---|
| Access Control / IDOR heuristic | Covered | Flags sequential integer IDs in URL path and ID-like query params as IDOR vectors |
| Mass Assignment | Covered | Detects privileged hidden inputs (`role`, `is_admin`, `permissions`, `owner`, `account_id`, …) in forms |
| XSS (reflected) | Covered | Multi-context payloads: HTML body, attribute, JS string, JS template, URL/`javascript:` |
| Content Security Policy (CSP) | Covered | Flags `unsafe-inline`, `unsafe-eval`, missing directives, no reporting endpoint |
| CSRF — cookie flags | Covered | `Secure`, `HttpOnly`, `SameSite` on session cookies |
| CSRF — form token heuristic | Covered | POST/PUT/PATCH/DELETE forms without hidden `csrf`/`token` input flagged |
| Open Redirect | Covered | 10-payload bypass pack (`@`, `//`, `\`, `%2F%2F`, `javascript:`, `data:`, `169.254.169.254`, IDN) |
| Secrets — `.env` deep detection | Covered | Content-validated, credentials highlighted, values redacted in evidence |
| Secrets — `.git` deep detection | Covered | Signature-validated metadata, escalation to full-repo brute |
| Auto-escalation (sensitive-file brute) | Covered | Extended path list triggered on confirmed `.git`/`.env` |
| Subdomain pivot | Covered | Probes common subdomains of the base domain on confirmed leak |
| Cross-target pivot | Covered | Re-runs sensitive-path checks on siblings sharing `/24` IP or base domain |
| Critical Exposure category | Covered | Auto-promotes qualifying findings (DB, Git, env-creds, phpinfo, proxy, backups) |
| Password security (transport + form) | Covered | HTTPS enforcement on password forms, `autocomplete` audit, cookie prefix audit |
| SSRF — parameter heuristic | Covered | Detects URL-accepting params (`url`, `next`, `redirect`, `callback`, `webhook`, `feed`, `uri`, `image`, …) |
| SSRF — cloud metadata via open redirect | Covered | Redirects landing on `169.254.169.254` marked CRITICAL |
| File Upload validation | Covered | Flags missing `multipart/form-data`, GET uploads, missing CSRF, missing `accept=` filter |
| SQL Injection — error-based | Covered | Expanded DB error patterns (MySQL, MariaDB, Postgres, MSSQL, Oracle, SQLite, DB2, Sybase, Informix) |
| SQL Injection — boolean-based | Covered | Compares response status/length between TRUE/FALSE injections against baseline |
| XML External Entity (XXE) | Covered | Echo-based probe on `/xmlrpc.php`, `/soap`, `/api/xml`, `/ws`, `/services`, `/wsdl` with canary entity |
| Path Traversal | Covered | Active probe on file-like params; OS-file signatures (`root:x:0:0:`, Windows `win.ini`) |
| Server-Side Template Injection (SSTI) | Covered | `{{7*7}}`, `${7*7}`, `<%=7*7%>`, `#{7*7}` with marker verification |
| Security Headers | Covered | HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP, Cache-Control |
| JWT exposure | Covered | Scans response body, `Set-Cookie`, and auth headers for `eyJ...` tokens |
| JWT runtime audit | Covered | Decodes and flags `alg:none`, HMAC confusion risk, missing `exp`/`iat`, sensitive claims in payload |
| GraphQL introspection | Covered | POSTs `{__schema{types{name}}}` to `/graphql`/`/graphiql` |
| GraphQL depth / cost limits | Covered | Sends 15-alias query to detect missing depth/cost limiting |
| GraphQL batching limits | Covered | Sends 20-operation batch to detect missing batching limits |
| CORS | Covered (strong) | Wildcard with credentials & reflected-origin checks |
| Cookie security — flags | Covered | `Secure` / `HttpOnly` / `SameSite` on sensitive cookies |
| Cookie security — name prefix | Covered | Flags sensitive cookies missing `__Host-` / `__Secure-` prefix |
| Subresource Integrity (SRI) | Covered | Flags cross-origin `<script>`/`<link>` without `integrity=` |
| Clickjacking protection | Covered | X-Frame-Options and CSP `frame-ancestors` |
| Mixed Content | Covered | HTTP assets on HTTPS pages |
| Inline scripts & styles | Covered | Reported for CSP hardening guidance |
| `robots.txt` disclosure | Covered | Parses `Disallow:` entries to surface internal paths |
| `sitemap.xml` discovery | Covered | Reported when reachable |
| `.well-known/security.txt` | Covered | Reported as informational discovery |
| TLS / SSL | Covered | Protocol version, cipher, certificate expiry days |
| TCP port scan | Covered | Common + user-provided ports with concurrent scanning |
| Banner grabbing | Covered | MySQL, PostgreSQL, Redis, Memcached, Elasticsearch, Docker, CouchDB, SSH, FTP, HTTP `Server`/`Via` |
| Database exposure | Covered | MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, Memcached, CouchDB, Docker — banner ⇒ CRITICAL |
| Dev / admin service exposure | Covered | Ports 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 5601 explicitly labeled |
| Open proxy detection | Covered | 3128 Squid + 8118 Privoxy + 1080 SOCKS with version disclosure |
| Infrastructure ports (SSH/FTP/Telnet/SMB/RDP) | Covered | Severity-weighted per service |
| HTTP method audit | Covered | OPTIONS probe flags risky verbs (`PUT`, `DELETE`, `TRACE`) |
| Redirect chain inspection | Covered | Flags insecure HTTP intermediate hops |
| Tech fingerprinting | Covered | From `Server`, `X-Powered-By`, cookie names |
| HTML analysis | Covered (strong) | Forms, external resources, inline scripts, `integrity=` tracking |
| Soft-404 detection | Covered | Avoids false positives on custom 200-OK error pages |
| Evidence capture with redaction | Covered | Up to 8 KB per hit; `.env` values masked |
| Web UI scan console | Covered | Submission form, live progress, per-category JSON dumps, scan history |
| CLI reports | Covered | Text, JSON, HTML output |
| Concurrency & timeouts | Covered | Tunable via `--concurrency`, `--timeout`, `--extra-ports` |


## How to use

### 1) Run with Web UI

```bash
python3 web_server.py
```

Open `http://127.0.0.1:8765`, add targets (one per line), choose options, and start scan.

### 2) Run with CLI

```bash
python3 security_test_runner.py \
  --target https://example.com \
  --check-paths --check-ports --active \
  --output-json report.json \
  --output-html report.html
```

### 3) Use targets file

Put one target per line in `targets.txt`, then run:

Example `targets.txt`:

```txt
https://example.com
https://api.example.com
http://10.0.0.15:8080
```

```bash
python3 security_test_runner.py --targets-file targets.txt --check-paths --output-json report.json
```

Only scan systems you are authorized to test.

Built by Salman
