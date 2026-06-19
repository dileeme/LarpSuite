"""
Scanner Tab — passive analysis of proxied history for common vulnerabilities.
Checks: missing security headers, cookie flags, sensitive data in responses,
        potential injection indicators, open redirects, information disclosure.
"""

import re
import threading
import tkinter as tk
from tkinter import ttk

from core.history import history, HistoryEntry


# ── Passive checks ────────────────────────────────────────────────────────────

def _check_entry(entry: HistoryEntry) -> list[dict]:
    findings = []
    req  = entry.request
    resp = entry.response

    # --- Request checks ---
    _chk_sensitive_params(req, findings, entry)

    if resp is None:
        return findings

    # --- Response checks ---
    _chk_missing_headers(resp, findings, entry)
    _chk_cookie_flags(resp, findings, entry)
    _chk_info_disclosure(resp, findings, entry)
    _chk_error_pages(resp, findings, entry)
    _chk_cors(resp, findings, entry)

    return findings


def _chk_sensitive_params(req, findings, entry):
    sensitive_keys = re.compile(
        r"(password|passwd|pwd|secret|token|api_key|apikey|credit_card|cvv|ssn|pan)", re.I
    )
    for key in req.params():
        if sensitive_keys.search(key):
            findings.append({
                "severity": "HIGH",
                "issue":    "Sensitive parameter in URL",
                "detail":   f"Parameter '{key}' in GET request URL — use POST/body instead",
                "url":      req.url,
                "id":       entry.id,
            })

    # Check for JWT in URL
    if re.search(r"(jwt|token)=[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", req.path):
        findings.append({
            "severity": "MEDIUM",
            "issue":    "JWT in URL",
            "detail":   "JWT token passed as query parameter — tokens in URLs are logged by servers and proxies",
            "url":      req.url,
            "id":       entry.id,
        })


def _chk_missing_headers(resp, findings, entry):
    req = entry.request
    h   = {k.lower(): v for k, v in resp.headers.items()}

    checks = [
        ("x-frame-options",           "MEDIUM", "Missing X-Frame-Options", "Clickjacking risk"),
        ("x-content-type-options",    "LOW",    "Missing X-Content-Type-Options", "MIME sniffing possible"),
        ("strict-transport-security", "MEDIUM", "Missing HSTS",            "Downgrade attacks possible"),
        ("content-security-policy",   "MEDIUM", "Missing Content-Security-Policy", "XSS mitigation absent"),
        ("x-xss-protection",          "LOW",    "Missing X-XSS-Protection", "Legacy header absent"),
    ]
    for header, sev, issue, detail in checks:
        if header not in h:
            findings.append({
                "severity": sev,
                "issue":    issue,
                "detail":   detail,
                "url":      req.url,
                "id":       entry.id,
            })

    # Check for Server version disclosure
    if "server" in h:
        findings.append({
            "severity": "INFO",
            "issue":    "Server version disclosed",
            "detail":   f"Server: {h['server']}",
            "url":      req.url,
            "id":       entry.id,
        })


def _chk_cookie_flags(resp, findings, entry):
    req = entry.request
    set_cookie = resp.headers.get("Set-Cookie", "") or resp.headers.get("set-cookie", "")
    if not set_cookie:
        return
    flags = set_cookie.lower()
    if "httponly" not in flags:
        findings.append({
            "severity": "MEDIUM",
            "issue":    "Cookie missing HttpOnly flag",
            "detail":   f"Set-Cookie: {set_cookie[:120]}",
            "url":      req.url,
            "id":       entry.id,
        })
    if entry.request.is_https and "secure" not in flags:
        findings.append({
            "severity": "MEDIUM",
            "issue":    "Cookie missing Secure flag",
            "detail":   f"Set-Cookie: {set_cookie[:120]}",
            "url":      req.url,
            "id":       entry.id,
        })
    if "samesite" not in flags:
        findings.append({
            "severity": "LOW",
            "issue":    "Cookie missing SameSite attribute",
            "detail":   f"Set-Cookie: {set_cookie[:120]}",
            "url":      req.url,
            "id":       entry.id,
        })


def _chk_info_disclosure(resp, findings, entry):
    req  = entry.request
    body = resp.body_text()

    patterns = [
        (r"stack\s*trace|traceback\s*\(most recent call", "HIGH",  "Stack trace in response"),
        (r"ORA-\d{5}|MySQL.*error|PostgreSQL.*ERROR|sqlite.*error",
                                                          "HIGH",  "Database error in response"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",       "CRITICAL","Private key in response"),
        (r"[A-Za-z0-9+/]{40,}={0,2}",                    None,    None),   # skip generic b64
        (r"(password|passwd|pwd)\s*[:=]\s*\S+",           "HIGH",  "Password in response body"),
        (r"AWS_SECRET_ACCESS_KEY|AKIA[0-9A-Z]{16}",       "CRITICAL","AWS credentials in response"),
        (r"<\?xml version",                               "INFO",  "XML response (check for XXE)"),
    ]
    for pat, sev, issue in patterns:
        if sev is None:
            continue
        if re.search(pat, body, re.I):
            findings.append({
                "severity": sev,
                "issue":    issue,
                "detail":   f"Pattern '{pat[:50]}' matched in response body",
                "url":      req.url,
                "id":       entry.id,
            })


def _chk_error_pages(resp, findings, entry):
    if resp.status_code >= 500:
        findings.append({
            "severity": "MEDIUM",
            "issue":    f"HTTP {resp.status_code} server error",
            "detail":   "Server-side error — may indicate injection or logic flaw",
            "url":      entry.request.url,
            "id":       entry.id,
        })


def _chk_cors(resp, findings, entry):
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        sev  = "HIGH" if acac.lower() == "true" else "MEDIUM"
        findings.append({
            "severity": sev,
            "issue":    "Permissive CORS policy",
            "detail":   f"ACAO: {acao}  ACAC: {acac}",
            "url":      entry.request.url,
            "id":       entry.id,
        })


# ── UI ────────────────────────────────────────────────────────────────────────

SEV_COLOUR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#88ccff",
    "INFO":     "#aaaaaa",
}

COLS = ("ID", "Severity", "Issue", "URL", "Detail")


class ScannerTab(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._findings: list[dict] = []
        self._scanned:  set[int]   = set()
        self._build()
        history.on_new_entry(self._on_new_entry)

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Toolbar
        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky="ew", padx=6, pady=4)
        ttk.Button(bar, text="Scan All History", command=self._scan_all).pack(side="left", padx=2)
        ttk.Button(bar, text="Clear",            command=self._clear).pack(side="left", padx=2)
        self._count_var = tk.StringVar(value="0 findings")
        ttk.Label(bar, textvariable=self._count_var, foreground="gray").pack(side="left", padx=12)

        # Filter
        ttk.Label(bar, text="Filter severity:").pack(side="right")
        self._sev_var = tk.StringVar(value="All")
        ttk.Combobox(bar, textvariable=self._sev_var,
                     values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                     width=10, state="readonly").pack(side="right", padx=4)
        self._sev_var.trace_add("write", lambda *_: self._refresh_tree())

        # Findings table
        tbl = ttk.Frame(self)
        tbl.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 4))
        tbl.columnconfigure(0, weight=1)
        tbl.rowconfigure(0, weight=1)

        self._tree = ttk.Treeview(tbl, columns=COLS, show="headings", selectmode="browse")
        widths = [40, 80, 240, 300, 400]
        for col, w in zip(COLS, widths):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, anchor="w")

        for sev, colour in SEV_COLOUR.items():
            self._tree.tag_configure(sev, foreground=colour)

        vsb = ttk.Scrollbar(tbl, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tbl, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Detail panel
        detail = ttk.LabelFrame(self, text="Finding Detail")
        detail.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))
        detail.columnconfigure(0, weight=1)
        self._detail_text = tk.Text(detail, height=5, wrap="word", bg="#1e1e1e", fg="#d4d4d4",
                                     font=("Consolas", 9), state="disabled")
        self._detail_text.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

    def _on_new_entry(self, entry: HistoryEntry):
        """Automatically scan each new entry as it arrives."""
        if entry.response is not None:
            self.after(0, self._scan_entry, entry)

    def _scan_entry(self, entry: HistoryEntry):
        if entry.id in self._scanned:
            return
        self._scanned.add(entry.id)
        findings = _check_entry(entry)
        for f in findings:
            self._findings.append(f)
            self._insert_finding(f)
        self._count_var.set(f"{len(self._findings)} findings")

    def _scan_all(self):
        def _run():
            for entry in history.get_all():
                if entry.response and entry.id not in self._scanned:
                    findings = _check_entry(entry)
                    self._scanned.add(entry.id)
                    for f in findings:
                        self._findings.append(f)
                    self.after(0, self._refresh_tree)
        threading.Thread(target=_run, daemon=True).start()

    def _insert_finding(self, f: dict):
        sev = f["severity"]
        flt = self._sev_var.get()
        if flt != "All" and flt != sev:
            return
        self._tree.insert("", "end", tags=(sev,), values=(
            f["id"], sev, f["issue"], f["url"][:80], f["detail"][:120],
        ))

    def _refresh_tree(self):
        for item in self._tree.get_children():
            self._tree.delete(item)
        flt = self._sev_var.get()
        for f in self._findings:
            if flt == "All" or f["severity"] == flt:
                self._insert_finding(f)
        self._count_var.set(f"{len(self._findings)} findings")

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        idx = self._tree.index(sel[0])
        flt = self._sev_var.get()
        filtered = [f for f in self._findings if flt == "All" or f["severity"] == flt]
        if idx >= len(filtered):
            return
        f = filtered[idx]
        text = f"Severity : {f['severity']}\nIssue    : {f['issue']}\nURL      : {f['url']}\nDetail   : {f['detail']}"
        self._detail_text.config(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", text)
        self._detail_text.config(state="disabled")

    def _clear(self):
        self._findings.clear()
        self._scanned.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._count_var.set("0 findings")
