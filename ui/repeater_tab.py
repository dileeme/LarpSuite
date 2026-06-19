"""
Repeater Tab — manually craft and resend HTTP requests.
"""

import socket
import ssl
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from core.history import HistoryEntry
from core.http_utils import HttpRequest, HttpResponse, parse_response, rebuild_request

TEMPLATE = """\
GET / HTTP/1.1\r
Host: example.com\r
User-Agent: BurpLite/1.0\r
Accept: */*\r
Connection: close\r
\r
"""


class RepeaterTab(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._tabs: list[_RepeaterPane] = []
        self._nb   = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=4, pady=4)

        btn_bar = ttk.Frame(self)
        btn_bar.pack(fill="x", padx=4, pady=(0, 4))
        ttk.Button(btn_bar, text="+ New Tab", command=self._new_tab).pack(side="left")

        self._new_tab()

    def _new_tab(self, entry: HistoryEntry | None = None):
        pane  = _RepeaterPane(self._nb, entry)
        title = f"Request {len(self._tabs) + 1}"
        self._nb.add(pane, text=title)
        self._tabs.append(pane)
        self._nb.select(pane)

    def load_entry(self, entry: HistoryEntry):
        """Called from Proxy tab 'Send to Repeater'."""
        self._new_tab(entry)


class _RepeaterPane(ttk.Frame):
    def __init__(self, parent, entry: HistoryEntry | None = None, **kw):
        super().__init__(parent, **kw)
        self._entry = entry
        self._build()
        if entry:
            self._load_entry(entry)

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Top bar
        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

        ttk.Label(bar, text="Target:").pack(side="left")
        self._scheme_var = tk.StringVar(value="https")
        ttk.Combobox(bar, textvariable=self._scheme_var, values=["http", "https"],
                     width=6, state="readonly").pack(side="left", padx=2)

        self._host_var = tk.StringVar(value="example.com")
        ttk.Entry(bar, textvariable=self._host_var, width=30).pack(side="left", padx=2)

        ttk.Label(bar, text=":").pack(side="left")
        self._port_var = tk.StringVar(value="443")
        ttk.Entry(bar, textvariable=self._port_var, width=6).pack(side="left", padx=2)

        ttk.Button(bar, text="Send", command=self._send).pack(side="left", padx=8)

        self._status_var = tk.StringVar()
        ttk.Label(bar, textvariable=self._status_var, foreground="gray").pack(side="left")

        # Paned editor
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))

        req_frame = ttk.LabelFrame(paned, text="Request")
        paned.add(req_frame, weight=1)
        req_frame.rowconfigure(0, weight=1)
        req_frame.columnconfigure(0, weight=1)
        self._req_text = tk.Text(req_frame, wrap="none", bg="#1e1e1e", fg="#d4d4d4",
                                  font=("Consolas", 9))
        self._req_text.grid(row=0, column=0, sticky="nsew")
        ttk.Scrollbar(req_frame, command=self._req_text.yview).grid(row=0, column=1, sticky="ns")
        ttk.Scrollbar(req_frame, orient="horizontal", command=self._req_text.xview).grid(
            row=1, column=0, sticky="ew")
        self._req_text.insert("1.0", TEMPLATE)

        resp_frame = ttk.LabelFrame(paned, text="Response")
        paned.add(resp_frame, weight=1)
        resp_frame.rowconfigure(0, weight=1)
        resp_frame.columnconfigure(0, weight=1)
        self._resp_text = tk.Text(resp_frame, wrap="none", bg="#1e1e1e", fg="#d4d4d4",
                                   font=("Consolas", 9), state="disabled")
        self._resp_text.grid(row=0, column=0, sticky="nsew")
        ttk.Scrollbar(resp_frame, command=self._resp_text.yview).grid(row=0, column=1, sticky="ns")
        ttk.Scrollbar(resp_frame, orient="horizontal", command=self._resp_text.xview).grid(
            row=1, column=0, sticky="ew")

    def _load_entry(self, entry: HistoryEntry):
        req = entry.request
        self._scheme_var.set("https" if req.is_https else "http")
        self._host_var.set(req.host)
        self._port_var.set(str(req.port))
        self._req_text.delete("1.0", "end")
        self._req_text.insert("1.0", req.to_display())

    def _send(self):
        self._status_var.set("Sending…")
        threading.Thread(target=self._do_send, daemon=True).start()

    def _do_send(self):
        try:
            raw   = rebuild_request(self._req_text.get("1.0", "end-1c"))
            host  = self._host_var.get().strip()
            port  = int(self._port_var.get().strip())
            https = self._scheme_var.get() == "https"

            sock = socket.create_connection((host, port), timeout=15)
            if https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(raw)
            resp_raw = b""
            sock.settimeout(10)
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    resp_raw += chunk
            except socket.timeout:
                pass
            sock.close()

            resp = parse_response(resp_raw)
            text = resp.to_display() if resp else resp_raw.decode(errors="replace")
            status = f"{resp.status_code} {resp.reason}" if resp else "Done"
            self.after(0, self._show_response, text, status)
        except Exception as e:
            self.after(0, self._show_response, f"Error: {e}", "Error")

    def _show_response(self, text: str, status: str):
        self._status_var.set(status)
        self._resp_text.config(state="normal")
        self._resp_text.delete("1.0", "end")
        self._resp_text.insert("1.0", text)
        self._resp_text.config(state="disabled")
