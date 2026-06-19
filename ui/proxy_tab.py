"""
Proxy Tab — HTTP history table + intercept panel.
"""

import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

from core.history import history, HistoryEntry
from core.proxy import intercept, ProxyServer
from core.http_utils import parse_request


# Candidate browser executables to try in order
_BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]

def _find_browser() -> str | None:
    for path in _BROWSERS:
        if os.path.exists(path):
            return path
    # Fallback: check PATH
    for name in ("chrome", "msedge"):
        try:
            result = subprocess.run(["where", name], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().splitlines()[0]
        except Exception:
            pass
    return None


def launch_proxied_browser(port: int):
    """Open Chrome or Edge with the proxy pre-configured — no manual setup needed."""
    browser = _find_browser()
    if not browser:
        messagebox.showerror(
            "Browser Not Found",
            "Could not find Chrome or Edge.\n\n"
            "Manually set your browser proxy to:\n"
            f"  Host: 127.0.0.1   Port: {port}"
        )
        return

    # Use a dedicated temp profile so it doesn't conflict with the user's normal browser
    profile_dir = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "burplite_browser_profile")
    os.makedirs(profile_dir, exist_ok=True)

    subprocess.Popen([
        browser,
        f"--proxy-server=127.0.0.1:{port}",
        "--ignore-certificate-errors",          # trust our MITM CA without installing it
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "about:blank",
    ])


COLS = ("#", "Method", "Host", "Path", "Status", "Length", "Type")


class ProxyTab(ttk.Frame):
    def __init__(self, parent, proxy_server: ProxyServer, send_to_repeater_cb=None, **kw):
        super().__init__(parent, **kw)
        self._proxy       = proxy_server
        self._send_to_rep = send_to_repeater_cb
        self._selected_entry: HistoryEntry | None = None
        self._intercept_entry_id: int | None = None
        self._build()
        history.on_new_entry(self._on_new_entry)

    # ── Layout ──────────────────────────────────────────────────────────────

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Top toolbar
        toolbar = ttk.Frame(self)
        toolbar.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

        self._proxy_var = tk.StringVar(value="Stopped")
        self._btn_toggle = ttk.Button(toolbar, text="Start Proxy", command=self._toggle_proxy)
        self._btn_toggle.pack(side="left", padx=2)

        self._port_var = tk.StringVar(value="8888")
        ttk.Label(toolbar, text="Port:").pack(side="left", padx=(8, 0))
        ttk.Entry(toolbar, textvariable=self._port_var, width=6).pack(side="left", padx=2)

        self._status_lbl = ttk.Label(toolbar, text="● Proxy stopped", foreground="red")
        self._status_lbl.pack(side="left", padx=12)

        self._intercept_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar, text="Intercept ON", variable=self._intercept_var,
            command=self._toggle_intercept,
        ).pack(side="left", padx=8)

        ttk.Button(toolbar, text="Open Browser", command=self._open_browser).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Clear History", command=self._clear_history).pack(side="right", padx=2)

        # Filter bar
        fbar = ttk.Frame(self)
        fbar.grid(row=1, column=0, sticky="ew", padx=4)
        ttk.Label(fbar, text="Filter:").pack(side="left")
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(fbar, textvariable=self._filter_var, width=30).pack(side="left", padx=4)
        ttk.Label(fbar, text="Method:").pack(side="left")
        self._method_var = tk.StringVar(value="All")
        ttk.Combobox(
            fbar, textvariable=self._method_var,
            values=["All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            width=8, state="readonly",
        ).pack(side="left", padx=4)
        self._method_var.trace_add("write", lambda *_: self._apply_filter())

        # Paned window: history table (top) + detail (bottom)
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        self.rowconfigure(2, weight=1)

        # History table
        tbl_frame = ttk.Frame(paned)
        paned.add(tbl_frame, weight=2)

        self._tree = ttk.Treeview(tbl_frame, columns=COLS, show="headings", selectmode="browse")
        widths = [40, 70, 200, 320, 60, 70, 160]
        for col, w in zip(COLS, widths):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, anchor="w")

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tbl_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tbl_frame.columnconfigure(0, weight=1)
        tbl_frame.rowconfigure(0, weight=1)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Button-3>", self._right_click)

        # Detail panel
        detail = ttk.Frame(paned)
        paned.add(detail, weight=1)
        detail.columnconfigure(0, weight=1)
        detail.columnconfigure(1, weight=1)
        detail.rowconfigure(0, weight=1)

        req_frame = ttk.LabelFrame(detail, text="Request")
        req_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 2))
        req_frame.rowconfigure(0, weight=1)
        req_frame.columnconfigure(0, weight=1)
        self._req_text = tk.Text(req_frame, wrap="none", bg="#1e1e1e", fg="#d4d4d4",
                                  font=("Consolas", 9), state="disabled")
        self._req_text.grid(row=0, column=0, sticky="nsew")
        ttk.Scrollbar(req_frame, command=self._req_text.yview).grid(row=0, column=1, sticky="ns")
        self._req_text.configure(yscrollcommand=lambda *a: None)

        resp_frame = ttk.LabelFrame(detail, text="Response")
        resp_frame.grid(row=0, column=1, sticky="nsew", padx=(2, 0))
        resp_frame.rowconfigure(0, weight=1)
        resp_frame.columnconfigure(0, weight=1)
        self._resp_text = tk.Text(resp_frame, wrap="none", bg="#1e1e1e", fg="#d4d4d4",
                                   font=("Consolas", 9), state="disabled")
        self._resp_text.grid(row=0, column=0, sticky="nsew")
        ttk.Scrollbar(resp_frame, command=self._resp_text.yview).grid(row=0, column=1, sticky="ns")

        # Intercept panel (hidden until intercept fires)
        self._intercept_panel = ttk.LabelFrame(self, text="Intercepted Request — edit and Forward or Drop")
        self._intercept_panel.grid(row=3, column=0, sticky="ew", padx=4, pady=(0, 4))
        self._intercept_panel.columnconfigure(0, weight=1)
        self._intercept_panel.grid_remove()

        self._intercept_text = tk.Text(
            self._intercept_panel, height=10, wrap="none",
            bg="#2d2d00", fg="#ffff88", font=("Consolas", 9),
        )
        self._intercept_text.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

        btn_row = ttk.Frame(self._intercept_panel)
        btn_row.grid(row=1, column=0, sticky="e", padx=4, pady=(0, 4))
        ttk.Button(btn_row, text="Forward", command=self._forward_intercepted).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Drop",    command=self._drop_intercepted).pack(side="left")

        intercept.set_on_queued(self._on_intercept_queued)

    # ── Proxy control ────────────────────────────────────────────────────────

    def _toggle_proxy(self):
        if self._proxy.running:
            self._proxy.stop()
            self._status_lbl.config(text="● Proxy stopped", foreground="red")
            self._btn_toggle.config(text="Start Proxy")
        else:
            try:
                port = int(self._port_var.get())
            except ValueError:
                messagebox.showerror("Invalid Port", "Enter a valid port number.")
                return

            # Thread can only be started once — create a fresh one each time
            from core.proxy import ProxyServer
            self._proxy = ProxyServer(host="127.0.0.1", port=port)
            self._proxy.start()

            # Wait briefly to see if bind succeeded
            self._proxy.join(timeout=0.5)
            if self._proxy.error:
                messagebox.showerror(
                    "Proxy Failed",
                    f"Could not bind to port {port}:\n{self._proxy.error}\n\n"
                    "Try a different port (e.g. 8888, 9090) or run as Administrator."
                )
                self._proxy.running = False
                return

            self._status_lbl.config(
                text=f"● Proxy running on 127.0.0.1:{port}", foreground="green"
            )
            self._btn_toggle.config(text="Stop Proxy")

    def _toggle_intercept(self):
        intercept.active = self._intercept_var.get()

    def _open_browser(self):
        if not self._proxy.running:
            if messagebox.askyesno("Proxy Not Running", "The proxy isn't started yet. Start it now?"):
                self._toggle_proxy()
            else:
                return
        try:
            port = int(self._port_var.get())
        except ValueError:
            port = 8888
        launch_proxied_browser(port)

    # ── History management ───────────────────────────────────────────────────

    def _on_new_entry(self, entry: HistoryEntry):
        self.after(0, self._insert_row, entry)

    def _insert_row(self, entry: HistoryEntry):
        self._tree.insert("", "end", iid=str(entry.id), values=(
            entry.id, entry.method, entry.host, entry.path,
            entry.status, entry.length, entry.content_type,
        ))
        self._tree.yview_moveto(1.0)

    def _apply_filter(self):
        search = self._filter_var.get().strip()
        method = self._method_var.get()

        for item in self._tree.get_children():
            self._tree.delete(item)

        entries = history.filter(
            search=search,
            method="" if method == "All" else method,
        )
        for e in entries:
            self._tree.insert("", "end", iid=str(e.id), values=(
                e.id, e.method, e.host, e.path,
                e.status, e.length, e.content_type,
            ))

    def _clear_history(self):
        history.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._set_text(self._req_text, "")
        self._set_text(self._resp_text, "")

    # ── Selection / detail ───────────────────────────────────────────────────

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        entry_id = int(sel[0])
        entry = history.get_by_id(entry_id)
        if not entry:
            return
        self._selected_entry = entry
        self._set_text(self._req_text, entry.request.to_display())
        resp_text = entry.response.to_display() if entry.response else "(no response yet)"
        self._set_text(self._resp_text, resp_text)

    def _right_click(self, event):
        iid = self._tree.identify_row(event.y)
        if not iid:
            return
        self._tree.selection_set(iid)
        self._on_select()
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Send to Repeater", command=self._send_selected_to_repeater)
        menu.add_command(label="Copy URL",         command=self._copy_url)
        menu.tk_popup(event.x_root, event.y_root)

    def _send_selected_to_repeater(self):
        if self._selected_entry and self._send_to_rep:
            self._send_to_rep(self._selected_entry)

    def _copy_url(self):
        if self._selected_entry:
            self.clipboard_clear()
            self.clipboard_append(self._selected_entry.request.url)

    # ── Intercept ────────────────────────────────────────────────────────────

    def _on_intercept_queued(self, entry_id: int, request):
        self._intercept_entry_id = entry_id
        self.after(0, self._show_intercept_panel, request)

    def _show_intercept_panel(self, request):
        self._intercept_text.delete("1.0", "end")
        self._intercept_text.insert("1.0", request.to_display())
        self._intercept_panel.grid()

    def _forward_intercepted(self):
        if self._intercept_entry_id is None:
            return
        raw     = self._intercept_text.get("1.0", "end-1c").encode()
        entry   = history.get_by_id(self._intercept_entry_id)
        req     = parse_request(raw,
                                host=entry.request.host if entry else "",
                                port=entry.request.port if entry else 80,
                                is_https=entry.request.is_https if entry else False)
        intercept.forward(self._intercept_entry_id, req)
        self._intercept_panel.grid_remove()
        self._intercept_entry_id = None

    def _drop_intercepted(self):
        if self._intercept_entry_id is None:
            return
        intercept.drop(self._intercept_entry_id)
        self._intercept_panel.grid_remove()
        self._intercept_entry_id = None

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _set_text(widget: tk.Text, text: str):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")
