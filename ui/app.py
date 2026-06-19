"""
Main application window — tabbed interface with dark theme.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from core.ca import ca_cert_path, install_ca_windows, uninstall_ca_windows, generate_root_ca
from core.proxy import ProxyServer
from ui.proxy_tab    import ProxyTab
from ui.repeater_tab import RepeaterTab
from ui.intruder_tab import IntruderTab
from ui.decoder_tab  import DecoderTab
from ui.scanner_tab  import ScannerTab


DARK_BG   = "#2b2b2b"
DARK_FG   = "#d4d4d4"
ACCENT    = "#e8761b"   # Burp-ish orange


def _apply_dark_theme(root: tk.Tk):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(".",
        background=DARK_BG, foreground=DARK_FG,
        fieldbackground="#3c3c3c", troughcolor="#3c3c3c",
        bordercolor="#555", selectbackground="#4a6fa5",
    )
    style.configure("TNotebook",       background=DARK_BG, tabmargins=[2, 2, 0, 0])
    style.configure("TNotebook.Tab",   background="#3c3c3c", foreground=DARK_FG, padding=[10, 4])
    style.map("TNotebook.Tab",
        background=[("selected", ACCENT)],
        foreground=[("selected", "#ffffff")],
    )
    style.configure("TFrame",          background=DARK_BG)
    style.configure("TLabelframe",     background=DARK_BG, foreground=DARK_FG)
    style.configure("TLabelframe.Label", background=DARK_BG, foreground=ACCENT)
    style.configure("TButton",         background="#3c3c3c", foreground=DARK_FG)
    style.map("TButton",               background=[("active", "#555")])
    style.configure("TEntry",          fieldbackground="#3c3c3c", foreground=DARK_FG)
    style.configure("TCombobox",       fieldbackground="#3c3c3c", foreground=DARK_FG,
                                       selectbackground="#4a6fa5")
    style.configure("TCheckbutton",    background=DARK_BG, foreground=DARK_FG)
    style.configure("TLabel",         background=DARK_BG, foreground=DARK_FG)
    style.configure("TScrollbar",      background="#3c3c3c", troughcolor="#2b2b2b")
    style.configure("Treeview",
        background="#1e1e1e", foreground=DARK_FG,
        fieldbackground="#1e1e1e", rowheight=20,
    )
    style.configure("Treeview.Heading", background="#3c3c3c", foreground=ACCENT)
    style.map("Treeview",              background=[("selected", "#4a6fa5")])
    style.configure("TSpinbox",        fieldbackground="#3c3c3c", foreground=DARK_FG)
    style.configure("Horizontal.TProgressbar", troughcolor="#3c3c3c", background=ACCENT)

    root.configure(bg=DARK_BG)
    root.option_add("*Background",    DARK_BG)
    root.option_add("*Foreground",    DARK_FG)
    root.option_add("*Font",          "TkDefaultFont")


class BurpLiteApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BurpLite — Web Penetration Testing Proxy")
        self.root.geometry("1280x800")
        self.root.minsize(900, 600)

        _apply_dark_theme(self.root)

        self._proxy = ProxyServer(host="127.0.0.1", port=8888)
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self):
        # ── Menu bar ────────────────────────────────────────────────────────
        menubar = tk.Menu(self.root, bg=DARK_BG, fg=DARK_FG, tearoff=0)
        self.root.config(menu=menubar)

        proxy_menu = tk.Menu(menubar, tearoff=0, bg=DARK_BG, fg=DARK_FG)
        menubar.add_cascade(label="Proxy", menu=proxy_menu)
        proxy_menu.add_command(label="Start Proxy",  command=self._start_proxy)
        proxy_menu.add_command(label="Stop Proxy",   command=self._stop_proxy)

        ca_menu = tk.Menu(menubar, tearoff=0, bg=DARK_BG, fg=DARK_FG)
        menubar.add_cascade(label="CA Certificate", menu=ca_menu)
        ca_menu.add_command(label="Install Root CA (Admin)",   command=self._install_ca)
        ca_menu.add_command(label="Uninstall Root CA (Admin)", command=self._uninstall_ca)
        ca_menu.add_command(label="Show CA cert path",         command=self._show_ca_path)
        ca_menu.add_command(label="Regenerate CA",             command=self._regen_ca)

        help_menu = tk.Menu(menubar, tearoff=0, bg=DARK_BG, fg=DARK_FG)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Quick Start", command=self._show_help)

        # ── Status bar ───────────────────────────────────────────────────────
        self._statusbar = tk.Label(
            self.root, text="  BurpLite ready  |  Set browser proxy to 127.0.0.1:8888",
            anchor="w", bg="#1a1a1a", fg="#888888", font=("Consolas", 8),
        )
        self._statusbar.pack(side="bottom", fill="x")

        # ── Notebook ─────────────────────────────────────────────────────────
        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill="both", expand=True, padx=4, pady=4)

        self._repeater_tab = RepeaterTab(self._nb)
        self._proxy_tab    = ProxyTab(
            self._nb,
            proxy_server=self._proxy,
            send_to_repeater_cb=self._repeater_tab.load_entry,
        )
        self._intruder_tab = IntruderTab(self._nb)
        self._decoder_tab  = DecoderTab(self._nb)
        self._scanner_tab  = ScannerTab(self._nb)

        self._nb.add(self._proxy_tab,    text="  Proxy  ")
        self._nb.add(self._repeater_tab, text="  Repeater  ")
        self._nb.add(self._intruder_tab, text="  Intruder  ")
        self._nb.add(self._decoder_tab,  text="  Decoder  ")
        self._nb.add(self._scanner_tab,  text="  Scanner  ")

    # ── Proxy menu actions ───────────────────────────────────────────────────

    def _start_proxy(self):
        if not self._proxy.running:
            self._proxy.start()
            self._statusbar.config(
                text=f"  Proxy running on 127.0.0.1:{self._proxy.port}  |  Route browser traffic through this address"
            )

    def _stop_proxy(self):
        if self._proxy.running:
            self._proxy.stop()
            self._statusbar.config(text="  Proxy stopped")

    # ── CA menu actions ──────────────────────────────────────────────────────

    def _install_ca(self):
        ok, msg = install_ca_windows()
        if ok:
            messagebox.showinfo("CA Installed", msg + "\n\nRestart your browser to trust the CA.")
        else:
            messagebox.showerror("Install Failed", msg + "\n\nRun BurpLite as Administrator.")

    def _uninstall_ca(self):
        ok, msg = uninstall_ca_windows()
        if ok:
            messagebox.showinfo("CA Removed", msg)
        else:
            messagebox.showerror("Uninstall Failed", msg)

    def _show_ca_path(self):
        path = ca_cert_path()
        messagebox.showinfo("CA Certificate", f"CA cert path:\n{path}\n\nImport this into your browser's trusted CAs to intercept HTTPS.")

    def _regen_ca(self):
        if messagebox.askyesno("Regenerate CA", "This will create a new root CA. Any existing browser trust for the old CA will break. Continue?"):
            generate_root_ca()
            messagebox.showinfo("Done", "New root CA generated. Re-install it into your browser.")

    # ── Help ─────────────────────────────────────────────────────────────────

    def _show_help(self):
        msg = (
            "BurpLite Quick Start\n"
            "═══════════════════\n\n"
            "1. CA Certificate:\n"
            "   Menu → CA Certificate → Install Root CA (Admin)\n"
            "   Then import the CA cert into your browser trust store.\n\n"
            "2. Browser proxy:\n"
            "   Set your browser HTTP proxy to:  127.0.0.1 : 8888\n\n"
            "3. Start proxy:\n"
            "   Proxy tab → Start Proxy  (or Menu → Proxy → Start)\n\n"
            "4. Browse your target — requests appear in Proxy tab.\n\n"
            "5. Right-click a request → Send to Repeater to replay/modify it.\n\n"
            "6. Intruder tab: paste a request, mark §payload§, load payloads, Start Attack.\n\n"
            "7. Decoder tab: encode/decode/hash data with chained transformations.\n\n"
            "8. Scanner tab: auto-detects issues in all proxied traffic."
        )
        messagebox.showinfo("Quick Start", msg)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _on_close(self):
        self._stop_proxy()
        self.root.destroy()

    def run(self):
        self.root.mainloop()
