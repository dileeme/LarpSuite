"""
Code Diagnostics Tab — browse a local source directory and run static analysis.
"""

import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core.code_analyzer import analyse_directory, AnalysisResult, Finding

DARK_BG = "#2b2b2b"
DARK_FG = "#d4d4d4"
ACCENT  = "#e8761b"

SEV_COLOUR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#88ccff",
    "INFO":     "#aaaaaa",
}

FIND_COLS = ("File", "Line", "Severity", "Category", "Snippet")


class DiagnosticsTab(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._result: AnalysisResult | None = None
        self._findings: list[Finding] = []
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # ── Top bar: folder selection ──────────────────────────────────────────
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", padx=6, pady=6)

        ttk.Label(top, text="Target directory:").pack(side="left")
        self._dir_var = tk.StringVar()
        ttk.Entry(top, textvariable=self._dir_var, width=60).pack(side="left", padx=4)
        ttk.Button(top, text="Browse…",   command=self._browse).pack(side="left")
        ttk.Button(top, text="▶  Run Diagnostics", command=self._run,
                   style="Accent.TButton").pack(side="left", padx=8)
        ttk.Button(top, text="Export Report", command=self._export).pack(side="left")

        # ── Progress bar ───────────────────────────────────────────────────────
        prog_frame = ttk.Frame(self)
        prog_frame.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 4))
        prog_frame.columnconfigure(1, weight=1)

        self._prog_label = ttk.Label(prog_frame, text="", foreground="gray")
        self._prog_label.grid(row=0, column=0, padx=(0, 6))
        self._prog_bar = ttk.Progressbar(prog_frame, mode="determinate",
                                         style="Horizontal.TProgressbar")
        self._prog_bar.grid(row=0, column=1, sticky="ew")

        # ── Paned area: summary left + findings right ──────────────────────────
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.grid(row=2, column=0, sticky="nsew", padx=6, pady=(0, 4))

        # Left: summary panel
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        ttk.Label(left, text="Summary", foreground=ACCENT,
                  font=("Consolas", 10, "bold")).grid(row=0, column=0, sticky="w", pady=(4, 2))

        self._summary_text = tk.Text(left, width=38, wrap="word",
                                      bg="#1e1e1e", fg=DARK_FG,
                                      font=("Consolas", 9), state="disabled")
        ssb = ttk.Scrollbar(left, orient="vertical", command=self._summary_text.yview)
        self._summary_text.configure(yscrollcommand=ssb.set)
        self._summary_text.grid(row=1, column=0, sticky="nsew")
        ssb.grid(row=1, column=1, sticky="ns")

        # Right: findings table
        right = ttk.Frame(paned)
        paned.add(right, weight=3)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        # Filter bar above the table
        fbar = ttk.Frame(right)
        fbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(4, 2))

        ttk.Label(fbar, text="Filter:").pack(side="left")
        self._sev_var = tk.StringVar(value="All")
        ttk.Combobox(fbar, textvariable=self._sev_var,
                     values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                     width=10, state="readonly").pack(side="left", padx=4)
        self._sev_var.trace_add("write", lambda *_: self._refresh_findings())

        self._cat_var = tk.StringVar(value="All")
        self._cat_box = ttk.Combobox(fbar, textvariable=self._cat_var,
                                      width=22, state="readonly")
        self._cat_box.pack(side="left", padx=4)
        self._cat_var.trace_add("write", lambda *_: self._refresh_findings())

        self._find_count = tk.StringVar(value="0 findings")
        ttk.Label(fbar, textvariable=self._find_count, foreground="gray").pack(side="left", padx=10)

        # Treeview
        self._tree = ttk.Treeview(right, columns=FIND_COLS, show="headings",
                                   selectmode="browse")
        widths = [240, 55, 80, 160, 350]
        for col, w in zip(FIND_COLS, widths):
            self._tree.heading(col, text=col,
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=w, anchor="w")
        for sev, col in SEV_COLOUR.items():
            self._tree.tag_configure(sev, foreground=col)

        vsb2 = ttk.Scrollbar(right, orient="vertical",   command=self._tree.yview)
        hsb2 = ttk.Scrollbar(right, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb2.set, xscrollcommand=hsb2.set)
        self._tree.grid(row=1, column=0, sticky="nsew")
        vsb2.grid(row=1, column=1, sticky="ns")
        hsb2.grid(row=2, column=0, sticky="ew")

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # ── Detail panel at bottom ─────────────────────────────────────────────
        detail = ttk.LabelFrame(self, text="Finding Detail")
        detail.grid(row=3, column=0, sticky="ew", padx=6, pady=(0, 6))
        detail.columnconfigure(0, weight=1)
        self._detail_text = tk.Text(detail, height=4, wrap="word",
                                     bg="#1e1e1e", fg=DARK_FG,
                                     font=("Consolas", 9), state="disabled")
        self._detail_text.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse(self):
        d = filedialog.askdirectory(title="Select source directory to analyse")
        if d:
            self._dir_var.set(d)

    def _run(self):
        d = self._dir_var.get().strip()
        if not d:
            messagebox.showwarning("No directory", "Please select a directory first.")
            return

        import os
        if not os.path.isdir(d):
            messagebox.showerror("Invalid path", f"Not a directory:\n{d}")
            return

        # Reset UI
        self._findings.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._set_summary("")
        self._find_count.set("Scanning…")
        self._prog_bar["value"] = 0
        self._prog_label.config(text="Starting…")

        def _progress(current_file: str, scanned: int, total: int):
            pct = (scanned / total * 100) if total else 0
            short = current_file[-60:] if len(current_file) > 60 else current_file
            self.after(0, lambda: (
                self._prog_bar.configure(value=pct),
                self._prog_label.config(text=f"{scanned}/{total}  {short}"),
            ))

        def _work():
            try:
                result = analyse_directory(d, progress_cb=_progress)
                self.after(0, lambda: self._show_result(result))
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Analysis Error", str(exc)))

        threading.Thread(target=_work, daemon=True).start()

    def _show_result(self, result: AnalysisResult):
        self._result = result
        self._findings = result.findings[:]

        # Build summary text
        code_lines = result.total_lines - result.blank_lines - result.comment_lines
        lines = [
            f"Root : {result.root}",
            "",
            f"Directories : {result.total_dirs}",
            f"Files       : {result.total_files}",
            f"Total lines : {result.total_lines:,}",
            f"  Code      : {code_lines:,}",
            f"  Comments  : {result.comment_lines:,}",
            f"  Blank     : {result.blank_lines:,}",
            "",
            "── Lines by language ──",
        ]
        for lang, cnt in sorted(result.lines_by_lang.items(),
                                 key=lambda x: x[1], reverse=True):
            files = result.files_by_lang.get(lang, 0)
            lines.append(f"  {lang:<22} {cnt:>7,}  ({files} files)")

        sev_counts: dict[str, int] = {}
        cat_counts: dict[str, int] = {}
        for f in result.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

        lines += ["", "── Findings by severity ──"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in sev_counts:
                lines.append(f"  {sev:<10} {sev_counts[sev]:>4}")

        lines += ["", "── Findings by category ──"]
        for cat, cnt in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {cat:<25} {cnt:>4}")

        if result.errors:
            lines += ["", f"── Read errors: {len(result.errors)} ──"]
            for fp, msg in result.errors[:10]:
                lines.append(f"  {fp}: {msg}")

        self._set_summary("\n".join(lines))

        # Update category filter
        cats = sorted(set(f.category for f in self._findings))
        self._cat_box["values"] = ["All"] + cats
        self._cat_var.set("All")

        self._prog_label.config(text="Done")
        self._prog_bar["value"] = 100
        self._refresh_findings()

    def _refresh_findings(self):
        for item in self._tree.get_children():
            self._tree.delete(item)

        sev_flt = self._sev_var.get()
        cat_flt = self._cat_var.get()

        visible = [
            f for f in self._findings
            if (sev_flt == "All" or f.severity == sev_flt)
            and (cat_flt == "All" or f.category == cat_flt)
        ]

        for f in visible:
            self._tree.insert("", "end", tags=(f.severity,), values=(
                f.file, f.line, f.severity, f.category, f.snippet,
            ))

        self._find_count.set(f"{len(visible)} / {len(self._findings)} findings")

    def _sort_by(self, col: str):
        col_idx = FIND_COLS.index(col)
        items = [(self._tree.set(i, col), i) for i in self._tree.get_children("")]
        items.sort(key=lambda x: x[0].lower())
        for idx, (_, iid) in enumerate(items):
            self._tree.move(iid, "", idx)

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], "values")
        if not vals:
            return
        file_, line, sev, cat, snippet = vals

        # Find matching finding for full detail
        detail_finding = next(
            (f for f in self._findings
             if f.file == file_ and str(f.line) == str(line)),
            None
        )
        detail = detail_finding.detail if detail_finding else ""

        text = (
            f"File     : {file_}  (line {line})\n"
            f"Severity : {sev}   Category: {cat}\n"
            f"Snippet  : {snippet}\n"
            f"Detail   : {detail}"
        )
        self._detail_text.config(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", text)
        self._detail_text.config(state="disabled")

    def _export(self):
        if not self._result:
            messagebox.showwarning("Nothing to export", "Run diagnostics first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text report", "*.txt"), ("All files", "*.*")],
            title="Save diagnostic report",
        )
        if not path:
            return

        lines = [
            "BurpLite — Code Diagnostics Report",
            "=" * 60,
            f"Root: {self._result.root}",
            "",
            f"Files       : {self._result.total_files}",
            f"Directories : {self._result.total_dirs}",
            f"Total lines : {self._result.total_lines:,}",
            "",
            "Findings",
            "-" * 60,
        ]
        for f in sorted(self._findings,
                        key=lambda x: ("CRITICAL","HIGH","MEDIUM","LOW","INFO").index(x.severity)
                        if x.severity in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") else 99):
            lines.append(
                f"[{f.severity:<8}] {f.category:<25} {f.file}:{f.line}\n"
                f"  Snippet : {f.snippet}\n"
                f"  Detail  : {f.detail}\n"
            )

        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            messagebox.showinfo("Exported", f"Report saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_summary(self, text: str):
        self._summary_text.config(state="normal")
        self._summary_text.delete("1.0", "end")
        self._summary_text.insert("1.0", text)
        self._summary_text.config(state="disabled")
