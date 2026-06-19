"""
Decoder Tab — encode/decode/hash arbitrary data.
Supports chained transformations.
"""

import base64
import binascii
import gzip
import hashlib
import html
import json
import tkinter as tk
import urllib.parse
from tkinter import ttk


OPERATIONS = [
    "URL Encode", "URL Decode",
    "Base64 Encode", "Base64 Decode",
    "HTML Encode", "HTML Decode",
    "Hex Encode", "Hex Decode",
    "MD5", "SHA1", "SHA256", "SHA512",
    "GZIP (base64)", "JSON Pretty",
]


def _apply(operation: str, text: str) -> str:
    data = text.encode("utf-8", errors="replace")
    try:
        if operation == "URL Encode":
            return urllib.parse.quote(text)
        if operation == "URL Decode":
            return urllib.parse.unquote(text)
        if operation == "Base64 Encode":
            return base64.b64encode(data).decode()
        if operation == "Base64 Decode":
            return base64.b64decode(text).decode("utf-8", errors="replace")
        if operation == "HTML Encode":
            return html.escape(text)
        if operation == "HTML Decode":
            return html.unescape(text)
        if operation == "Hex Encode":
            return data.hex()
        if operation == "Hex Decode":
            return bytes.fromhex(text.replace(" ", "")).decode("utf-8", errors="replace")
        if operation == "MD5":
            return hashlib.md5(data).hexdigest()
        if operation == "SHA1":
            return hashlib.sha1(data).hexdigest()
        if operation == "SHA256":
            return hashlib.sha256(data).hexdigest()
        if operation == "SHA512":
            return hashlib.sha512(data).hexdigest()
        if operation == "GZIP (base64)":
            return base64.b64encode(gzip.compress(data)).decode()
        if operation == "JSON Pretty":
            return json.dumps(json.loads(text), indent=2)
    except Exception as e:
        return f"[Error: {e}]"
    return text


class DecoderTab(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._rows: list[_DecoderRow] = []
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
        ttk.Label(header, text="Decoder / Encoder", font=("", 11, "bold")).pack(side="left")
        ttk.Button(header, text="+ Add Step", command=self._add_row).pack(side="right")
        ttk.Button(header, text="Reset",      command=self._reset).pack(side="right", padx=4)

        # Scrollable container for rows
        canvas_frame = ttk.Frame(self)
        canvas_frame.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)
        self.rowconfigure(1, weight=1)
        canvas_frame.columnconfigure(0, weight=1)
        canvas_frame.rowconfigure(0, weight=1)

        self._canvas = tk.Canvas(canvas_frame, bg="#2b2b2b", highlightthickness=0)
        vsb = ttk.Scrollbar(canvas_frame, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=vsb.set)
        self._canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._row_frame = ttk.Frame(self._canvas)
        self._row_frame.columnconfigure(0, weight=1)
        self._canvas_window = self._canvas.create_window((0, 0), window=self._row_frame, anchor="nw")
        self._row_frame.bind("<Configure>", self._on_frame_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # Seed with first row
        self._add_row()

    def _on_frame_configure(self, _event=None):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self._canvas.itemconfig(self._canvas_window, width=event.width)

    def _add_row(self, initial_text: str = ""):
        row_num = len(self._rows)
        row     = _DecoderRow(self._row_frame, row_num, initial_text, self._on_transform)
        row.grid(row=row_num, column=0, sticky="ew", padx=4, pady=4)
        self._rows.append(row)
        self._on_frame_configure()

    def _on_transform(self, source_row_idx: int, result_text: str):
        """Cascade result into next row's input (if it exists), else add a new row."""
        next_idx = source_row_idx + 1
        if next_idx < len(self._rows):
            self._rows[next_idx].set_input(result_text)
        else:
            self._add_row(result_text)

    def _reset(self):
        for row in self._rows:
            row.destroy()
        self._rows.clear()
        self._add_row()


class _DecoderRow(ttk.LabelFrame):
    def __init__(self, parent, idx: int, initial: str, on_transform, **kw):
        super().__init__(parent, text=f"Step {idx + 1}", **kw)
        self._idx          = idx
        self._on_transform = on_transform
        self.columnconfigure(0, weight=1)
        self._build(initial)

    def _build(self, initial: str):
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 0))

        self._op_var = tk.StringVar(value=OPERATIONS[0])
        ttk.Combobox(top, textvariable=self._op_var, values=OPERATIONS,
                     width=18, state="readonly").pack(side="left", padx=2)
        ttk.Button(top, text="Transform →", command=self._transform).pack(side="left", padx=4)
        ttk.Button(top, text="Copy",        command=self._copy).pack(side="left")

        self._in_text = tk.Text(self, height=4, wrap="none", bg="#1e1e1e", fg="#d4d4d4",
                                 font=("Consolas", 9))
        self._in_text.grid(row=1, column=0, sticky="ew", padx=4, pady=(4, 2))
        if initial:
            self._in_text.insert("1.0", initial)

        result_label = ttk.Frame(self)
        result_label.grid(row=2, column=0, sticky="ew", padx=4)
        ttk.Label(result_label, text="Result:").pack(side="left")

        self._out_var = tk.StringVar()
        out_entry = ttk.Entry(self, textvariable=self._out_var, state="readonly",
                              font=("Consolas", 9))
        out_entry.grid(row=3, column=0, sticky="ew", padx=4, pady=(0, 4))

    def set_input(self, text: str):
        self._in_text.delete("1.0", "end")
        self._in_text.insert("1.0", text)

    def _transform(self):
        text   = self._in_text.get("1.0", "end-1c")
        result = _apply(self._op_var.get(), text)
        self._out_var.set(result)
        self._on_transform(self._idx, result)

    def _copy(self):
        self.clipboard_clear()
        self.clipboard_append(self._out_var.get())
