"""
HTTP parsing helpers — raw bytes ↔ structured request/response.
"""

import json
import re
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class HttpRequest:
    method:   str
    path:     str
    version:  str
    headers:  dict
    body:     bytes
    host:     str  = ""
    port:     int  = 80
    is_https: bool = False
    raw:      bytes = field(default=b"", repr=False)

    @property
    def url(self) -> str:
        scheme = "https" if self.is_https else "http"
        port_part = f":{self.port}" if self.port not in (80, 443) else ""
        return f"{scheme}://{self.host}{port_part}{self.path}"

    def to_bytes(self) -> bytes:
        lines  = f"{self.method} {self.path} {self.version}\r\n"
        for k, v in self.headers.items():
            lines += f"{k}: {v}\r\n"
        lines += "\r\n"
        return lines.encode() + (self.body or b"")

    def to_display(self) -> str:
        lines = f"{self.method} {self.path} {self.version}\n"
        for k, v in self.headers.items():
            lines += f"{k}: {v}\n"
        if self.body:
            lines += "\n" + _try_decode(self.body)
        return lines

    def params(self) -> dict:
        """Parse query string parameters."""
        parsed = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def body_params(self) -> dict:
        """Parse application/x-www-form-urlencoded body."""
        ct = self.headers.get("Content-Type", "")
        if "urlencoded" in ct and self.body:
            return dict(urllib.parse.parse_qsl(self.body.decode(errors="replace")))
        return {}

    def body_json(self):
        ct = self.headers.get("Content-Type", "")
        if "json" in ct and self.body:
            try:
                return json.loads(self.body)
            except Exception:
                pass
        return None


@dataclass
class HttpResponse:
    version:     str
    status_code: int
    reason:      str
    headers:     dict
    body:        bytes
    raw:         bytes = field(default=b"", repr=False)

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")

    def to_display(self) -> str:
        lines = f"{self.version} {self.status_code} {self.reason}\n"
        for k, v in self.headers.items():
            lines += f"{k}: {v}\n"
        if self.body:
            lines += "\n" + _try_decode(self.body)
        return lines

    def body_text(self) -> str:
        return _try_decode(self.body)


def _try_decode(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return repr(data)


def parse_request(raw: bytes, host: str = "", port: int = 80, is_https: bool = False) -> HttpRequest | None:
    """Parse raw HTTP request bytes into an HttpRequest."""
    try:
        header_end = raw.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = raw.find(b"\n\n")
            sep_len = 2
        else:
            sep_len = 4

        header_bytes = raw[:header_end]
        body         = raw[header_end + sep_len:]

        lines = header_bytes.decode(errors="replace").split("\r\n")
        if not lines:
            return None

        parts = lines[0].split(" ", 2)
        if len(parts) < 3:
            return None
        method, path, version = parts

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

        inferred_host = host or headers.get("Host", "").split(":")[0]
        inferred_port = port
        if ":" in headers.get("Host", ""):
            try:
                inferred_port = int(headers["Host"].split(":")[1])
            except ValueError:
                pass

        return HttpRequest(
            method=method, path=path, version=version,
            headers=headers, body=body,
            host=inferred_host, port=inferred_port,
            is_https=is_https, raw=raw,
        )
    except Exception:
        return None


def parse_response(raw: bytes) -> HttpResponse | None:
    """Parse raw HTTP response bytes into an HttpResponse."""
    try:
        header_end = raw.find(b"\r\n\r\n")
        if header_end == -1:
            return None
        header_bytes = raw[:header_end]
        body         = raw[header_end + 4:]

        lines = header_bytes.decode(errors="replace").split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2:
            return None
        version     = parts[0]
        status_code = int(parts[1])
        reason      = parts[2] if len(parts) > 2 else ""

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

        return HttpResponse(
            version=version, status_code=status_code, reason=reason,
            headers=headers, body=body, raw=raw,
        )
    except Exception:
        return None


def rebuild_request(display_text: str) -> bytes:
    """Rebuild raw request bytes from the editable display text (used in Repeater)."""
    lines = display_text.replace("\r\n", "\n").split("\n")
    # Find blank line separating headers from body
    try:
        blank = lines.index("")
        header_lines = lines[:blank]
        body_lines   = lines[blank + 1:]
    except ValueError:
        header_lines = lines
        body_lines   = []

    raw  = "\r\n".join(header_lines) + "\r\n\r\n"
    body = "\n".join(body_lines)
    if body:
        raw += body
    return raw.encode()


def highlight_params(text: str) -> list[tuple[int, int, str]]:
    """Return (start, end, tag) spans for injectable parameters in a request."""
    spans = []
    for m in re.finditer(r"([A-Za-z_][\w.-]*)=([^&\s]*)", text):
        spans.append((m.start(), m.end(), "param"))
    return spans
