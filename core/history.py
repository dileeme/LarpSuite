"""
History — thread-safe store of all proxied request/response pairs.
Other components (proxy tab, scanner, repeater) read from this store.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from core.http_utils import HttpRequest, HttpResponse


@dataclass
class HistoryEntry:
    id:        int
    timestamp: float
    request:   HttpRequest
    response:  HttpResponse | None = None
    flagged:   bool                = False
    notes:     str                 = ""
    tags:      list[str]           = field(default_factory=list)

    @property
    def method(self) -> str:
        return self.request.method

    @property
    def host(self) -> str:
        return self.request.host

    @property
    def path(self) -> str:
        return self.request.path

    @property
    def status(self) -> str:
        if self.response:
            return str(self.response.status_code)
        return "—"

    @property
    def length(self) -> str:
        if self.response and self.response.body:
            return str(len(self.response.body))
        return "0"

    @property
    def content_type(self) -> str:
        if self.response:
            ct = self.response.content_type
            return ct.split(";")[0].strip()
        return ""


class History:
    """Central store for all proxied traffic."""

    def __init__(self):
        self._lock     = threading.Lock()
        self._entries: list[HistoryEntry] = []
        self._counter  = 0
        self._listeners: list[Callable[[HistoryEntry], None]] = []

    def add(self, request: HttpRequest, response: HttpResponse | None = None) -> HistoryEntry:
        with self._lock:
            self._counter += 1
            entry = HistoryEntry(
                id=self._counter,
                timestamp=time.time(),
                request=request,
                response=response,
            )
            self._entries.append(entry)

        for cb in self._listeners:
            try:
                cb(entry)
            except Exception:
                pass
        return entry

    def update_response(self, entry_id: int, response: HttpResponse):
        with self._lock:
            for e in self._entries:
                if e.id == entry_id:
                    e.response = response
                    break

    def get_all(self) -> list[HistoryEntry]:
        with self._lock:
            return list(self._entries)

    def get_by_id(self, entry_id: int) -> HistoryEntry | None:
        with self._lock:
            for e in self._entries:
                if e.id == entry_id:
                    return e
        return None

    def filter(
        self,
        host:   str = "",
        method: str = "",
        status: str = "",
        search: str = "",
    ) -> list[HistoryEntry]:
        with self._lock:
            results = list(self._entries)

        if host:
            results = [e for e in results if host.lower() in e.host.lower()]
        if method:
            results = [e for e in results if e.method.upper() == method.upper()]
        if status:
            results = [e for e in results if e.status.startswith(status)]
        if search:
            sl = search.lower()
            results = [
                e for e in results
                if sl in e.request.to_display().lower()
                or (e.response and sl in e.response.to_display().lower())
            ]
        return results

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._counter = 0

    def on_new_entry(self, callback: Callable[[HistoryEntry], None]):
        """Register a callback invoked whenever a new entry is added."""
        self._listeners.append(callback)

    def __len__(self):
        with self._lock:
            return len(self._entries)


# Singleton shared across all modules
history = History()
