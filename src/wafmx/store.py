"""In-memory TTL cache and optional SQLite history (host-level only, no paths)."""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class TTLCache:
    def __init__(self, ttl: float, max_items: int = 512):
        self.ttl = ttl
        self.max_items = max_items
        self._d: dict[Any, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        with self._lock:
            hit = self._d.get(key)
            if not hit:
                return None
            if time.monotonic() - hit[0] > self.ttl:
                del self._d[key]
                return None
            return hit[1]

    def put(self, key: Any, value: Any) -> None:
        with self._lock:
            if len(self._d) >= self.max_items:
                oldest = min(self._d, key=lambda k: self._d[k][0])
                del self._d[oldest]
            self._d[key] = (time.monotonic(), value)

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


@dataclass
class HistoryRow:
    ts: float
    host: str
    status: str
    mx: str
    http_status: int


class History:
    """Tiny append-only log. Only the host is stored, never full URLs/paths/queries."""

    def __init__(self, path: Path, max_entries: int = 200):
        self.path = path
        self.max_entries = max_entries
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS history ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, host TEXT NOT NULL, "
                "status TEXT NOT NULL, mx TEXT NOT NULL, http_status INTEGER NOT NULL)"
            )

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.path), timeout=5)
        return c

    def add(self, host: str, status: str, mx: str, http_status: int) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO history (ts, host, status, mx, http_status) VALUES (?,?,?,?,?)",
                (time.time(), host, status, mx or "", http_status or 0),
            )
            c.execute(
                "DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT ?)",
                (self.max_entries,),
            )

    def recent(self, limit: int = 100) -> list[HistoryRow]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT ts, host, status, mx, http_status FROM history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [HistoryRow(*r) for r in rows]

    def clear(self) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM history")
