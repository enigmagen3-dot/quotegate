#!/usr/bin/env python3
"""
Live Web Service for PULSAR quotegate (/check and /api/check/*).
Zero external dependencies (Python 3 stdlib + sqlite3).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Deque, Dict, Optional

import quotegate_engine as qg

HOST = os.environ.get("QUOTEGATE_HOST", "127.0.0.1")
PORT = int(os.environ.get("QUOTEGATE_PORT", "8787"))
DB_PATH = os.environ.get("QUOTEGATE_DB", os.path.join(os.path.dirname(__file__), "scans.sqlite3"))
HTML_PATH = os.path.join(os.path.dirname(__file__), "web", "index.html")
PUBLIC_BASE = os.environ.get("QUOTEGATE_PUBLIC_BASE", "https://pulsare-lab.space").rstrip("/")
SALT = os.environ.get("QUOTEGATE_IP_SALT", "pulsar-quotegate-2026")
RATE_WINDOW_SEC = 600
RATE_MAX_REQ = 25
MAX_INPUT_CHARS = 40_000
_REPORT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{6,24}$")

_rate_buckets: Dict[str, Deque[float]] = defaultdict(deque)


def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            mode TEXT NOT NULL,
            ok_count INTEGER NOT NULL,
            fail_count INTEGER NOT NULL,
            skip_count INTEGER NOT NULL,
            total_count INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            ip_hash TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event_name TEXT NOT NULL,
            meta TEXT DEFAULT '',
            ip_hash TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


_DB = init_db()


def _save_report(audit: dict) -> str:
    rid = secrets.token_hex(5)
    payload = json.dumps(audit, ensure_ascii=False)
    _DB.execute(
        "INSERT OR REPLACE INTO reports (id, ts, payload_json) VALUES (?, datetime('now'), ?)",
        (rid, payload),
    )
    _DB.commit()
    return rid


def _load_report(rid: str) -> Optional[dict]:
    if not _REPORT_ID_RE.match(rid):
        return None
    row = _DB.execute("SELECT ts, payload_json FROM reports WHERE id = ?", (rid,)).fetchone()
    if not row:
        return None
    try:
        data = json.loads(row[1])
        data["report_id"] = rid
        data["created_at"] = row[0]
        return data
    except Exception:
        return None


def _ip_hash(client_ip: str) -> str:
    return hashlib.sha256(f"{SALT}:{client_ip}".encode("utf-8")).hexdigest()[:16]


def _check_rate_limit(ip_key: str) -> bool:
    now = time.time()
    q = _rate_buckets[ip_key]
    while q and q[0] < now - RATE_WINDOW_SEC:
        q.popleft()
    if len(q) >= RATE_MAX_REQ:
        return False
    q.append(now)
    return True


def _get_stats() -> dict:
    row = _DB.execute(
        """
        SELECT
            COUNT(*) AS total_scans,
            COALESCE(SUM(fail_count), 0) AS hallucinations_caught,
            COALESCE(SUM(ok_count), 0) AS ok_verified,
            COALESCE(SUM(skip_count), 0) AS skipped_safe
        FROM scans
        """
    ).fetchone()
    return {
        "total_scans": int(row[0] or 0),
        "hallucinations_caught": int(row[1] or 0),
        "ok_verified": int(row[2] or 0),
        "skipped_safe": int(row[3] or 0),
    }


class QuotegateHandler(BaseHTTPRequestHandler):
    server_version = "PULSAR-Quotegate/1.1"

    def _client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        xri = self.headers.get("X-Real-IP", "").strip()
        return xff or xri or (self.client_address[0] if self.client_address else "unknown")

    def _send_json(self, code: int, payload: dict, head_only: bool = False) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(raw)

    def _send_html(self, code: int, path: str, head_only: bool = False) -> None:
        with open(path, "rb") as f:
            raw = f.read()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.end_headers()
        if not head_only:
            self.wfile.write(raw)

    def _send_report_html(self, rid: str, head_only: bool = False) -> None:
        import html as _html
        with open(HTML_PATH, "r", encoding="utf-8") as f:
            page = f.read()
        rep = _load_report(rid)
        if rep:
            s = rep.get("summary") or {}
            verdict = rep.get("verdict", "AUDITED")
            og_title = f"QuoteGate Audit [{verdict}]: OK={s.get('ok', 0)} FAIL={s.get('fail', 0)} SKIP={s.get('skip', 0)}"
            first_fail = next((r for r in (rep.get("results") or []) if r.get("status") == "FAIL"), None)
            if first_fail:
                og_desc = f"Caught: {first_fail.get('reason', '')} — {first_fail.get('claim', '')[:120]}"
            else:
                og_desc = "Deterministic verification against live HTTP 200 sources via PULSAR QuoteGate (MIT)."
            og_url = f"{PUBLIC_BASE}/check/r/{rid}"
            meta = (
                f'<title>{_html.escape(og_title)}</title>\n'
                f'  <meta property="og:title" content="{_html.escape(og_title)}" />\n'
                f'  <meta property="og:description" content="{_html.escape(og_desc)}" />\n'
                f'  <meta property="og:url" content="{_html.escape(og_url)}" />'
            )
            page = re.sub(r"<title>.*?</title>", lambda _m: meta, page, count=1, flags=re.S)
        raw = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.end_headers()
        if not head_only:
            self.wfile.write(raw)

    def log_message(self, fmt: str, *args) -> None:
        # Keep stdout compact for systemd journal
        pass

    def do_HEAD(self) -> None:
        self._handle_get(head_only=True)

    def do_GET(self) -> None:
        self._handle_get(head_only=False)

    def _handle_get(self, head_only: bool = False) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/check", "/check/", "/"):
            return self._send_html(200, HTML_PATH, head_only=head_only)
        if path.startswith("/check/r/"):
            rid = path.split("/check/r/", 1)[1].strip("/")
            return self._send_report_html(rid, head_only=head_only)
        if path == "/api/check/healthz":
            return self._send_json(200, {"ok": True, "service": "quotegate-web", "version": "1.1"}, head_only=head_only)
        if path == "/api/check/stats":
            return self._send_json(200, {"ok": True, "stats": _get_stats()}, head_only=head_only)
        if path.startswith("/api/check/report/"):
            rid = path.split("/api/check/report/", 1)[1].strip("/")
            rep = _load_report(rid)
            if not rep:
                return self._send_json(404, {"ok": False, "error": "Report not found"}, head_only=head_only)
            return self._send_json(200, {"ok": True, "audit": rep, "stats": _get_stats()}, head_only=head_only)
        self._send_json(404, {"error": "Not found"}, head_only=head_only)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send_json(400, {"error": "Invalid Content-Length"})
        if length <= 0 or length > 120_000:
            return self._send_json(400, {"error": "Payload size out of range"})

        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return self._send_json(400, {"error": "Invalid JSON body"})

        ip_hash = _ip_hash(self._client_ip())

        if path == "/api/check/event":
            ev = str(data.get("event", "")).strip()[:64]
            meta = str(data.get("meta", "")).strip()[:180]
            if ev:
                _DB.execute(
                    "INSERT INTO events (ts, event_name, meta, ip_hash) VALUES (datetime('now'), ?, ?, ?)",
                    (ev, meta, ip_hash),
                )
                _DB.commit()
            return self._send_json(200, {"ok": True})

        if path == "/api/check/run":
            if not _check_rate_limit(ip_hash):
                return self._send_json(429, {"error": "Rate limit exceeded (25 scans / 10 min). Wait a bit or use the free MIT CLI."})

            raw_input = str(data.get("input", "")).strip()
            if not raw_input:
                return self._send_json(400, {"error": "Paste a report with URLs or an article URL to check."})
            if len(raw_input) > MAX_INPUT_CHARS:
                return self._send_json(400, {"error": f"Input exceeds {MAX_INPUT_CHARS} character limit."})

            audit = qg.audit_input(raw_input)
            s = audit.get("summary", {})
            _DB.execute(
                """
                INSERT INTO scans (ts, mode, ok_count, fail_count, skip_count, total_count, verdict, ip_hash)
                VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit.get("mode", "unknown"),
                    int(s.get("ok", 0)),
                    int(s.get("fail", 0)),
                    int(s.get("skip", 0)),
                    int(s.get("total", 0)),
                    audit.get("verdict", "SKIPPED"),
                    ip_hash,
                ),
            )
            _DB.commit()
            rid = _save_report(audit)
            share_url = f"{PUBLIC_BASE}/check/r/{rid}"
            audit["report_id"] = rid
            audit["share_url"] = share_url
            return self._send_json(200, {"ok": True, "audit": audit, "report_id": rid, "share_url": share_url, "stats": _get_stats()})

        return self._send_json(404, {"error": "Not found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), QuotegateHandler)
    print(f"[quotegate-web] listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
