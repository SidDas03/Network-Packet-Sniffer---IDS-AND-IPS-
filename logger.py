"""
logger.py  –  NPS-IDS persistent SQLite alert logger
------------------------------------------------------
SECURITY FIXES applied:
  V05 – DB path traversal: DB_PATH is pinned to the project directory
        and file permissions are set to owner-only (0o600) on creation.
  V08 – Silent exception swallowing: errors now print a descriptive
        message rather than being silently discarded.
  All queries already used parameterised statements — no SQL injection risk.
"""

import os
import sqlite3
import stat
import threading
import time
from pathlib import Path

# V05: pin DB to the project directory — never accept an external path
DB_PATH = Path(__file__).parent.resolve() / "nps_ids.db"
_lock   = threading.Lock()

_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    ts_str    TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    src_ip    TEXT    NOT NULL,
    message   TEXT    NOT NULL,
    severity  TEXT    NOT NULL,
    blocked   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ts       ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_kind     ON alerts(kind);
CREATE INDEX IF NOT EXISTS idx_src_ip   ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity);
"""

# Valid severity values — anything else is normalised to INFO
_VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR"})


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(DB_PATH), timeout=10)
    c.row_factory = sqlite3.Row
    return c


def _init() -> None:
    with _lock:
        with _conn() as c:
            c.executescript(_DDL)
    # V05: restrict DB file to owner read/write only after creation
    try:
        os.chmod(str(DB_PATH), stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass  # Windows doesn't support chmod — silently skip

_init()


def log_alert(kind: str, src_ip: str, message: str,
              severity: str, blocked: bool = False) -> None:
    """Write one alert row. Thread-safe."""
    now = time.time()
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

    # normalise / clamp inputs
    kind     = str(kind    or "unknown")[:64]
    src_ip   = str(src_ip  or "unknown")[:45]
    message  = str(message or "")[:512]
    severity = severity if severity in _VALID_SEVERITIES else "INFO"

    try:
        with _lock:
            with _conn() as c:
                c.execute(
                    "INSERT INTO alerts "
                    "(ts, ts_str, kind, src_ip, message, severity, blocked)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (now, ts_str, kind, src_ip, message, severity, int(bool(blocked)))
                )
    except sqlite3.OperationalError as e:
        # V08: report database errors explicitly
        print(f"[logger] DB write failed (operational): {e}")
    except sqlite3.DatabaseError as e:
        print(f"[logger] DB write failed (database): {e}")
    except Exception as e:
        print(f"[logger] Unexpected write error: {e}")


def get_recent(limit: int = 200) -> list[dict]:
    """Return the most recent `limit` alerts, newest first."""
    limit = max(1, min(limit, 10_000))   # clamp to safe range
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[logger] get_recent failed: {e}")  # V08
        return []


def get_all() -> list[dict]:
    try:
        with _conn() as c:
            rows = c.execute("SELECT * FROM alerts ORDER BY ts ASC").fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[logger] get_all failed: {e}")     # V08
        return []


def get_summary(hours: int = 24) -> dict:
    hours = max(1, min(hours, 8760))   # clamp: 1h – 1y
    since = time.time() - hours * 3600
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT kind, src_ip, severity FROM alerts WHERE ts >= ?",
                (since,)
            ).fetchall()
    except Exception as e:
        print(f"[logger] get_summary failed: {e}")  # V08
        return {}

    sev_counts  = {}
    kind_counts = {}
    ip_counts   = {}
    for r in rows:
        sev_counts[r["severity"]]  = sev_counts.get(r["severity"],  0) + 1
        kind_counts[r["kind"]]     = kind_counts.get(r["kind"],     0) + 1
        ip_counts[r["src_ip"]]     = ip_counts.get(r["src_ip"],     0) + 1

    return {
        "severity_counts": sev_counts,
        "kind_counts":     kind_counts,
        "top_ips":         sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "total":           len(rows),
        "hours":           hours,
    }


def clear_old(days: int = 30) -> int:
    """Delete alerts older than `days` days. Returns rows deleted."""
    days   = max(1, min(days, 3650))
    cutoff = time.time() - days * 86400
    try:
        with _lock:
            with _conn() as c:
                cur = c.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
                return cur.rowcount
    except Exception as e:
        print(f"[logger] clear_old failed: {e}")   # V08
        return 0
