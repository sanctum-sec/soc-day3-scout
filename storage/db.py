import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "ioc.db"

_CREATE_IOC = """
CREATE TABLE IF NOT EXISTS ioc (
    ioc_value         TEXT PRIMARY KEY,
    ioc_type          TEXT NOT NULL,
    source            TEXT NOT NULL,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    tags              TEXT NOT NULL DEFAULT '[]',
    reputation_score  INTEGER NOT NULL DEFAULT 0,
    already_broadcast INTEGER NOT NULL DEFAULT 0
)
"""

_CREATE_FEED_RUNS = """
CREATE TABLE IF NOT EXISTS feed_runs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    feed      TEXT NOT NULL,
    ran_at    TEXT NOT NULL,
    status    TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    error_msg TEXT NOT NULL DEFAULT ''
)
"""

_CREATE_QUERY_LOG = """
CREATE TABLE IF NOT EXISTS query_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value  TEXT NOT NULL,
    queried_at TEXT NOT NULL
)
"""


def init_db() -> None:
    with connect() as conn:
        conn.execute(_CREATE_IOC)
        conn.execute(_CREATE_FEED_RUNS)
        conn.execute(_CREATE_QUERY_LOG)
        # migrate existing DBs
        cols = {r[1] for r in conn.execute("PRAGMA table_info(ioc)")}
        if "already_broadcast" not in cols:
            conn.execute("ALTER TABLE ioc ADD COLUMN already_broadcast INTEGER NOT NULL DEFAULT 0")


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── IOC ────────────────────────────────────────────────────────────────────────

def upsert_ioc(row: dict) -> None:
    row = {**row, "tags": json.dumps(row.get("tags", []))}
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO ioc (ioc_value, ioc_type, source, first_seen, last_seen, tags, reputation_score)
            VALUES (:ioc_value, :ioc_type, :source, :first_seen, :last_seen, :tags, :reputation_score)
            ON CONFLICT(ioc_value) DO UPDATE SET
                last_seen         = excluded.last_seen,
                tags              = excluded.tags,
                reputation_score  = excluded.reputation_score,
                already_broadcast = 0
            """,
            row,
        )


def get_bad_ips(min_score: int = 70, since: str | None = None) -> list[dict]:
    sql = """
        SELECT ioc_value AS ip, reputation_score AS score, tags, last_seen
        FROM ioc WHERE ioc_type = 'ip' AND reputation_score >= ?
    """
    params: list = [min_score]
    if since:
        sql += " AND last_seen > ?"
        params.append(since)
    sql += " ORDER BY reputation_score DESC"
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [{"ip": r["ip"], "score": r["score"], "tags": json.loads(r["tags"]), "last_seen": r["last_seen"]} for r in rows]


def get_ioc(ioc_value: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM ioc WHERE ioc_value = ?", (ioc_value,)).fetchone()
    return _row_to_dict(row) if row else None


def get_ioc_by_type(value: str, ioc_type: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM ioc WHERE ioc_value = ? AND ioc_type = ?", (value, ioc_type)
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_unbroadcast(min_score: int = 70, within_seconds: int = 30) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM ioc
            WHERE reputation_score >= ? AND already_broadcast = 0
              AND last_seen >= datetime('now', ?)
            """,
            (min_score, f"-{within_seconds} seconds"),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def mark_broadcast(ioc_value: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE ioc SET already_broadcast = 1 WHERE ioc_value = ?", (ioc_value,))


def get_ioc_totals() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT ioc_type, COUNT(*) AS count FROM ioc GROUP BY ioc_type ORDER BY count DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_broadcast_queue_depth() -> int:
    with connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM ioc WHERE reputation_score >= 70 AND already_broadcast = 0"
        ).fetchone()[0]


# ── feed runs ──────────────────────────────────────────────────────────────────

def log_feed_run(feed: str, status: str, count: int = 0, error_msg: str = "") -> None:
    from datetime import datetime, timezone
    with connect() as conn:
        conn.execute(
            "INSERT INTO feed_runs (feed, ran_at, status, count, error_msg) VALUES (?, ?, ?, ?, ?)",
            (feed, datetime.now(timezone.utc).isoformat(), status, count, error_msg),
        )


def get_feed_health() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM feed_runs
            WHERE id IN (SELECT MAX(id) FROM feed_runs GROUP BY feed)
            ORDER BY feed
            """
        ).fetchall()
    return [dict(r) for r in rows]


# ── query log ──────────────────────────────────────────────────────────────────

def log_query(ioc_value: str) -> None:
    from datetime import datetime, timezone
    with connect() as conn:
        conn.execute(
            "INSERT INTO query_log (ioc_value, queried_at) VALUES (?, ?)",
            (ioc_value, datetime.now(timezone.utc).isoformat()),
        )


def get_top_queried(limit: int = 10) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT ioc_value, COUNT(*) AS count FROM query_log
            WHERE queried_at >= date('now')
            GROUP BY ioc_value ORDER BY count DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── helpers ────────────────────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["tags"] = json.loads(d["tags"])
    return d
