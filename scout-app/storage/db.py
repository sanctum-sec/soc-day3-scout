import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(os.getenv("DB_PATH", "/home/ubuntu/app/scout.db"))


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS iocs (
            ioc_value        TEXT NOT NULL,
            ioc_type         TEXT NOT NULL,
            sources          TEXT NOT NULL DEFAULT '[]',
            first_seen       TEXT,
            last_seen        TEXT,
            tags             TEXT NOT NULL DEFAULT '[]',
            reputation_score INTEGER NOT NULL DEFAULT 0,
            already_broadcast INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (ioc_value, ioc_type)
        );
        CREATE INDEX IF NOT EXISTS idx_score
            ON iocs (reputation_score);
        CREATE INDEX IF NOT EXISTS idx_last_seen
            ON iocs (last_seen);
        CREATE INDEX IF NOT EXISTS idx_type_score
            ON iocs (ioc_type, reputation_score);

        CREATE TABLE IF NOT EXISTS feed_runs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name     TEXT NOT NULL,
            ran_at        TEXT NOT NULL,
            status        TEXT NOT NULL,
            count_added   INTEGER NOT NULL DEFAULT 0,
            error_msg     TEXT
        );

        CREATE TABLE IF NOT EXISTS query_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            queried_at  TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            ioc_value   TEXT,
            caller_ip   TEXT,
            found       INTEGER NOT NULL DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def upsert_ioc(ioc_value: str, ioc_type: str, source: str,
               tags: list, score_base: int) -> bool:
    """
    Insert or update an IOC.
    Returns True if this is a newly-created record or if reputation_score
    just crossed the broadcast threshold (≥70) so the broadcaster knows to push it.
    """
    conn = get_conn()
    now = _now_utc()

    existing = conn.execute(
        "SELECT * FROM iocs WHERE ioc_value=? AND ioc_type=?",
        (ioc_value, ioc_type)
    ).fetchone()

    if existing:
        sources = list(set(json.loads(existing["sources"]) + [source]))
        merged_tags = list(set(json.loads(existing["tags"]) + tags))
        old_score = existing["reputation_score"]

        boost = 0
        if len(sources) >= 3:
            boost = 15
        elif len(sources) >= 2:
            boost = 10
        new_score = min(100, score_base + boost)

        # reset broadcast flag if score just jumped over threshold
        was_broadcast = existing["already_broadcast"]
        reset_broadcast = 1 if (was_broadcast and new_score > old_score) else was_broadcast

        conn.execute("""
            UPDATE iocs
            SET last_seen=?, sources=?, tags=?, reputation_score=?,
                already_broadcast=?
            WHERE ioc_value=? AND ioc_type=?
        """, (now, json.dumps(sources), json.dumps(merged_tags),
              new_score, reset_broadcast, ioc_value, ioc_type))
        newly_created = False
    else:
        conn.execute("""
            INSERT INTO iocs
                (ioc_value, ioc_type, sources, first_seen, last_seen,
                 tags, reputation_score, already_broadcast)
            VALUES (?,?,?,?,?,?,?,0)
        """, (ioc_value, ioc_type, json.dumps([source]), now, now,
              json.dumps(tags), score_base))
        newly_created = True

    conn.commit()
    conn.close()
    return newly_created


def log_feed_run(feed_name: str, status: str, count: int, error: str = None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO feed_runs (feed_name, ran_at, status, count_added, error_msg) "
        "VALUES (?,?,?,?,?)",
        (feed_name, _now_utc(), status, count, error)
    )
    conn.commit()
    conn.close()


def log_query(endpoint: str, ioc_value: str, caller_ip: str, found: bool):
    conn = get_conn()
    conn.execute(
        "INSERT INTO query_log (queried_at, endpoint, ioc_value, caller_ip, found) "
        "VALUES (?,?,?,?,?)",
        (_now_utc(), endpoint, ioc_value, caller_ip, int(found))
    )
    conn.commit()
    conn.close()
