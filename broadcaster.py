import os
import sys
import json
import time
import logging
import httpx
from datetime import datetime, timezone

sys.path.insert(0, "/home/ubuntu/app")
from storage.db import get_unbroadcast, mark_broadcast

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("broadcaster")

PEERS = [
    "http://wic03.sanctumsec.com:8000/ingest",
    "http://wic04.sanctumsec.com:8000/context",
]
SOC_TOKEN = os.getenv("SOC_PROTOCOL_TOKEN", "")


def _now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_envelope(row):
    obs = {}
    ioc_type = row.get("ioc_type", "ipv4")
    ioc_value = row.get("ioc_value", "")
    if ioc_type == "ipv4":
        obs["source_ip"] = ioc_value
    elif ioc_type == "domain":
        obs["domain"] = ioc_value
    elif ioc_type == "hash":
        obs["file_hash_sha256"] = ioc_value
    elif ioc_type == "url":
        obs["url"] = ioc_value

    score = row.get("reputation_score", 70)
    return {
        "schema_version": "1.0",
        "event_id": f"scout-{ioc_value[:16]}-{int(time.time())}",
        "event_type": "ioc",
        "timestamp": _now_utc(),
        "producer": "scout",
        "severity": "high" if score >= 85 else "medium",
        "observables": obs,
        "data": {
            "reputation_score": score,
            "tags": row.get("tags", []),
        }
    }


def broadcast_once():
    if not SOC_TOKEN:
        log.error("SOC_PROTOCOL_TOKEN not set")
        return

    rows = get_unbroadcast(min_score=70, within_seconds=30)
    if not rows:
        log.info("No new IOCs to broadcast")
        return

    log.info(f"Broadcasting {len(rows)} IOCs")
    headers = {"Authorization": f"Bearer {SOC_TOKEN}"}

    for row in rows:
        envelope = build_envelope(row)
        success = True
        for peer_url in PEERS:
            try:
                resp = httpx.post(peer_url, json=envelope, headers=headers, timeout=10)
                resp.raise_for_status()
                log.info(f"Sent {row.get('ioc_value')} -> {peer_url} ({resp.status_code})")
            except Exception as e:
                log.error(f"Failed {row.get('ioc_value')} -> {peer_url}: {e}")
                success = False
        if success:
            mark_broadcast(row.get("ioc_value"))


if __name__ == "__main__":
    log.info("Broadcaster starting...")
    while True:
        broadcast_once()
        time.sleep(30)


# ── lifecycle wrappers expected by main.py ─────────────────────────────────────
import threading as _threading

_thread: _threading.Thread | None = None

def _loop():
    while True:
        try:
            broadcast_once()
        except Exception as exc:
            log.error("broadcaster error: %s", exc)
        import time as _time
        _time.sleep(30)

def start():
    global _thread
    log.info("Broadcaster starting...")
    _thread = _threading.Thread(target=_loop, daemon=True, name="broadcaster")
    _thread.start()

def stop():
    log.info("Broadcaster stopped.")
