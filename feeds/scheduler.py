import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from feeds import firehol, spamhaus, tor, urlhaus, threatfox
from storage.db import get_ioc, log_feed_run, upsert_ioc

log = logging.getLogger(__name__)

_BASE_SCORES: dict[str, int] = {
    "firehol": 70,
    "spamhaus": 70,
    "tor": 70,
    "urlhaus": 85,
    "threatfox": 85,
}


def _calc_score(sources: set[str]) -> int:
    base = max((_BASE_SCORES.get(s, 50) for s in sources), default=50)
    n = len(sources)
    boost = 15 if n >= 3 else (10 if n >= 2 else 0)
    return min(100, base + boost)


async def run_all_feeds() -> None:
    log.info("Feed run started")
    now = datetime.now(timezone.utc).isoformat()

    ioc_map: dict[str, dict] = {}

    def add(value: str, ioc_type: str, source: str, extra_tags: list[str] | None = None) -> None:
        value = value.strip()
        if not value:
            return
        if value not in ioc_map:
            ioc_map[value] = {"ioc_type": ioc_type, "sources": set(), "tags": set()}
        ioc_map[value]["sources"].add(source)
        if extra_tags:
            ioc_map[value]["tags"].update(t for t in extra_tags if t)

    # ── fetch all feeds ────────────────────────────────────────────────────────

    try:
        entries = await firehol.fetch()
        for ip, label in entries:
            add(ip, "ip", "firehol", [label])
        log_feed_run("firehol", "ok", len(entries))
        log.info("firehol: ok (%d)", len(entries))
    except Exception as exc:
        log_feed_run("firehol", "error", error_msg=str(exc))
        log.error("firehol feed failed: %s", exc)

    try:
        entries = await spamhaus.fetch()
        for cidr, desc in entries:
            add(cidr, "ip", "spamhaus", ["spamhaus_drop", *([desc] if desc else [])])
        log_feed_run("spamhaus", "ok", len(entries))
        log.info("spamhaus: ok (%d)", len(entries))
    except Exception as exc:
        log_feed_run("spamhaus", "error", error_msg=str(exc))
        log.error("spamhaus feed failed: %s", exc)

    try:
        entries = await tor.fetch()
        for ip in entries:
            add(ip, "ip", "tor", ["tor_exit"])
        log_feed_run("tor", "ok", len(entries))
        log.info("tor: ok (%d)", len(entries))
    except Exception as exc:
        log_feed_run("tor", "error", error_msg=str(exc))
        log.error("tor feed failed: %s", exc)

    try:
        entries = await urlhaus.fetch()
        for url, tags in entries:
            add(url, "url", "urlhaus", tags)
        log_feed_run("urlhaus", "ok", len(entries))
        log.info("urlhaus: ok (%d)", len(entries))
    except Exception as exc:
        log_feed_run("urlhaus", "error", error_msg=str(exc))
        log.error("urlhaus feed failed: %s", exc)

    try:
        entries = await threatfox.fetch()
        for item in entries:
            add(item["ioc_value"], item["ioc_type"], "threatfox", item.get("tags"))
        log_feed_run("threatfox", "ok", len(entries))
        log.info("threatfox: ok (%d)", len(entries))
    except Exception as exc:
        log_feed_run("threatfox", "error", error_msg=str(exc))
        log.error("threatfox feed failed: %s", exc)

    # ── upsert ─────────────────────────────────────────────────────────────────

    upserted = 0
    for ioc_value, meta in ioc_map.items():
        sources = meta["sources"]
        tags = list(meta["tags"] | sources)
        existing = get_ioc(ioc_value)
        upsert_ioc({
            "ioc_value": ioc_value,
            "ioc_type": meta["ioc_type"],
            "source": ",".join(sorted(sources)),
            "first_seen": existing["first_seen"] if existing else now,
            "last_seen": now,
            "tags": tags,
            "reputation_score": _calc_score(sources),
        })
        upserted += 1

    log.info("Feed run complete — %d IOCs upserted", upserted)


_scheduler = AsyncIOScheduler()


def start() -> None:
    _scheduler.add_job(
        run_all_feeds,
        trigger="interval",
        minutes=15,
        id="feeds",
        replace_existing=True,
        
    )
    _scheduler.start()
    log.info("Feed scheduler started (interval=15m)")


def stop() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
