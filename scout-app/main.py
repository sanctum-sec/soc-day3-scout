import os
import json
import logging
import logging.handlers
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from schemas.envelope import EventEnvelope
from storage.db import init_db, upsert_ioc, log_query, get_conn

# ── Config ────────────────────────────────────────────────────────────────────
SOC_TOKEN = os.getenv("SOC_PROTOCOL_TOKEN", "")
LOG_DIR   = Path(os.getenv("LOG_DIR", "/home/ubuntu/app/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ── Security log (append-only JSON-lines) ────────────────────────────────────
sec_logger = logging.getLogger("security")
sec_logger.setLevel(logging.INFO)
_sh = logging.FileHandler(LOG_DIR / "security.log")
_sh.setFormatter(logging.Formatter("%(message)s"))
sec_logger.addHandler(_sh)

def sec_log(event: str, detail: str, ip: str = ""):
    sec_logger.info(json.dumps({
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": event, "detail": detail, "ip": ip
    }))


# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Scout — CTI Library", version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Mock data (used until real feeds are running) ─────────────────────────────
MOCK_IPS = [
    {"ip": "198.51.100.1",  "score": 92, "tags": ["scanner","tor-exit"],    "last_seen": "2026-04-23T09:00:00Z"},
    {"ip": "203.0.113.42",  "score": 88, "tags": ["brute-force","firehol"], "last_seen": "2026-04-23T08:30:00Z"},
    {"ip": "192.0.2.77",    "score": 75, "tags": ["spamhaus-drop"],         "last_seen": "2026-04-23T07:00:00Z"},
    {"ip": "185.220.101.5", "score": 95, "tags": ["tor-exit","scanner"],    "last_seen": "2026-04-23T09:10:00Z"},
    {"ip": "45.155.205.93", "score": 85, "tags": ["brute-force","urlhaus"], "last_seen": "2026-04-23T08:55:00Z"},
]
MOCK_ENRICH = {
    "198.51.100.42": {
        "ioc_value": "198.51.100.42", "ioc_type": "ipv4",
        "reputation_score": 88,
        "tags": ["brute-force", "tor-exit"],
        "sources": ["firehol_level1", "tor-exit-list"],
        "first_seen": "2026-01-15T00:00:00Z",
        "last_seen": "2026-04-23T09:00:00Z",
    }
}


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    init_db()


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "tool": "scout", "version": "0.1.0"}


# ── GET /ioc/bad-ips ──────────────────────────────────────────────────────────
@app.get("/ioc/bad-ips")
@limiter.limit("200/minute")
def bad_ips(request: Request, since: Optional[str] = Query(None)):
    """Return known-bad IPs with reputation_score >= 70.
    Optional ?since=<ISO8601> filters to records updated after that time.
    Falls back to mock data if the database is empty."""
    conn = get_conn()
    if since:
        rows = conn.execute(
            "SELECT ioc_value, reputation_score, tags, last_seen FROM iocs "
            "WHERE ioc_type='ipv4' AND reputation_score >= 70 AND last_seen > ? "
            "ORDER BY reputation_score DESC LIMIT 2000",
            (since,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT ioc_value, reputation_score, tags, last_seen FROM iocs "
            "WHERE ioc_type='ipv4' AND reputation_score >= 70 "
            "ORDER BY reputation_score DESC LIMIT 2000"
        ).fetchall()
    conn.close()

    if rows:
        return [
            {"ip": r["ioc_value"], "score": r["reputation_score"],
             "tags": json.loads(r["tags"]), "last_seen": r["last_seen"]}
            for r in rows
        ]
    # DB empty — return mock so Trap can develop against us
    return MOCK_IPS


# ── GET /enrich ───────────────────────────────────────────────────────────────
@app.get("/enrich")
@limiter.limit("200/minute")
def enrich(
    request: Request,
    ip: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    hash: Optional[str] = Query(None),
):
    """Return the full IOC record for one observable, or 404."""
    if ip:
        value, ioc_type = ip, "ipv4"
    elif domain:
        value, ioc_type = domain, "domain"
    elif hash:
        value, ioc_type = hash, "hash"
    else:
        raise HTTPException(status_code=400, detail="Provide ?ip=, ?domain=, or ?hash=")

    caller = request.client.host if request.client else "unknown"

    # check DB first
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM iocs WHERE ioc_value=? AND ioc_type=?", (value, ioc_type)
    ).fetchone()
    conn.close()

    if row:
        log_query("/enrich", value, caller, True)
        return {
            "ioc_value":        row["ioc_value"],
            "ioc_type":         row["ioc_type"],
            "reputation_score": row["reputation_score"],
            "tags":             json.loads(row["tags"]),
            "sources":          json.loads(row["sources"]),
            "first_seen":       row["first_seen"],
            "last_seen":        row["last_seen"],
        }

    # fallback mock for Trap integration before feeds run
    if ip and ip in MOCK_ENRICH:
        log_query("/enrich", value, caller, True)
        return MOCK_ENRICH[ip]

    log_query("/enrich", value, caller, False)
    raise HTTPException(status_code=404, detail="IOC not found")


# ── POST /observe ─────────────────────────────────────────────────────────────
@app.post("/observe", status_code=202)
@limiter.limit("60/minute")
def observe(
    event: EventEnvelope,
    request: Request,
    authorization: str = Header(...),
):
    """Accept an observable from a peer (Trap / Hunter).
    Requires Bearer token. Stores with low confidence until confirmed by a feed."""
    caller = request.client.host if request.client else "unknown"

    # auth
    if not SOC_TOKEN:
        sec_log("config_error", "SOC_PROTOCOL_TOKEN not set", caller)
        raise HTTPException(status_code=500, detail="Server misconfigured")
    if authorization != f"Bearer {SOC_TOKEN}":
        sec_log("auth_failure", "Bad token on /observe", caller)
        raise HTTPException(status_code=401, detail="Unauthorized")

    # extract observable
    obs = event.observables
    if obs is None:
        raise HTTPException(status_code=400, detail="observables field required")

    ioc_value = obs.source_ip or obs.domain or obs.file_hash_sha256 or obs.url
    if not ioc_value:
        raise HTTPException(status_code=400, detail="No usable observable (source_ip/domain/hash/url)")

    if obs.source_ip:
        ioc_type = "ipv4"
    elif obs.domain:
        ioc_type = "domain"
    elif obs.file_hash_sha256:
        ioc_type = "hash"
    else:
        ioc_type = "url"

    upsert_ioc(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        source="community",
        tags=["community_submitted", f"from:{event.producer}"],
        score_base=40,   # low confidence — needs feed confirmation
    )

    return {"status": "accepted", "ioc": ioc_value, "type": ioc_type}


# ── 422 handler — log schema rejections ──────────────────────────────────────
@app.exception_handler(422)
async def validation_exception_handler(request: Request, exc):
    caller = request.client.host if request.client else "unknown"
    sec_log("schema_rejection", str(exc.errors() if hasattr(exc, "errors") else exc), caller)
    return JSONResponse(status_code=422, content={"detail": "Invalid event envelope"})
