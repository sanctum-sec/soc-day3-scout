import logging
import os
import threading
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import broadcaster
from feeds import scheduler as feed_scheduler
from schemas.envelope import EventEnvelope
from storage.db import (
    get_bad_ips, get_ioc, get_ioc_by_type, init_db,
    log_query, upsert_ioc,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

OBSERVE_TOKEN = os.environ.get("OBSERVE_TOKEN", "changeme")
SOC_PROTOCOL_TOKEN = os.environ.get("SOC_PROTOCOL_TOKEN", "")
bearer = HTTPBearer(auto_error=False)
limiter = Limiter(key_func=get_remote_address)

_rl_store: dict[str, list[float]] = defaultdict(list)
_rl_lock = threading.Lock()
_RL_LIMIT = 60
_RL_WINDOW = 60.0

def ingest_rate_limit(request: Request):
    ip = request.client.host if request.client else "0.0.0.0"
    now = time.time()
    with _rl_lock:
        _rl_store[ip] = [t for t in _rl_store[ip] if now - t < _RL_WINDOW]
        if len(_rl_store[ip]) >= _RL_LIMIT:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
        _rl_store[ip].append(now)


@asynccontextmanager
async def lifespan(_: "FastAPI"):
    init_db()
    feed_scheduler.start()
    broadcaster.start()
    yield
    broadcaster.stop()
    feed_scheduler.stop()


app = FastAPI(title="IOC Service", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def require_token(credentials: HTTPAuthorizationCredentials | None = Security(bearer)):
    token = credentials.credentials if credentials else ""
    valid_tokens = {t for t in [OBSERVE_TOKEN, SOC_PROTOCOL_TOKEN] if t}
    if token not in valid_tokens:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


_REQUIRED_FIELDS = {"event_id", "timestamp", "source", "ioc_value", "ioc_type", "reputation_score"}

def require_json(request: Request):
    ct = request.headers.get("content-type", "")
    if "application/json" not in ct:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Content-Type must be application/json")


async def require_fields(request: Request):
    try:
        body = await request.json()
        if isinstance(body, dict) and (body.keys() & _REQUIRED_FIELDS):
            missing = _REQUIRED_FIELDS - set(body.keys())
            if missing:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Missing required fields: {sorted(missing)}")
    except HTTPException:
        raise
    except Exception:
        pass


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": exc.errors()})


# ── health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


# ── GET /ioc/bad-ips ───────────────────────────────────────────────────────────

@app.get("/ioc/bad-ips")
@limiter.limit("200/minute")
def bad_ips(request: Request, min_score: int = 70, since: str | None = None):
    return get_bad_ips(min_score=min_score, since=since)


# ── GET /enrich ────────────────────────────────────────────────────────────────

@app.get("/enrich")
@limiter.limit("200/minute")
def enrich(request: Request, ip: str | None = None, domain: str | None = None, hash: str | None = None):
    if ip:
        record = get_ioc_by_type(ip, "ip") or get_ioc(ip)
        value = ip
    elif domain:
        record = get_ioc_by_type(domain, "domain") or get_ioc(domain)
        value = domain
    elif hash:
        record = get_ioc_by_type(hash, "hash") or get_ioc(hash)
        value = hash
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provide ?ip=, ?domain=, or ?hash=")
    log_query(value)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    return record


# ── POST /ingest + /observe ────────────────────────────────────────────────────

def _handle_observe(envelope: EventEnvelope) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    existing = get_ioc(envelope.ioc_value)
    if existing:
        merged_tags = list(set(existing["tags"]) | set(envelope.tags) | {"community_submitted"})
        upsert_ioc({
            "ioc_value": envelope.ioc_value,
            "ioc_type": existing["ioc_type"],
            "source": existing["source"],
            "first_seen": existing["first_seen"],
            "last_seen": now,
            "tags": merged_tags,
            "reputation_score": existing["reputation_score"],
        })
    else:
        upsert_ioc({
            "ioc_value": envelope.ioc_value,
            "ioc_type": envelope.ioc_type,
            "source": "community",
            "first_seen": now,
            "last_seen": now,
            "tags": list(set(envelope.tags) | {"community_submitted"}),
            "reputation_score": 40,
        })
    return {"accepted": True, "event_id": envelope.event_id}


@app.post("/ingest", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(ingest_rate_limit), Depends(require_token), Depends(require_json), Depends(require_fields)])
def ingest(envelope: EventEnvelope):
    return _handle_observe(envelope)


@app.post("/observe", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(ingest_rate_limit), Depends(require_token), Depends(require_json), Depends(require_fields)])
def observe(envelope: EventEnvelope):
    return _handle_observe(envelope)
