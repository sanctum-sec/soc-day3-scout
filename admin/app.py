import os
import re
import secrets
import sys
from pathlib import Path

# ensure parent package is importable when run standalone
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from storage.db import (
    get_broadcast_queue_depth,
    get_feed_health,
    get_ioc_totals,
    get_top_queried,
    init_db,
)

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
SECURITY_LOG = Path(__file__).parent.parent / "security.log"

security = HTTPBasic()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["enumerate"] = enumerate

app = FastAPI(title="IOC Admin", docs_url=None, redoc_url=None)


def require_auth(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    ok = (
        secrets.compare_digest(credentials.username.encode(), ADMIN_USER.encode())
        and secrets.compare_digest(credentials.password.encode(), ADMIN_PASS.encode())
    )
    if not ok:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    return credentials.username


_LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+"
    r"(?P<level>\w+)\s+(?P<logger>\S+):\s+(?P<message>.*)$"
)


def _parse_security_log(n: int = 50) -> list[dict]:
    if not SECURITY_LOG.exists():
        return []
    lines = SECURITY_LOG.read_text().splitlines()
    entries = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        m = _LOG_RE.match(line)
        if m:
            entries.append(m.groupdict())
        else:
            entries.append({"ts": "", "level": "UNKNOWN", "logger": "", "message": line})
        if len(entries) >= n:
            break
    return entries


# ── routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
def index(request: Request, _: str = Depends(require_auth)):
    return templates.TemplateResponse(request, "base.html")


@app.get("/partials/operational", response_class=HTMLResponse)
def partial_operational(request: Request, _: str = Depends(require_auth)):
    return templates.TemplateResponse(request, "partials/operational.html", {
        "feed_health": get_feed_health(),
        "ioc_totals": get_ioc_totals(),
        "top_queried": get_top_queried(10),
        "queue_depth": get_broadcast_queue_depth(),
    })


@app.get("/partials/security", response_class=HTMLResponse)
def partial_security(request: Request, _: str = Depends(require_auth)):
    return templates.TemplateResponse(request, "partials/security.html", {
        "log_entries": _parse_security_log(50),
    })


if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run("admin.app:app", host="0.0.0.0", port=8001, reload=True)
