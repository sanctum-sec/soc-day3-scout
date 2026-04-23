# Team 2 — Scout (Розвідник)

> Production SOC tool delivered at **STEP UP 3! Women's Cyber Defense Workshop** (Kraków, 21–23 April 2026) — part of a 6-team live exercise that built a working Security Operations Center in one day.

## What the team built

Threat-intelligence aggregator — pulls public feeds (URLhaus, ThreatFox, Firehol, Spamhaus, Tor exit list), enriches observables, broadcasts high-reputation IOCs to Analyst and Hunter.

## Deployed services

| Service | Role |
| --- | --- |
| `soc-scout.service` | single service running the FastAPI app on port 8000 |

Ran in production on **`wic02.sanctumsec.com`**.

## Repo layout

| Path | What's there |
| --- | --- |
| `main.py` | query API (`/ioc/bad-ips`, `/enrich`, `/observe`) |
| `broadcaster.py` | pushes newly high-scored IOCs to Analyst/Hunter |
| `feeds/` | one parser per CTI source + scheduler |
| `storage/` | SQLite IOC cache with reputation scoring |
| `admin/` | port-8001 admin dashboard |
| `schemas/` | event-envelope models |
| `scout-app/` | earlier scaffold (superseded by the root layout) |

## Running it locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
# Admin UI (if present) on port 8001 — see the team's service files
```

Required env vars (set in a local `.env` or `~/.soc_env`):

- `SOC_PROTOCOL_TOKEN` — shared bearer token used between peer SOC tools
- `ADMIN_USER` / `ADMIN_PASS` — admin page HTTP Basic credentials (if this team has an admin UI)

## Protocol implemented

This tool implements the contract defined in **[sanctum-sec/soc-protocol](https://github.com/sanctum-sec/soc-protocol)** — event envelope, bearer-token auth, MITRE ATT&CK tagging, per-port convention (8000 app / 8001 admin).

## Notes from the build day

- Reputation score = weighted sum across sources; +10 boost when an IOC is seen in 2+ sources, +15 when seen in 3+ (capped at 100)
- Read endpoints (`/ioc/bad-ips`, `/enrich`) are public so peers can poll without needing a token

## Day 3 build plan (archival)

The original build plan that guided the team during the workshop is preserved here:

- 🇬🇧 [`PLAN.en.md`](PLAN.en.md)
- 🇺🇦 [`PLAN.uk.md`](PLAN.uk.md)

The plans include a cross-cutting AI-CTI goals section covering Modules 4–6 of the Day 3 curriculum (AI-augmented CTI, AI-enabled attack patterns, AI social engineering).
