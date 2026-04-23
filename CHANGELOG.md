# Changelog

All notable changes to this repository. Format based on [Keep a Changelog](https://keepachangelog.com/).

---

## [post-workshop] — 2026-04-23

Post-workshop consolidation and publication pass. Everything below was done by the
workshop facilitator after the teams departed — the intent was to capture the team's
production state, redact anything unsafe for a public repo, and give the repo a
permanent shape future readers can use.

### Added

- `README.md` rewritten to describe what the team actually shipped — file layout, services, how to run locally, and a pointer to the shared protocol.
- `PLAN.en.md` / `PLAN.uk.md` — the original Day 3 build plan preserved (bilingual). These used to be the repo's README before the production code landed.
- `.gitignore` — standard Python/SQLite/log excludes.
- `CHANGELOG.md` — this file.

### Changed

- Production code imported from the team's Lightsail (`sudo tar cz` → stream → `tar xz`), excluding `.git`, `__pycache__`, virtualenvs, logs, SQLite databases, and `.env` files.
- The repo now reflects the **final state of production** at workshop close, not just the plan document.

### Security

- Hardcoded Basic Auth credentials (`wic / stepup-krakow-2026`) scrubbed from `PLAN.en.md` / `PLAN.uk.md` — replaced with "ask the instructor."
- Workshop deploy key (SSH, write-scope on this repo) was **revoked** after the workshop closed.
- GitHub Actions secrets set during the workshop (`LIGHTSAIL_HOST`, `LIGHTSAIL_PASSWORD`, `SOC_PROTOCOL_TOKEN`) were **removed** from the repo's secret store.

### Administrative

- Repository visibility flipped from **private** to **public** on 2026-04-23 as part of the workshop's open-share commitment.
- Pre-publication secret scan run on the repo: no credential patterns remain in current tree (git history still contains the original commits made during the workshop).
- Production box (`wic02.sanctumsec.com`) now runs from a git checkout of `main`; future updates propagate via `git fetch && git reset --hard origin/main`.



---

## [0.1.0] — 2026-04-23 (workshop build day)

**Team 2 — Scout (Розвідник)** shipped during the STEP UP 3! Women's Cyber
Defense Workshop in Kraków (10:45–16:30 CET).

### Summary

Built a threat-intelligence aggregator that pulls from five public CTI feeds (URLhaus, ThreatFox, Firehol, Spamhaus, Tor exit list), scores and tags IOCs, serves read endpoints (`/ioc/bad-ips`, `/enrich`) for peer tools, and broadcasts newly high-scored IOCs to Analyst and Hunter.

### Shipped to production on `wic02.sanctumsec.com` (deployed at `/home/ubuntu/app/`)

- `main.py` — FastAPI query API (`/ioc/bad-ips`, `/enrich`, `/observe`)
- `broadcaster.py` — pushes newly high-reputation IOCs to peers
- `feeds/` — one parser per CTI source + scheduler (15-minute cadence)
- `storage/` — SQLite IOC cache with reputation scoring
- `admin/` — port-8001 admin dashboard
- `schemas/` — event envelope models
- `scout-app/` — earlier scaffold, later superseded by the root layout
- `soc-scout.service` — systemd unit

### Notes from build day

- Built almost entirely with Claude Code over ~6 hours, following the Day-3 plan
  preserved in `PLAN.en.md` / `PLAN.uk.md`.
- Implements the shared contract in [`sanctum-sec/soc-protocol`](https://github.com/sanctum-sec/soc-protocol).
- Running on a `medium_3_0` Lightsail instance in `eu-central-1` (Frankfurt).

---

## [0.0.1] — 2026-04-22 (repo initialised)

- Repo created with the Day-3 team plan as `README.md` + `README.en.md` (English and
  Ukrainian versions).
- GitHub Actions secrets set: `LIGHTSAIL_HOST`, `LIGHTSAIL_PASSWORD`, `SOC_PROTOCOL_TOKEN`.
- Deploy key installed on the team's Lightsail.
- Discussions enabled.
