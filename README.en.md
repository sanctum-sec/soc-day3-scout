> **Українська версія:** [README.md](README.md)

# Team 2 — Scout (Розвідник): Threat Intelligence Aggregator

**Your Lightsail:** `wic02.sanctumsec.com` (63.179.14.154)
**Your GitHub repo:** `https://github.com/sanctum-sec/soc-day3-scout`
**Read first:** [`sanctum-sec/soc-protocol`](https://github.com/sanctum-sec/soc-protocol) — this is the contract you ship against.

---

## 1. Your mission

You are the SOC's **library**. You pull cyber threat intelligence from the open internet, clean it up, and make it queryable so every other team can answer *"is this thing bad?"* in under a second.

By the end of the day you will have:
- Periodic pulls from 3+ free public threat-intel feeds (URLhaus, ThreatFox, Firehol, Spamhaus, Tor exit list)
- A local SQLite database of IOCs (IPs, domains, hashes, URLs) with reputation, tags, and timestamps
- A query API that other teams can hit: `GET /ioc/bad-ips`, `GET /enrich?ip=…`
- A pusher that broadcasts high-severity IOCs to Analyst and Hunter as SOC Protocol `ioc` events
- An admin dashboard showing what's in your library, what you've ingested, and who's been hitting *your* API

Trap depends on you to mark attackers as known-bad. Analyst depends on you to score alerts. Hunter depends on you for context when scoring anomalies. You are everyone's second opinion.

---

## 2. Where this fits in a real SOC

From Table 1 of the 11 Strategies of a World-Class SOC (MITRE):

- **Cyber Threat Intelligence Collection, Processing, and Fusion** — you're doing all three.
- **Cyber Threat Intelligence Analysis and Production** — tagging, scoring, trending.
- **Cyber Threat Intelligence Sharing and Distribution** — you publish out to peer tools.

This is the function every mature SOC eventually builds. For today, you're building a minimum-viable version in eight hours.

---

## 3. Access and what's already on your Lightsail

```
ssh ubuntu@wic02.sanctumsec.com
# password/пароль: see https://wic-krakow.sanctumsec.com/wic-access-ghosttrace (Basic Auth: wic / stepup-krakow-2026)
```

Already installed: `git`, Python 3.10 + pip, Node.js LTS, `claude`, `codex`, AWS CLI + credentials for `s3://wic-krakow-2026`.

Outbound internet access is unrestricted — you can pull feeds freely.

---

## 4. Data flows

### 4.1 What you produce (outputs)

Two flavors of output:

**(a) On-demand query API** — other teams pull from you:

| Endpoint                                      | Who calls it        | What it returns                                                |
| --------------------------------------------- | ------------------- | -------------------------------------------------------------- |
| `GET /ioc/bad-ips?since=<timestamp>`          | **Trap** (polling)  | JSON list of known-bad IPs with scores and tags                |
| `GET /enrich?ip=1.2.3.4`                      | Any team            | Reputation record for one IP (or 404)                          |
| `GET /enrich?domain=example.com`              | Any team            | Reputation record for one domain                               |
| `GET /enrich?hash=<sha256>`                   | Any team            | Reputation record for one file hash                            |
| `GET /health`                                 | Everyone            | `{"status":"ok","tool":"scout"}`                               |

**(b) Push events** — you POST `ioc` events to:

| To team     | Endpoint                                    | When                                                            |
| ----------- | ------------------------------------------- | --------------------------------------------------------------- |
| **Analyst** | `http://wic03.sanctumsec.com:8000/ingest`   | Whenever a newly-ingested IOC has reputation ≥ 70               |
| **Hunter**  | `http://wic04.sanctumsec.com:8000/context`  | Same trigger — Hunter uses this to adjust baselines             |

### 4.2 What you consume (inputs)

**(a) External threat feeds** (free, public — no API keys needed for the starter set):

| Source                                                                                      | What you get                             | How                                |
| ------------------------------------------------------------------------------------------- | ---------------------------------------- | ---------------------------------- |
| [URLhaus](https://urlhaus.abuse.ch/downloads/)                                              | Malicious URLs                           | CSV over HTTPS, updated every 5min |
| [ThreatFox](https://threatfox.abuse.ch/export/)                                             | IOCs tagged with malware families        | JSON over HTTPS                    |
| [Firehol Level 1](https://iplists.firehol.org/?ipset=firehol_level1)                        | Known-bad IPs                            | Plain-text list                    |
| [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt)                                     | Spammer networks                         | Plain-text list                    |
| [Tor exit list](https://check.torproject.org/torbulkexitlist)                               | Current Tor exit nodes                   | Plain-text list                    |

For a bonus, get free API keys (signups take 2 minutes):
- [AbuseIPDB](https://www.abuseipdb.com/register) — 1000 checks/day free
- [AlienVault OTX](https://otx.alienvault.com/) — free, generous rate limits

**(b) Peer observables** (teams telling you "I saw this"):

| From team   | Endpoint              | What they send                           |
| ----------- | --------------------- | ---------------------------------------- |
| **Trap**    | `POST /observe`       | Fresh IPs seen attacking the honeypot    |
| **Hunter**  | `POST /observe`       | IPs/domains/hashes hunter found suspicious |

You ingest these, enrich with whatever you have, and if the reputation score crosses a threshold, broadcast an `ioc` event.

### 4.3 Example IOC event you'll emit

```json
{
  "schema_version": "1.0",
  "event_id": "<uuid>",
  "event_type": "ioc",
  "timestamp": "2026-04-23T09:16:00Z",
  "producer": "scout",
  "severity": "high",
  "observables": {
    "source_ip": "203.0.113.42"
  },
  "data": {
    "ioc_type": "ipv4",
    "reputation_score": 92,
    "first_seen": "2025-12-01T00:00:00Z",
    "last_seen": "2026-04-22T22:00:00Z",
    "tags": ["brute-force", "scanner", "tor-exit"],
    "sources": ["firehol", "tor-exit-list"],
    "confidence": "high"
  }
}
```

---

## 5. Architecture — the three things you're building

### 5.1 The intel engine (ingest + normalize)

A scheduler that runs every 15 minutes and:
1. Fetches each configured feed (HTTPS GET — most are plain text or CSV)
2. Parses the format (one parser per feed)
3. Normalizes into a common IOC record: `{ioc_value, ioc_type, source, first_seen, last_seen, tags, raw}`
4. Upserts into local SQLite (bump `last_seen`, merge `tags`, recompute `reputation_score`)
5. Detects new high-reputation IOCs and queues them for broadcast

### 5.2 The query API

FastAPI server on port **8000** with the endpoints in 4.1(a). Under the hood it just reads SQLite. Add caching if you feel fancy.

### 5.3 The broadcaster

Small background task that drains the broadcast queue and POSTs `ioc` events to Analyst + Hunter with the SOC Protocol envelope.

### 5.4 The admin page (port 8001)

**Operational tab:**
- Feed status: last successful pull per feed, count of records ingested
- Total IOCs in DB, broken down by type (IP / domain / hash / URL)
- Incoming query stats: which peers are hitting `/enrich` and `/ioc/bad-ips`, how often
- Broadcast queue depth

**Security tab:**
- Auth failures on your API
- Rate-limit trips
- Schema-validation rejections on `/observe`
- Peers that asked for things not in your DB (potentially useful data to go fetch)

---

## 6. Recommended stack (not mandatory)

| Concern           | Recommendation                                   | Why                                                                   |
| ----------------- | ------------------------------------------------ | --------------------------------------------------------------------- |
| Language          | **Python 3.10**                                  | requests, pandas, sqlite3 all stdlib-adjacent                         |
| HTTP              | **FastAPI** + Uvicorn                             | Same as everyone else                                                 |
| Scheduler         | **APScheduler** or a tiny asyncio loop            | Feeds every 15 min; don't need Celery                                 |
| Storage           | **SQLite** with one table per IOC type            | One file, indexes on `ioc_value`                                      |
| HTTP client       | **httpx** (supports async) or **requests**        | Depends on async preference                                           |
| Admin UI          | FastAPI + Jinja + HTMX                            | Ditto                                                                 |

---

## 7. Security infrastructure — non-negotiable

Must-have:

- [ ] Bearer token on `/observe` and any write endpoint (read endpoints stay open, since that's the point — but rate-limit them)
- [ ] Pydantic validation on `/observe`
- [ ] Rate limiting on all public endpoints (200/min per IP is reasonable for a query API)
- [ ] HTTP Basic auth on admin page
- [ ] **Feed-source allowlist** — only fetch from hostnames on a hardcoded list. Prevents anyone from pivoting a compromise into an SSRF.
- [ ] **Don't trust incoming `/observe` data as IOCs by default** — tag them `community_submitted`, require corroboration from a second source before promoting to high-reputation
- [ ] Append-only security log

Ask Claude:
```
Add a feed-source allowlist module. When fetching, check the hostname against
a hardcoded set: urlhaus.abuse.ch, threatfox.abuse.ch, iplists.firehol.org,
www.spamhaus.org, check.torproject.org. Reject anything else with a clear
error in the security log.
```

---

## 8. Admin page spec

URL: `http://wic02.sanctumsec.com:8001/admin` — HTTP Basic login.

**Operational tab:**
- Feed health table: name, last-fetch time, status, record count delta
- IOC totals: a 4-pie breakdown (IPs / domains / hashes / URLs)
- Top 10 most-looked-up IOCs today (what peers care about most)
- Broadcast queue depth and error rate

**Security tab:**
- Auth failures (last 50)
- Rate-limit trips
- `/observe` payloads rejected by schema
- Unknown-IOC lookups (potentially interesting; could suggest attacker recon against you)

---

## 9. Your day — phase by phase with Claude

### Phase 0 — Kickoff (9:15–10:00)

Attend the facilitator-led protocol session. Decide roles.

### Phase 1 — Scaffold (10:00–10:45)

```
Start a FastAPI project in ~/app. Create:
- main.py with /health and the read endpoints GET /ioc/bad-ips, GET /enrich.
  They can return empty lists / 404 for now.
- /observe POST endpoint protected by bearer token validating the event envelope.
- schemas/envelope.py — shared Pydantic model.
- storage/db.py — SQLite connection + schema for ioc table (ioc_value TEXT PRIMARY KEY,
  ioc_type TEXT, source TEXT, first_seen TEXT, last_seen TEXT, tags TEXT JSON,
  reputation_score INTEGER).
- systemd unit to run uvicorn on port 8000.
- requirements.txt with fastapi, uvicorn, pydantic, httpx, apscheduler, slowapi.
```

Commit and push. Deploy. Curl `/health`. Stub `/ioc/bad-ips` returns `[]`.

### Phase 2 — Feed ingest (10:45–12:30)

```
Create ~/app/feeds/ with one parser module per source:
- firehol.py: fetches https://iplists.firehol.org/files/firehol_level1.netset,
  parses out /32 IPs, returns list of (ip, "firehol_level1") tuples.
- spamhaus.py: fetches https://www.spamhaus.org/drop/drop.txt, skips ; comments,
  extracts CIDR + description.
- tor.py: fetches https://check.torproject.org/torbulkexitlist, returns list of IPs.
- urlhaus.py: fetches https://urlhaus.abuse.ch/downloads/csv_recent/, parses CSV,
  returns list of URLs + their malware tags.
- threatfox.py: fetches https://threatfox-api.abuse.ch/export/json/recent/,
  returns list of IOCs with their types.

Then create ~/app/feeds/scheduler.py that runs all of these every 15 minutes,
upserts results into the sqlite ioc table, and recalculates reputation_score:
- In firehol/tor/spamhaus: 70
- In urlhaus: 85
- In threatfox: 85
- Appearing in 2+ sources: boost by 10
- Appearing in 3+ sources: boost by 15 (cap at 100)

Tag each ioc with all source names.
```

Test locally. First run should populate ~300,000 Firehol entries + some from each other source.

### Phase 3 — Query API + broadcaster (12:30–14:30)

(Includes a lunch break — eat, don't code on an empty stomach.)

Implement:

```
Fill in GET /ioc/bad-ips — query all IPs with reputation_score >= 70, return a
JSON list of objects {ip, score, tags, last_seen}. Support ?since=<iso-timestamp>
to only return IOCs whose last_seen is newer than that.

Fill in GET /enrich — accepts ?ip= or ?domain= or ?hash=. Returns the full
ioc record if found, else 404.

Fill in POST /observe — accepts an event envelope. Extract the observable
(source_ip / domain / hash), upsert into ioc table with source="community",
reputation_score=40 (low-confidence), tag=["community_submitted"].
If the same ioc already exists from another source, bump last_seen.

Create ~/app/broadcaster.py — runs every 30s. Queries ioc table for records
where reputation_score >= 70 AND last_seen > 30 seconds ago AND NOT already_broadcast.
For each, construct an "ioc" event envelope and POST to:
- http://wic03.sanctumsec.com:8000/ingest
- http://wic04.sanctumsec.com:8000/context
Mark as broadcast. If POST fails, log to security.log and retry next tick.
```

### Phase 4 — Admin page + hardening (14:30–16:30)

```
Create ~/app/admin/ on port 8001 with HTTP Basic auth, HTMX auto-refresh every 10s.
- "Operational" tab: feed health table (query a feed_runs table you also need to
  create), IOC totals per type, top-10 queried IOCs today (from a query_log table),
  broadcast queue depth.
- "Security" tab: last 50 entries from security.log parsed as JSON lines.

Also add rate limiting to the public endpoints: 200 req/min per source IP.
```

### Phase 5 — Integrations + demo prep (16:30–17:30)

- Verify Trap's polling hits `/ioc/bad-ips` successfully (check the admin page's incoming queries)
- Verify you're broadcasting at least one `ioc` event per minute to Analyst and Hunter
- Write a synthetic-observable POST to `/observe` to make sure it flows end-to-end
- Write pytest: auth, schema, enrich lookup

---

## 10. Splitting the work across 3–5 people

If you have **3**:

| Role               | Owns                                     |
| ------------------ | ---------------------------------------- |
| Feeds engineer     | Feed parsers, scheduler, storage schema  |
| API + broadcaster  | FastAPI routes, broadcaster, event envelope |
| Admin + deploy     | Port-8001 dashboard, systemd, Actions    |

If you have **4**:

| Role                | Owns                                    |
| ------------------- | --------------------------------------- |
| Feeds engineer      | Feed parsers + scheduler                |
| Storage + API       | SQLite schema + all query endpoints     |
| Broadcaster         | Push-out events + retry                 |
| Admin + security    | Dashboard, auth, rate limiting, logs    |

If you have **5**:

Split "Feeds engineer" into "feeds-A" (Firehol, Spamhaus, Tor — the easy text lists) and "feeds-B" (URLhaus, ThreatFox — the CSV/JSON ones).

---

## 11. Mock-first checklist

By 11:00:

- [ ] `GET /health` works
- [ ] `GET /ioc/bad-ips` returns a hand-rolled list of 5 fake bad IPs (so Trap can dev against it)
- [ ] `GET /enrich?ip=198.51.100.42` returns a fake IOC record
- [ ] `POST /observe` with bearer accepts a fake envelope and returns 202

This way Trap and Hunter can start integrating before your real feeds are flowing.

---

## 12. Definition of done

**Minimum viable:**
- [ ] Three feeds pulling successfully on a 15-minute cadence
- [ ] SQLite table populated with ≥ 100 real IOCs
- [ ] `GET /ioc/bad-ips` returns real data
- [ ] `GET /enrich` works for all three IOC types
- [ ] `POST /observe` accepts and stores community submissions
- [ ] Broadcaster emitting `ioc` events to Analyst and Hunter
- [ ] Admin page on 8001 with both tabs working
- [ ] systemd + GitHub Actions deploy

**Bonus:**
- [ ] 5 feeds live (add URLhaus + ThreatFox)
- [ ] AbuseIPDB integration with API key for real-time lookups on `/enrich`
- [ ] IOC "decay" — reduce score of IOCs not seen in > 30 days
- [ ] Per-peer audit log: who asked about which IOCs
- [ ] A very small world-map visualization of source IP geolocation

---

## 13. Stretch goals (if you're ahead)

- MISP-style TAXII feed export so external platforms could consume your library
- Correlation: "this IP has appeared 4 times in the last hour across peer submissions" → elevate confidence automatically
- Enrichment pipeline: on any new IOC, look it up in a WHOIS and geolocation API, attach to the record
- Archive daily snapshots to `s3://wic-krakow-2026/public/scout/snapshots/`

Good hunting.

---

## Day 3 cross-cutting goals (AI-CTI themes)

In addition to your team-specific deliverables above, **the following three themes from Day 3's curriculum (Modules 4–6) should visibly show up somewhere in your tool, your admin page, or your training artifacts.** Claude Code is the one that makes these feasible in a single day — use it.

### Goal 1 — AI-Augmented CTI

Use Claude (or any LLM) to automate at least one step of the CTI lifecycle *inside* your tool: extraction, classification, correlation, or enrichment of threat intelligence. This is Module 4's practical application.

### Goal 2 — TTPs and AI-enabled Attack Patterns

When you map behaviors to MITRE ATT&CK, also recognize TTPs that an AI-enabled adversary would produce differently: LLM-generated phishing prose, automated OSINT-driven recon, machine-generated polymorphic payloads, scripted beaconing at unusual intervals. Reflect this in your detections, hypotheses, IOC tags, or playbooks.

### Goal 3 — AI Social Engineering (offense *and* defense)

Real attackers now use AI to scale phishing, voice-cloning, and impersonation. Your tool should touch this at least once: capturing a social-engineering artifact, tagging one, alerting on it, enriching one, or — at minimum — documenting how your tool *would* react to an AI-enabled SE attempt.

### How each goal lands in your work — team-specific guidance

- **AI-Augmented CTI:** Pipe each newly-ingested IOC through Claude with a prompt like: *"Given this IOC (IP / domain / hash), describe its most likely tactic and technique (MITRE ATT&CK) in one sentence."* Store the LLM-generated description as `data.llm_tag`; show it in `/enrich` responses.
- **TTPs / AI attack patterns:** When you pull URLhaus / ThreatFox, add a tag filter for entries that reference `phishing-kit`, `generated-phishing`, or campaigns the feeds flag as automated. Expose a `/ioc/ai-campaigns` endpoint listing those specifically.
- **AI social engineering:** Include at least one feed focused on AI-generated phishing domains. The `ThreatFox` feed already tags this; promote those to a dedicated dashboard panel.
