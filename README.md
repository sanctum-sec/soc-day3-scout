> **English version:** [README.en.md](README.en.md)

# Команда 2 — Розвідник (Scout): агрегатор Threat Intelligence

**Ваш Lightsail:** `wic02.sanctumsec.com` (63.179.14.154)
**Ваш GitHub-репозиторій:** `https://github.com/sanctum-sec/soc-day3-scout`
**Прочитайте спочатку:** [`sanctum-sec/soc-protocol`](https://github.com/sanctum-sec/soc-protocol) — це контракт, якого ви маєте дотримуватися.

---

## 1. Ваша місія

Ви — **бібліотека** SOC. Ви тягнете cyber threat intelligence з відкритого інтернету, прибираєте її та робите запитованою, щоб інші команди за секунду отримували відповідь на питання *«це щось погане?»*.

До кінця дня у вас буде:
- Періодичні pull-и з 3+ безкоштовних публічних threat-intel фідів (URLhaus, ThreatFox, Firehol, Spamhaus, Tor exit list)
- Локальна SQLite-база IOC (IP, домени, хеші, URL) з репутацією, тегами, часовими мітками
- Query API, куди інші команди ходять: `GET /ioc/bad-ips`, `GET /enrich?ip=…`
- Pusher, що броадкастить високо-репутаційні IOC в Аналітик і Мисливець як `ioc`-події SOC Protocol
- Адмін-дашборд, де видно, що у вашій бібліотеці, що ви заінжестили та хто стукав у *ваше* API

Пастка розраховує на вас, щоб мітити зловмисників як відомо-поганих. Аналітик — щоб скорувати алерти. Мисливець — для контексту при оцінці аномалій. Ви — друга думка всіх.

---

## 2. Де це місце в реальному SOC

З Таблиці 1 «11 Strategies of a World-Class SOC» (MITRE):

- **Cyber Threat Intelligence Collection, Processing, and Fusion** — ви робите всі три.
- **Cyber Threat Intelligence Analysis and Production** — тегування, скорінг, трендинг.
- **Cyber Threat Intelligence Sharing and Distribution** — ви публікуєте peer-інструментам.

Це функція, яку кожен зрілий SOC рано чи пізно будує. Сьогодні ви робите мінімально-життєздатну версію за вісім годин.

---

## 3. Доступ і що вже встановлено

```
ssh ubuntu@wic02.sanctumsec.com
# пароль: GhostTrace-02!
```

Вже встановлено: `git`, Python 3.10 + pip, Node.js LTS, `claude`, `codex`, AWS CLI + креденшли для `s3://wic-krakow-2026`.

Вихідний доступ в інтернет не обмежений — фіди тягти можна вільно.

---

## 4. Потоки даних

### 4.1 Що ви виробляєте (виходи)

Дві форми виходу:

**(а) Query API на запит** — інші команди самі до вас:

| Endpoint                                      | Хто кличе           | Що повертає                                                  |
| --------------------------------------------- | ------------------- | ------------------------------------------------------------ |
| `GET /ioc/bad-ips?since=<timestamp>`          | **Пастка** (polling) | JSON-список відомо-поганих IP з оцінками та тегами          |
| `GET /enrich?ip=1.2.3.4`                      | Будь-хто            | Репутаційний запис для одного IP (або 404)                   |
| `GET /enrich?domain=example.com`              | Будь-хто            | Репутаційний запис для одного домену                         |
| `GET /enrich?hash=<sha256>`                   | Будь-хто            | Репутаційний запис для одного file-хешу                      |
| `GET /health`                                 | Усі                 | `{"status":"ok","tool":"scout"}`                             |

**(б) Push-події** — ви POST-ите `ioc`-події до:

| Кому        | Endpoint                                    | Коли                                                              |
| ----------- | ------------------------------------------- | ----------------------------------------------------------------- |
| **Аналітик** | `http://wic03.sanctumsec.com:8000/ingest`  | Як тільки свіжозаінжещений IOC має репутацію ≥ 70                 |
| **Мисливець** | `http://wic04.sanctumsec.com:8000/context` | Той самий тригер — Мисливець використовує це для калібрування    |

### 4.2 Що ви споживаєте (входи)

**(а) Зовнішні threat-фіди** (безкоштовні, публічні — для стартового набору ключі не потрібні):

| Джерело                                                                                     | Що отримуєте                                | Як                                     |
| ------------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------- |
| [URLhaus](https://urlhaus.abuse.ch/downloads/)                                              | Шкідливі URL                                | CSV через HTTPS, оновлення раз на 5хв  |
| [ThreatFox](https://threatfox.abuse.ch/export/)                                             | IOC, тегнуті родинами шкідливого ПЗ         | JSON через HTTPS                       |
| [Firehol Level 1](https://iplists.firehol.org/?ipset=firehol_level1)                        | Відомо-погані IP                            | Plain-text список                      |
| [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt)                                     | Spammer-мережі                              | Plain-text список                      |
| [Tor exit list](https://check.torproject.org/torbulkexitlist)                               | Поточні Tor exit-ноди                       | Plain-text список                      |

На бонус — отримайте безкоштовні API-ключі (реєстрація — 2 хвилини):
- [AbuseIPDB](https://www.abuseipdb.com/register) — 1000 перевірок/день безкоштовно
- [AlienVault OTX](https://otx.alienvault.com/) — безкоштовно, щедрі rate limits

**(б) Peer-observables** (команди, які кажуть вам «я це бачив»):

| Від кого    | Endpoint              | Що шлють                                 |
| ----------- | --------------------- | ---------------------------------------- |
| **Пастка**   | `POST /observe`       | Свіжі IP, що атакують honeypot           |
| **Мисливець** | `POST /observe`     | IP/домени/хеші, які Мисливець вважає підозрілими |

Ви їх заінжещуєте, збагачуєте чим маєте, і якщо reputation-скор перетнув поріг — броадкастите `ioc`-подію.

### 4.3 Приклад IOC-події, яку ви емітите

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

## 5. Архітектура — три речі, які ви будуєте

### 5.1 Intel-движок (ingest + normalize)

Scheduler, що раз на 15 хвилин:
1. Тягне кожен налаштований фід (HTTPS GET — більшість це plain text або CSV)
2. Парсить формат (один парсер на фід)
3. Нормалізує у спільний IOC-запис: `{ioc_value, ioc_type, source, first_seen, last_seen, tags, raw}`
4. Upsert-ить у локальний SQLite (оновлює `last_seen`, мержить `tags`, перераховує `reputation_score`)
5. Детектить нові високорепутаційні IOC і кладе їх у чергу на broadcast

### 5.2 Query API

FastAPI-сервер на порті **8000** з endpoint-ами з 4.1(а). Під капотом просто читає SQLite. Додайте кеш, якщо хочеться.

### 5.3 Broadcaster

Невелика фонова задача, що дренить broadcast-чергу та POST-ить `ioc`-події до Аналітика + Мисливця з конвертом SOC Protocol.

### 5.4 Адмін-сторінка (порт 8001)

**Operational:**
- Статус фідів: час останнього успішного pull-у на фід, кількість заінжещених записів
- Усього IOC у БД, розбивка по типах (IP / домен / хеш / URL)
- Статистика вхідних запитів: хто з peer-ів б'є `/enrich` і `/ioc/bad-ips`, з якою частотою
- Глибина broadcast-черги

**Security:**
- Невдалі auth-и
- Спрацювання rate-limit
- Відмови через schema-валідацію на `/observe`
- Peer-и, що питали про те, чого у вас немає (потенційно цікаві дані, які варто потягти)

---

## 6. Рекомендований стек (не обовʼязково)

| Компонент      | Рекомендація                                     | Чому                                                                     |
| -------------- | ------------------------------------------------ | ------------------------------------------------------------------------ |
| Мова           | **Python 3.10**                                  | requests, pandas, sqlite3 — усе майже stdlib                             |
| HTTP           | **FastAPI** + Uvicorn                            | Як у всіх                                                                |
| Scheduler      | **APScheduler** або крихітний asyncio-loop        | Фіди раз на 15 хв; Celery непотрібен                                      |
| Сховище        | **SQLite** з однією таблицею на тип IOC          | Один файл, індекси на `ioc_value`                                         |
| HTTP-клієнт    | **httpx** (підтримує async) або **requests**     | Залежно від того, чи хочете async                                         |
| Адмін-UI       | FastAPI + Jinja + HTMX                           | Те саме                                                                  |

---

## 7. Security-інфраструктура — без компромісів

Мінімум:

- [ ] Bearer-token на `/observe` та будь-якому write-endpoint (read-endpoint-и лишаються відкритими — такий зміст — але з rate-limit)
- [ ] Pydantic-валідація на `/observe`
- [ ] Rate-limit на всіх публічних endpoint-ах (200/хв на IP — розумно для query API)
- [ ] HTTP Basic auth на адмінці
- [ ] **Allowlist джерел фідів** — тягнемо тільки з hostname-ів у hardcoded-списку. Це запобігає pivot-ингу потенційної компрометації у SSRF.
- [ ] **Дані з `/observe` не довіряти як IOC за замовчуванням** — тегуємо їх `community_submitted`, вимагаємо підтвердження з другого джерела перед підвищенням до high-reputation
- [ ] Append-only security-лог

Попросіть Claude:
```
Add a feed-source allowlist module. When fetching, check the hostname against
a hardcoded set: urlhaus.abuse.ch, threatfox.abuse.ch, iplists.firehol.org,
www.spamhaus.org, check.torproject.org. Reject anything else with a clear
error in the security log.
```

---

## 8. Специфікація адмін-сторінки

URL: `http://wic02.sanctumsec.com:8001/admin` — HTTP Basic login.

**Operational:**
- Таблиця стану фідів: назва, час останнього fetch-у, статус, дельта кількості записів
- Загалом IOC: 4-кругова розбивка (IP / домени / хеші / URL)
- Топ-10 найбільш-шуканих IOC за сьогодні (що peer-и цікавлять найбільше)
- Глибина broadcast-черги та помилки

**Security:**
- Останні 50 невдалих auth-ів
- Спрацювання rate-limit
- `/observe`-пейлоади, відкинуті схемою
- Запити про невідомі IOC (можуть бути цікавими; потенційно recon проти вас)

---

## 9. Ваш день — фази з Claude

### Фаза 0 — Kickoff (9:15–10:00)

Спільна сесія з фасилітатором. Визначтеся з ролями.

### Фаза 1 — Скафолд (10:00–10:45)

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

Commit, push. Deploy. curl `/health`. Заглушка `/ioc/bad-ips` повертає `[]`.

### Фаза 2 — Інжест фідів (10:45–12:30)

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

Тест локально. Перший прогін має заповнити ~300,000 Firehol-записів + щось із кожного іншого джерела.

### Фаза 3 — Query API + broadcaster (12:30–14:30)

(Включає обід — поїжте, не кодіть на порожній шлунок.)

Імплементація:

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

### Фаза 4 — Адмін-сторінка + хардінг (14:30–16:30)

```
Create ~/app/admin/ on port 8001 with HTTP Basic auth, HTMX auto-refresh every 10s.
- "Operational" tab: feed health table (query a feed_runs table you also need to
  create), IOC totals per type, top-10 queried IOCs today (from a query_log table),
  broadcast queue depth.
- "Security" tab: last 50 entries from security.log parsed as JSON lines.

Also add rate limiting to the public endpoints: 200 req/min per source IP.
```

### Фаза 5 — Інтеграції + підготовка до демо (16:30–17:30)

- Перевірте, що polling Пастки успішно б'є `/ioc/bad-ips` (подивіться у адмінці вхідні запити)
- Переконайтеся, що ви броадкастите щонайменше одну `ioc`-подію на хвилину до Аналітика і Мисливця
- Надішліть синтетичний observable у `/observe` — має пройти end-to-end
- Напишіть pytest: auth, schema, enrich lookup

---

## 10. Як поділити роботу між 3–5 людьми

Якщо вас **3**:

| Роль                | Відповідає за                            |
| ------------------- | ---------------------------------------- |
| Feeds engineer      | Парсери фідів, scheduler, storage-схема  |
| API + broadcaster   | FastAPI-роути, broadcaster, envelope     |
| Admin + deploy      | Дашборд на порту 8001, systemd, Actions  |

Якщо вас **4**:

| Роль                 | Відповідає за                            |
| -------------------- | ---------------------------------------- |
| Feeds engineer       | Парсери фідів + scheduler                |
| Storage + API        | SQLite-схема + усі query-endpoint-и      |
| Broadcaster          | Push-події + retry                       |
| Admin + security     | Дашборд, auth, rate limiting, логи       |

Якщо вас **5**:

Поділіть «Feeds engineer» на «feeds-A» (Firehol, Spamhaus, Tor — легкі текстові) та «feeds-B» (URLhaus, ThreatFox — CSV/JSON).

---

## 11. Чекліст «спочатку мок»

До 11:00:

- [ ] `GET /health` працює
- [ ] `GET /ioc/bad-ips` повертає заздалегідь написаний список з 5 фейкових поганих IP (щоб Пастка могла розробляти проти)
- [ ] `GET /enrich?ip=198.51.100.42` повертає фейковий IOC-запис
- [ ] `POST /observe` із bearer приймає фейковий конверт і повертає 202

Так Пастка і Мисливець можуть почати інтегруватися до того, як у вас потечуть справжні фіди.

---

## 12. Definition of done

**Мінімум:**
- [ ] Три фіди успішно тягнуться з каденцією 15 хв
- [ ] SQLite заповнена ≥ 100 реальними IOC
- [ ] `GET /ioc/bad-ips` віддає справжні дані
- [ ] `GET /enrich` працює для всіх трьох типів IOC
- [ ] `POST /observe` приймає та зберігає community-подання
- [ ] Broadcaster шле `ioc`-події до Аналітика і Мисливця
- [ ] Адмінка на 8001 з обома табами
- [ ] systemd + GitHub Actions деплой

**Бонус:**
- [ ] 5 фідів живі (додано URLhaus + ThreatFox)
- [ ] AbuseIPDB-інтеграція з API-ключем для real-time lookup на `/enrich`
- [ ] IOC «decay» — знижуємо score тих IOC, які не бачили > 30 днів
- [ ] Per-peer audit-лог: хто питав про які IOC
- [ ] Дуже маленька карта світу з геолокацією source IP

---

## 13. Stretch goals (якщо випереджаєте графік)

- MISP-подібний TAXII-фід, щоб зовнішні платформи могли споживати вашу бібліотеку
- Кореляція: «цей IP з'являвся 4 рази за останню годину в peer-поданнях» → автоматично підвищуємо впевненість
- Enrichment-пайплайн: на кожний новий IOC автоматично робимо WHOIS і geolocation, прикладаємо до запису
- Щоденні снапшоти в `s3://wic-krakow-2026/public/scout/snapshots/`

Гарного полювання.
