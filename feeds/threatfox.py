import csv
import io

import httpx

URL = "https://threatfox.abuse.ch/export/csv/recent/"

# CSV columns: id, ioc, ioc_type, threat_type, malware, malware_alias,
#              malware_malpedia, confidence_level, first_seen, last_seen,
#              reporter, tags, reference

_TYPE_MAP = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash",
    "sha1_hash": "hash",
    "sha256_hash": "hash",
}


async def fetch() -> list[dict]:
    """Returns list of dicts with keys: ioc_value, ioc_type, tags."""
    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        r = await client.get(URL)
        r.raise_for_status()
    results = []
    reader = csv.reader(io.StringIO(r.text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 12:
            continue
        raw_type = row[2].strip()
        ioc_type = _TYPE_MAP.get(raw_type, "url")
        ioc_value = row[1].strip().strip('"')
        if raw_type == "ip:port" and ":" in ioc_value:
            ioc_value = ioc_value.rsplit(":", 1)[0]
        malware = row[4].strip()
        raw_tags = row[11].strip()
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        if malware and malware not in tags:
            tags.append(malware)
        if ioc_value:
            results.append({"ioc_value": ioc_value, "ioc_type": ioc_type, "tags": tags})
    return results
