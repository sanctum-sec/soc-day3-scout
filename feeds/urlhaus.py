import csv
import io

import httpx

URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Column order in urlhaus CSV:
# id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter


async def fetch() -> list[tuple[str, list[str]]]:
    """Returns list of (url, tags) tuples."""
    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        r = await client.get(URL)
        r.raise_for_status()
    results = []
    reader = csv.reader(io.StringIO(r.text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 7:
            continue
        url = row[2].strip()
        raw_tags = row[6].strip()
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []
        if url:
            results.append((url, tags))
    return results
