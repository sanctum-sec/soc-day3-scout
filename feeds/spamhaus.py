import httpx

URL = "https://www.spamhaus.org/drop/drop.txt"


async def fetch() -> list[tuple[str, str]]:
    """Returns list of (cidr, description) tuples."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(URL)
        r.raise_for_status()
    results = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(";", 1)
        cidr = parts[0].strip()
        desc = parts[1].strip() if len(parts) > 1 else ""
        if cidr:
            results.append((cidr, desc))
    return results
