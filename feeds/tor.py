import httpx

URL = "https://check.torproject.org/torbulkexitlist"


async def fetch() -> list[str]:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(URL)
        r.raise_for_status()
    return [
        line.strip()
        for line in r.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
