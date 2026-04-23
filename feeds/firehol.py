import httpx

URL = "https://iplists.firehol.org/files/firehol_level1.netset"


async def fetch() -> list[tuple[str, str]]:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(URL)
        r.raise_for_status()
    results = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # keep plain IPs, /32s (strip suffix), and all other CIDRs as-is
        if line.endswith("/32"):
            results.append((line[:-3], "firehol_level1"))
        else:
            results.append((line, "firehol_level1"))
    return results
