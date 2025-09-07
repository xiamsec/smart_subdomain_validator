
import httpx, os
from typing import Optional, Dict

async def enrich_ip(ip: str) -> Dict:
    token = os.getenv("IPINFO_TOKEN")
    if not token:
        return {}
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(f"https://ipinfo.io/{ip}", params={"token":token})
            if r.status_code == 200:
                j = r.json()
                org = j.get("org","")
                if org.startswith("AS"):
                    asn, _, orgname = org.partition(" ")
                else:
                    asn, orgname = None, org
                return {"asn": asn, "org": orgname, "country": j.get("country")}
    except Exception:
        pass
    return {}
