import logging
from typing import Set
import aiohttp
from haxder.feeds.provider_base import BaseSource

log = logging.getLogger("haxder")

class VirusTotalSource(BaseSource):
    def __init__(self, api_key: str):
        super().__init__("VirusTotal")
        self.api_key = api_key

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        if not self.api_key:
            log.warning(f"[{self.name}] No API key provided. Skipping.")
            return subdomains

        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000"
        headers = {"x-apikey": self.api_key}

        try:
            while url:
                async with session.get(url, headers=headers, timeout=15) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get("data", []):
                            sub_id = item.get("id")
                            if sub_id:
                                subdomains.add(sub_id)
                        
                        # Pagination
                        url = data.get("links", {}).get("next")
                    elif response.status == 401:
                        log.warning(f"[{self.name}] Invalid API Key.")
                        break
                    elif response.status == 429:
                        log.warning(f"[{self.name}] Rate limit exceeded.")
                        break
                    else:
                        log.debug(f"[{self.name}] Returned status code {response.status}")
                        break
        except Exception as e:
            log.debug(f"[{self.name}] Error: {e}")

        return subdomains
