import logging
import json
from typing import Set
import aiohttp
from haxder.sources.base import BaseSource

log = logging.getLogger("haxder")

class ChaosSource(BaseSource):
    def __init__(self, api_key: str):
        super().__init__("Chaos")
        self.api_key = api_key

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        if not self.api_key:
            log.warning(f"[{self.name}] No API key provided. Skipping.")
            return subdomains

        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {"Authorization": self.api_key}

        try:
            async with session.get(url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    data = await response.json()
                    for sub in data.get("subdomains", []):
                        subdomains.add(f"{sub}.{domain}")
                elif response.status == 401:
                    log.warning(f"[{self.name}] Invalid API Key.")
                elif response.status == 403:
                    log.warning(f"[{self.name}] Access Denied / Unregistered Domain.")
                else:
                    log.debug(f"[{self.name}] Returned status code {response.status}")
        except Exception as e:
            log.debug(f"[{self.name}] Error: {e}")

        return subdomains
