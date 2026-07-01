import logging
from typing import Set
import aiohttp
from haxder.feeds.provider_base import BaseSource

log = logging.getLogger("haxder")

class ShodanSource(BaseSource):
    def __init__(self, api_key: str):
        super().__init__("Shodan")
        self.api_key = api_key

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        if not self.api_key:
            log.warning(f"[{self.name}] No API key provided. Skipping.")
            return subdomains

        url = f"https://api.shodan.io/dns/domain/{domain}?key={self.api_key}"
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data.get("subdomains", []):
                        subdomains.add(f"{item}.{domain}")
                elif response.status == 401:
                    log.warning(f"[{self.name}] Invalid API Key.")
                elif response.status == 403:
                    log.warning(f"[{self.name}] Access Denied / API Limits reached.")
                else:
                    log.debug(f"[{self.name}] Returned status code {response.status}")
        except Exception as e:
            log.debug(f"[{self.name}] Error: {e}")

        return subdomains
