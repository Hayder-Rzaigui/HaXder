import logging
from typing import Set
import aiohttp
from haxder.sources.base import BaseSource

log = logging.getLogger("haxder")

class BufferOverSource(BaseSource):
    def __init__(self):
        super().__init__("BufferOver")

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://tls.bufferover.run/dns?q=.{domain}"
        
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    records = data.get("FDNS_A", [])
                    if records:
                        for record in records:
                            parts = record.split(',')
                            if len(parts) >= 2:
                                sub = parts[1]
                                if sub.endswith(domain):
                                    subdomains.add(sub)
                else:
                    log.debug(f"[{self.name}] Returned status code {response.status}")
        except Exception as e:
            log.debug(f"[{self.name}] Error: {e}")

        return subdomains
