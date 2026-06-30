import logging
from typing import Set
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from haxder.sources.base import BaseSource

log = logging.getLogger("haxder")

class AlienVaultSource(BaseSource):
    """
    Passive subdomain source querying AlienVault OTX API.
    """

    def __init__(self):
        super().__init__(name="AlienVault OTX")
        self.url_template = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, ValueError)),
        reraise=False
    )
    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str) -> dict:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HaXder/2.0"}
        async with session.get(url, headers=headers, timeout=15) as response:
            if response.status != 200:
                log.debug(f"AlienVault returned HTTP status {response.status}")
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=f"HTTP {response.status}",
                    headers=response.headers
                )
            return await response.json(content_type=None)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        url = self.url_template.format(domain=domain)
        log.debug(f"Querying AlienVault for domain: {domain}")

        try:
            data = await self._fetch_with_retry(session, url)
            if not data or "passive_dns" not in data:
                return subdomains

            for entry in data["passive_dns"]:
                hostname = entry.get("hostname", "")
                if hostname:
                    hostname = hostname.strip().lower()
                    if hostname.endswith(domain) and hostname != domain:
                        subdomains.add(hostname)

        except Exception as e:
            log.debug(f"Error querying AlienVault after retries: {e}")

        return subdomains
