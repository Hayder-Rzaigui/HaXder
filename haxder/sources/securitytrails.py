import logging
from typing import Set
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from haxder.sources.base import BaseSource

log = logging.getLogger("haxder")

class SecurityTrailsSource(BaseSource):
    def __init__(self, api_key: str):
        super().__init__(name="SecurityTrails")
        self.api_key = api_key
        self.url_template = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, ValueError)),
        reraise=False
    )
    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str) -> dict:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HaXder/2.0",
            "APIKEY": self.api_key,
            "Accept": "application/json"
        }
        async with session.get(url, headers=headers, timeout=15) as response:
            if response.status != 200:
                log.debug(f"SecurityTrails returned HTTP {response.status}.")
                raise aiohttp.ClientResponseError(
                    response.request_info, response.history, status=response.status
                )
            return await response.json(content_type=None)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        if not self.api_key:
            return subdomains

        url = self.url_template.format(domain=domain)
        try:
            data = await self._fetch_with_retry(session, url)
            if not data or "subdomains" not in data:
                return subdomains
            for sub in data["subdomains"]:
                full_sub = f"{sub}.{domain}".lower()
                subdomains.add(full_sub)
        except Exception as e:
            log.debug(f"Error querying SecurityTrails: {e}")
        return subdomains
