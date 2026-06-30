import logging
from typing import Set
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from haxder.sources.base import BaseSource

log = logging.getLogger("haxder")

class HackerTargetSource(BaseSource):
    """
    Passive subdomain source querying HackerTarget's host search API.
    """

    def __init__(self):
        super().__init__(name="HackerTarget")
        self.url_template = "https://api.hackertarget.com/hostsearch/?q={domain}"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(aiohttp.ClientError),
        reraise=False
    )
    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str) -> str:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HaXder/2.0"}
        async with session.get(url, headers=headers, timeout=15) as response:
            if response.status != 200:
                log.debug(f"HackerTarget returned HTTP status {response.status}")
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=f"HTTP {response.status}",
                    headers=response.headers
                )
            return await response.text()

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        url = self.url_template.format(domain=domain)
        log.debug(f"Querying HackerTarget for domain: {domain}")

        try:
            text = await self._fetch_with_retry(session, url)
            if not text or "error" in text.lower():
                return subdomains

            lines = text.split("\n")
            for line in lines:
                parts = line.split(",")
                if parts:
                    subdomain = parts[0].strip().lower()
                    if subdomain.endswith(domain) and subdomain != domain:
                        subdomains.add(subdomain)

        except Exception as e:
            log.debug(f"Error querying HackerTarget after retries: {e}")

        return subdomains
