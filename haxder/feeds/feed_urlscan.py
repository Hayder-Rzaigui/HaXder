import logging
from typing import Set
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from haxder.feeds.provider_base import BaseSource

log = logging.getLogger("haxder")

class URLScanSource(BaseSource):
    def __init__(self):
        super().__init__(name="URLScan")
        self.url_template = "https://urlscan.io/api/v1/search/?q=domain:{domain}"

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
                raise aiohttp.ClientResponseError(
                    response.request_info, response.history, status=response.status
                )
            return await response.json(content_type=None)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        url = self.url_template.format(domain=domain)
        try:
            data = await self._fetch_with_retry(session, url)
            if not data or "results" not in data:
                return subdomains
            for result in data["results"]:
                page_domain = result.get("page", {}).get("domain", "")
                if page_domain:
                    page_domain = page_domain.strip().lower()
                    if page_domain.endswith(domain) and page_domain != domain:
                        subdomains.add(page_domain)
        except Exception as e:
            log.debug(f"Error querying URLScan: {e}")
        return subdomains
