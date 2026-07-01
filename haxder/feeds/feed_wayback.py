import logging
from typing import Set
import urllib.parse
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from haxder.feeds.provider_base import BaseSource

log = logging.getLogger("haxder")

class WaybackSource(BaseSource):
    def __init__(self):
        super().__init__(name="WaybackMachine")
        self.url_template = "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, ValueError)),
        reraise=False
    )
    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str) -> list:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HaXder/2.0"}
        async with session.get(url, headers=headers, timeout=20) as response:
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
            if not data or len(data) <= 1:
                return subdomains
            # Skip the first row as it contains headers like ["original"]
            for row in data[1:]:
                if row and len(row) > 0:
                    original_url = row[0]
                    try:
                        parsed = urllib.parse.urlparse(original_url)
                        hostname = parsed.hostname
                        if hostname and hostname.endswith(domain) and hostname != domain:
                            subdomains.add(hostname.lower())
                    except Exception:
                        pass
        except Exception as e:
            log.debug(f"Error querying WaybackMachine: {e}")
        return subdomains
