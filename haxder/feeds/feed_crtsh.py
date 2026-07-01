import logging
import re
from typing import Set
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from haxder.feeds.provider_base import BaseSource

log = logging.getLogger("haxder")

class CrtShSource(BaseSource):
    """
    Passive subdomain source querying crt.sh (Certificate Transparency logs).
    """

    def __init__(self):
        super().__init__(name="crt.sh")
        self.url_template = "https://crt.sh/?q=%.{domain}&output=json"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, ValueError)),
        reraise=False
    )
    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str) -> list:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HaXder/2.0"}
        async with session.get(url, headers=headers, timeout=25) as response:
            if response.status != 200:
                log.debug(f"crt.sh returned HTTP status {response.status}")
                # Raise an error to trigger a retry
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=f"HTTP {response.status}",
                    headers=response.headers
                )
            # Use content_type=None to handle cases where crt.sh returns weird content types
            return await response.json(content_type=None)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        url = self.url_template.format(domain=domain)
        log.debug(f"Querying crt.sh for domain: {domain}")

        try:
            data = await self._fetch_with_retry(session, url)
            if not data:
                return subdomains

            for entry in data:
                name_value = entry.get("name_value", "")
                common_name = entry.get("common_name", "")
                
                for raw_domain in (name_value.split("\n") + common_name.split("\n")):
                    raw_domain = raw_domain.strip().lower()
                    
                    if raw_domain.startswith("*."):
                        raw_domain = raw_domain[2:]
                    
                    if raw_domain.endswith(domain) and raw_domain != domain:
                        if re.match(r"^[a-zA-Z0-9-_\.]+$", raw_domain):
                            subdomains.add(raw_domain)

        except Exception as e:
            log.debug(f"Error querying crt.sh after retries: {e}")

        return subdomains
