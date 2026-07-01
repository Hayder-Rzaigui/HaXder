import aiohttp
import asyncio
import logging
import re
from typing import Set, Dict, List

log = logging.getLogger("haxder")

class UrlExtractor:
    """
    Extracts URLs from Wayback Machine and scans JS files for exposed secrets/API keys.
    """
    def __init__(self, threads: int = 50):
        self.concurrency = threads
        
        # Signatures for common secrets
        self.secret_signatures = {
            "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "Google API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            "Stripe Standard API": re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            "Slack Token": re.compile(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}'),
            "GitHub Token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36}'),
            "Generic Secret": re.compile(r'(?i)(?:secret|token|password|api_key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']')
        }

    async def get_urls(self, domain: str) -> Set[str]:
        urls = set()
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey"
        
        log.info(f"[*] Extracting historical URLs for {domain} from Wayback Machine...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line and not line.startswith("http://web.archive"):
                                urls.add(line)
        except Exception as e:
            log.error(f"[-] Error extracting URLs: {e}")
            
        return urls

    async def _scan_js_worker(self, session: aiohttp.ClientSession, queue: asyncio.Queue, results: List[Dict]):
        while True:
            url = await queue.get()
            if url is None:
                break
                
            try:
                # Limit size to avoid downloading massive non-js files
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        for name, regex in self.secret_signatures.items():
                            matches = regex.findall(content)
                            if matches:
                                for match in set(matches):
                                    if isinstance(match, tuple):
                                        match = match[0]
                                    results.append({
                                        "url": url,
                                        "type": name,
                                        "secret": match[:10] + "..." + match[-4:] if len(match) > 15 else match
                                    })
            except Exception:
                pass
                
            queue.task_done()

    async def scan_secrets(self, urls: Set[str]) -> List[Dict]:
        js_urls = [u for u in urls if u.endswith('.js')]
        if not js_urls:
            return []
            
        log.info(f"[*] Scanning {len(js_urls)} Javascript files for exposed secrets...")
        
        results = []
        queue = asyncio.Queue()
        for u in js_urls:
            queue.put_nowait(u)
            
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(min(self.concurrency, len(js_urls))):
                task = asyncio.create_task(self._scan_js_worker(session, queue, results))
                tasks.append(task)
                
            await queue.join()
            
            for _ in tasks:
                await queue.put(None)
            await asyncio.gather(*tasks)
            
        return results
