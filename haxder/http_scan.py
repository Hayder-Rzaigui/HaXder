import asyncio
import logging
import aiohttp
from bs4 import BeautifulSoup
from typing import Dict, List, Tuple

log = logging.getLogger("haxder")

class HttpProber:
    """
    Actively probes resolved subdomains on given ports to retrieve HTTP Status Codes
    and webpage titles, turning HaXder into an all-in-one offensive framework.
    """
    def __init__(self, threads: int = 200, timeout: float = 5.0, ports: List[int] = None):
        self.concurrency = threads
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.ports = ports if ports else [80, 443]

    async def _probe_url(self, session: aiohttp.ClientSession, url: str) -> Tuple[str, str, str, List[str]]:
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as response:
                status = str(response.status)
                title = "N/A"
                body = ""
                
                # Check for standard security headers
                missing_headers = []
                headers = response.headers
                if "Content-Security-Policy" not in headers:
                    missing_headers.append("Content-Security-Policy")
                if "Strict-Transport-Security" not in headers:
                    missing_headers.append("Strict-Transport-Security")
                if "X-Frame-Options" not in headers:
                    missing_headers.append("X-Frame-Options")
                if "X-Content-Type-Options" not in headers:
                    missing_headers.append("X-Content-Type-Options")

                if "text/html" in response.headers.get("Content-Type", "").lower():
                    html = await response.text()
                    if html:
                        body = html
                        soup = BeautifulSoup(html, "lxml")
                        if soup.title and soup.title.string:
                            title = soup.title.string.strip()[:60]
                return status, title, body, missing_headers
        except Exception:
            return "ERR", "N/A", "", []

    async def _worker(self, session: aiohttp.ClientSession, queue: asyncio.Queue, results: Dict[str, dict], progress_callback):
        while True:
            subdomain = await queue.get()
            
            # Probe all specified ports
            success_status = "ERR"
            success_title = "N/A"
            success_body = ""
            success_missing_headers = []
            success_port = None
            
            for port in self.ports:
                # For 443 and 8443 we try HTTPS first, otherwise HTTP first
                schemes = ["https", "http"] if port in [443, 8443, 4443] else ["http", "https"]
                
                for scheme in schemes:
                    # Construct URL without port if it's default to keep headers clean, else append port
                    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                        url = f"{scheme}://{subdomain}"
                    else:
                        url = f"{scheme}://{subdomain}:{port}"
                        
                    status, title, body, missing_hdrs = await self._probe_url(session, url)
                    
                    if status != "ERR":
                        success_status = status
                        success_title = title
                        success_body = body
                        success_missing_headers = missing_hdrs
                        success_port = port
                        break # Found a working web service on this port, stop trying schemes
                
                if success_status != "ERR":
                    break # Found a working port, store result and move on
            
            results[subdomain] = {
                "status": success_status, 
                "title": success_title, 
                "body": success_body,
                "missing_headers": success_missing_headers,
                "port": success_port
            }
            
            if progress_callback:
                progress_callback()
                
            queue.task_done()

    async def probe_all(self, subdomains: List[str], progress_callback=None) -> Dict[str, dict]:
        results: Dict[str, dict] = {}
        if not subdomains:
            return results

        queue = asyncio.Queue()
        for sub in subdomains:
            queue.put_nowait(sub)

        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            tasks = []
            for _ in range(min(self.concurrency, len(subdomains))):
                task = asyncio.create_task(self._worker(session, queue, results, progress_callback))
                tasks.append(task)
            
            await queue.join()
            
            for task in tasks:
                task.cancel()
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
        return results
