import logging
import asyncio
import aiohttp
import yaml
import os
import re
from typing import List, Dict

log = logging.getLogger("haxder")

class VulnEngine:
    """
    Native vulnerability scanner that executes YAML templates against discovered endpoints.
    Similar to Nuclei but tightly integrated into the HaXder streaming pipeline.
    """
    def __init__(self, templates_dir: str = "vuln_checks"):
        self.templates_dir = templates_dir
        self.templates = []
        self._load_templates()
        
    def _load_templates(self):
        if not os.path.exists(self.templates_dir):
            os.makedirs(self.templates_dir)
            return
            
        for root, _, files in os.walk(self.templates_dir):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                            tmpl = yaml.safe_load(f)
                            if tmpl and "id" in tmpl and "requests" in tmpl:
                                self.templates.append(tmpl)
                    except Exception as e:
                        log.error(f"[-] Error loading template {file}: {e}")
                        
        log.info(f"[*] Loaded {len(self.templates)} vulnerability templates.")

    async def _scan_target(self, session: aiohttp.ClientSession, target_url: str) -> List[Dict]:
        findings = []
        for tmpl in self.templates:
            for req in tmpl.get("requests", []):
                method = req.get("method", "GET")
                paths = req.get("path", ["/"])
                matchers = req.get("matchers", [])
                
                for path in paths:
                    # Replace {{BaseURL}} like Nuclei does
                    url = path.replace("{{BaseURL}}", target_url)
                    try:
                        async with session.request(method, url, timeout=10, ssl=False, allow_redirects=False) as response:
                            text = await response.text()
                            status = response.status

                            # Evaluate every matcher individually, then combine them.
                            # Default condition is AND (all matchers must pass) to avoid
                            # false positives, e.g. a "word" + "status" template should
                            # not fire on a 200 response alone. A template can opt into
                            # OR semantics via `matchers-condition: or`.
                            condition = str(req.get("matchers-condition", "and")).lower()
                            matcher_results = []
                            for matcher in matchers:
                                m_type = matcher.get("type")
                                words = matcher.get("words", [])
                                status_codes = matcher.get("status", [])

                                if m_type == "word":
                                    matcher_results.append(all(w in text for w in words))
                                elif m_type == "status":
                                    matcher_results.append(status in status_codes)
                                else:
                                    matcher_results.append(False)

                            if not matcher_results:
                                is_match = False
                            elif condition == "or":
                                is_match = any(matcher_results)
                            else:
                                is_match = all(matcher_results)

                            if is_match:
                                findings.append({
                                    "id": tmpl.get("id"),
                                    "name": tmpl.get("info", {}).get("name", "Unknown"),
                                    "severity": tmpl.get("info", {}).get("severity", "info"),
                                    "matched_at": url
                                })
                                break # Move to next template if matched
                    except Exception:
                        pass
        return findings

    async def _worker(self, session: aiohttp.ClientSession, queue: asyncio.Queue, results: List[Dict]):
        while True:
            target = await queue.get()
            if target is None:
                break
                
            findings = await self._scan_target(session, target)
            if findings:
                results.extend(findings)
                
            queue.task_done()

    async def scan(self, targets: List[str], threads: int = 50) -> List[Dict]:
        if not self.templates or not targets:
            return []
            
        log.info(f"[*] Running Vulnerability Engine on {len(targets)} active targets...")
        
        results = []
        queue = asyncio.Queue()
        for t in targets:
            # Ensure it's a URL
            if not t.startswith("http"):
                queue.put_nowait(f"http://{t}")
                queue.put_nowait(f"https://{t}")
            else:
                queue.put_nowait(t)
                
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(threads):
                tasks.append(asyncio.create_task(self._worker(session, queue, results)))
                
            await queue.join()
            
            for _ in tasks:
                await queue.put(None)
            await asyncio.gather(*tasks)
            
        return results
