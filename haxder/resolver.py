import asyncio
import logging
import random
import string
from typing import Dict, List, Set, Optional
import aiodns
import pycares

import os

log = logging.getLogger("haxder")

class SubdomainResolver:
    """
    Validates subdomains using pure asynchronous DNS resolution (aiodns/c-ares).
    Designed to work as a worker in a Producer-Consumer pipeline.
    """

    def __init__(self, threads: int = 500, timeout: float = 3.0, resolvers_file: str = None):
        self.concurrency = threads
        self.timeout = timeout
        
        # Depth-aware wildcard mappings. Dict[domain_level, Set[IPs] | asyncio.Event (while resolving)]
        self.wildcards: Dict[str, Set[str]] = {}
        self.wildcard_lock = asyncio.Lock()
        
        # Configure aiodns resolver
        self.resolver = aiodns.DNSResolver(timeout=timeout, tries=2)
        
        if resolvers_file and os.path.exists(resolvers_file):
            try:
                with open(resolvers_file, 'r') as f:
                    nameservers = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    if nameservers:
                        self.resolver.nameservers = nameservers
                        log.debug("Loaded %d custom DNS resolvers from %s", len(nameservers), resolvers_file)
            except Exception as e:
                log.error("Failed to load resolvers file %s: %s", resolvers_file, e)

    async def _query_record(self, domain: str, qtype: str) -> List[str]:
        """Helper to query a specific record type."""
        try:
            answers = await self.resolver.query(domain, qtype)
            if qtype == 'A':
                return [rdata.host for rdata in answers]
            elif qtype == 'CNAME':
                return [answers.cname]
        except (aiodns.error.DNSError, Exception):
            pass
        return []

    async def _get_wildcard_for_level(self, level_domain: str) -> Set[str]:
        """
        Check and cache wildcard IPs for a specific level (e.g., dev.example.com).
        Uses a per-level asyncio.Event so concurrent workers checking the same
        level wait for the in-progress resolution to finish instead of reading
        a half-finished placeholder (which previously caused false negatives
        on wildcard detection under high concurrency).
        """
        async with self.wildcard_lock:
            cached = self.wildcards.get(level_domain)
            if cached is None:
                # Not claimed yet: claim it ourselves with an Event.
                event = asyncio.Event()
                self.wildcards[level_domain] = event
                is_claimer = True
            elif isinstance(cached, asyncio.Event):
                # Someone else is already resolving this level.
                event = cached
                is_claimer = False
            else:
                # Already resolved.
                return cached

        if not is_claimer:
            await event.wait()
            async with self.wildcard_lock:
                return self.wildcards.get(level_domain, set())

        # We are the claimer: test multiple random subdomains at this level.
        level_wildcard_ips = set()
        for _ in range(3):
            random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
            test_domain = f"{random_sub}.{level_domain}"
            ips = await self._query_record(test_domain, 'A')
            if ips:
                level_wildcard_ips.update(ips)

        async with self.wildcard_lock:
            self.wildcards[level_domain] = level_wildcard_ips
            if level_wildcard_ips:
                log.debug("Wildcard detected at *.%s -> %s", level_domain, level_wildcard_ips)

        event.set()
        return level_wildcard_ips

    def _get_parent_levels(self, subdomain: str, base_domain: str) -> List[str]:
        """
        Extract parent domain levels to check for wildcards.
        For api.dev.example.com (base: example.com), returns ['dev.example.com', 'example.com']
        """
        sub_part = subdomain.replace(base_domain, "").strip(".")
        if not sub_part:
            return [base_domain]
            
        parts = sub_part.split(".")
        levels = []
        for i in range(len(parts)):
            level = ".".join(parts[i:]) + "." + base_domain
            levels.append(level)
        levels.append(base_domain)
        return levels

    async def resolve_worker(self, in_queue: asyncio.Queue, out_queue: asyncio.Queue, base_domain: str, progress_callback=None):
        """
        Worker that reads subdomains from in_queue, resolves them, checks wildcards,
        and places valid ones into out_queue.
        """
        while True:
            subdomain = await in_queue.get()
            if subdomain is None: # Sentinel value to shutdown
                in_queue.task_done()
                break

            # Resolve A and CNAME concurrently
            a_task = asyncio.create_task(self._query_record(subdomain, 'A'))
            cname_task = asyncio.create_task(self._query_record(subdomain, 'CNAME'))
            
            ips, cnames = await asyncio.gather(a_task, cname_task)

            if ips:
                # Check against wildcards at all parent levels
                is_wildcard = False
                parent_levels = self._get_parent_levels(subdomain, base_domain)
                
                for level in parent_levels:
                    wildcard_ips = await self._get_wildcard_for_level(level)
                    # If any of the resolved IPs matches the wildcard IPs for this level
                    if any(ip in wildcard_ips for ip in ips):
                        is_wildcard = True
                        break
                
                if not is_wildcard:
                    # Valid subdomain
                    await out_queue.put({
                        "subdomain": subdomain,
                        "ips": ips,
                        "cnames": cnames
                    })

            if progress_callback:
                progress_callback()

            in_queue.task_done()

    async def resolve_all(self, subdomains: Set[str], domain: str, progress_callback=None) -> Dict[str, dict]:
        """
        Legacy batch method maintained for backward compatibility.
        """
        if not subdomains:
            return {}

        log.info("Resolving %d subdomains using %d concurrent aiodns queries...", len(subdomains), self.concurrency)
        
        in_queue = asyncio.Queue()
        out_queue = asyncio.Queue()
        
        for sub in subdomains:
            in_queue.put_nowait(sub)
            
        # Add sentinels
        for _ in range(self.concurrency):
            in_queue.put_nowait(None)

        workers = [
            asyncio.create_task(self.resolve_worker(in_queue, out_queue, domain, progress_callback))
            for _ in range(self.concurrency)
        ]
        
        await asyncio.gather(*workers)
        
        results = {}
        while not out_queue.empty():
            item = out_queue.get_nowait()
            results[item["subdomain"]] = {"ips": item["ips"], "cnames": item["cnames"]}
            
        return results
