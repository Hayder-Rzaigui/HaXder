import logging
import asyncio
import os
import aiohttp
import yaml
from typing import List, Set, Optional

from haxder.settings import Config
from haxder.feeds.provider_base import BaseSource
from haxder.feeds.yaml_provider import YamlSource
from haxder.feeds.feed_crtsh import CrtShSource
from haxder.feeds.feed_hackertarget import HackerTargetSource
from haxder.feeds.feed_alienvault import AlienVaultSource
from haxder.feeds.feed_certspotter import CertSpotterSource
from haxder.feeds.feed_urlscan import URLScanSource
from haxder.feeds.feed_wayback import WaybackSource
from haxder.feeds.feed_anubis import AnubisSource
from haxder.feeds.feed_securitytrails import SecurityTrailsSource
from haxder.feeds.feed_shodan import ShodanSource
from haxder.feeds.feed_virustotal import VirusTotalSource
from haxder.feeds.feed_chaos import ChaosSource
from haxder.feeds.feed_bufferover import BufferOverSource

log = logging.getLogger("haxder")

# Free sources that don't require an API key
DEFAULT_SOURCES = (
    CrtShSource,
    HackerTargetSource,
    AlienVaultSource,
    CertSpotterSource,
    URLScanSource,
    AnubisSource,
    WaybackSource,
    BufferOverSource,
)

# (config key, source class) pairs for premium sources that need a key
PREMIUM_SOURCES = (
    ("securitytrails", SecurityTrailsSource),
    ("shodan", ShodanSource),
    ("virustotal", VirusTotalSource),
    ("chaos", ChaosSource),
)


class SubdomainEnumerator:
    """
    Orchestrates the loading and querying of passive subdomain sources asynchronously.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = Config(config_path)
        self.sources: List[BaseSource] = self._build_source_list()
        self._load_yaml_providers()

    def _build_source_list(self) -> List[BaseSource]:
        sources: List[BaseSource] = [cls() for cls in DEFAULT_SOURCES]

        for key_name, source_cls in PREMIUM_SOURCES:
            api_key = self.config.get_api_key(key_name)
            if api_key:
                sources.append(source_cls(api_key))

        return sources

    def _load_yaml_providers(self, providers_dir: str = "data_feeds"):
        if not os.path.isdir(providers_dir):
            return

        for filename in os.listdir(providers_dir):
            if not filename.endswith((".yaml", ".yml")):
                continue

            filepath = os.path.join(providers_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    provider_cfg = yaml.safe_load(fh)
                if provider_cfg:
                    self.sources.append(YamlSource(provider_cfg))
                    log.debug("Loaded YAML provider: %s", provider_cfg.get("name", filename))
            except Exception as exc:
                log.error("Failed to load YAML provider %s: %s", filename, exc)

    async def enumerate(self, domain: str, progress_callback=None, out_queue: Optional[asyncio.Queue] = None) -> Set[str]:
        """
        Query all registered sources concurrently for subdomains related to the target domain.
        If out_queue is provided, streams discovered subdomains directly to the queue.
        """
        discovered: Set[str] = set()
        log.info("Starting async passive subdomain enumeration for target: %s", domain)

        # ThreadedResolver relies on the OS getaddrinfo implementation
        resolver = aiohttp.ThreadedResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)

        async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
            jobs = [
                self._run_source(source, session, domain, progress_callback, out_queue)
                for source in self.sources
            ]
            for job_result in await asyncio.gather(*jobs, return_exceptions=True):
                if isinstance(job_result, Exception):
                    log.error("Unexpected error during enumeration: %s", job_result)
                elif isinstance(job_result, set):
                    discovered.update(job_result)

        log.info("Passive enumeration complete. Total unique subdomains discovered: %d", len(discovered))
        return discovered

    async def _run_source(self, source: BaseSource, session: aiohttp.ClientSession, domain: str, progress_callback, out_queue: Optional[asyncio.Queue]) -> Set[str]:
        try:
            found = await source.fetch(session, domain)
            log.info("Source %s discovered %d subdomains.", source.name, len(found))

            if out_queue:
                for sub in found:
                    await out_queue.put(sub)

            return found
        except Exception as exc:
            log.error("Error in source %s: %s", source.name, exc)
            return set()
        finally:
            if progress_callback:
                progress_callback(source.name)
