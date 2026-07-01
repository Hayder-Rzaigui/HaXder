import aiohttp
import asyncio
import logging
import os

log = logging.getLogger("haxder")

class ResolversUpdater:
    """
    Downloads and updates the list of public resolvers from trusted sources.
    """

    def __init__(self, resolvers_path: str = "dns_resolvers.txt"):
        self.resolvers_path = resolvers_path

    async def update(self):
        log.info("[*] Downloading latest trusted public DNS resolvers...")
        
        # We'll just use the trickest trusted resolvers list as it's the industry standard
        url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        text = await response.text()
                        with open(self.resolvers_path, "w") as f:
                            f.write(text)
                        
                        count = len([line for line in text.splitlines() if line.strip()])
                        log.info(f"[+] Successfully downloaded {count} trusted resolvers to {self.resolvers_path}")
                    else:
                        log.error(f"[-] Failed to download resolvers. HTTP Status: {response.status}")
        except Exception as e:
            log.error(f"[-] Error downloading resolvers: {e}")
