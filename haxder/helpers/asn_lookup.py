import aiohttp
import asyncio
import logging
from typing import Set

log = logging.getLogger("haxder")

class ASNLookup:
    """
    Utility to discover domains associated with an ASN or CIDR block
    using public APIs (e.g., HackerTarget).
    """
    @staticmethod
    async def get_domains(target: str) -> Set[str]:
        found = set()
        url = ""
        
        target = target.upper().strip()
        
        if target.startswith("AS"):
            log.info(f"[*] Discovering domains for ASN: {target}")
            url = f"https://api.hackertarget.com/asndns/?q={target}"
        elif "/" in target:
            log.info(f"[*] Discovering domains for CIDR: {target}")
            url = f"https://api.hackertarget.com/reversedns/?q={target}"
        else:
            return found
            
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status == 200:
                        text = await response.text()
                        if "error" in text.lower() or "api count" in text.lower():
                            log.warning(f"[-] ASN/CIDR API Rate limited or error: {text.strip()}")
                            return found
                            
                        for line in text.splitlines():
                            parts = line.split(',')
                            if len(parts) > 0:
                                # HackerTarget returns: IP,domain
                                # For ASNDNS, it might just return the domain or IP,domain
                                domain = parts[-1].strip().lower()
                                if domain and "." in domain:
                                    found.add(domain)
                                    
        except Exception as e:
            log.error(f"[-] Error querying ASN/CIDR: {e}")
            
        return found
