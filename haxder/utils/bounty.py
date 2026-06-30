import aiohttp
import logging
from typing import Set
import json

log = logging.getLogger("haxder")

class BountyScopeFetcher:
    """
    Fetches in-scope domains for a given public Bug Bounty program.
    Leverages ProjectDiscovery's public Chaos Bug Bounty list.
    """
    @staticmethod
    async def get_program_scope(program_name: str) -> Set[str]:
        found = set()
        program_name = program_name.lower().strip()
        url = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json"
        
        log.info(f"[*] Fetching Bug Bounty scope for program: {program_name}")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status == 200:
                        data = await response.json()
                        programs = data.get("programs", [])
                        
                        for prog in programs:
                            name = prog.get("name", "").lower()
                            # Exact or partial match
                            if program_name == name or program_name in name:
                                domains = prog.get("domains", [])
                                for d in domains:
                                    if d.strip():
                                        found.add(d.strip())
                                
                                log.info(f"[+] Found {len(domains)} in-scope domains for program '{prog.get('name')}'")
                                # We can return early if exact match, but let's gather all that match
                                
                        if not found:
                            log.warning(f"[-] Could not find any in-scope domains for program: {program_name}")
                    else:
                        log.error(f"[-] Failed to fetch Bug Bounty list. HTTP: {response.status}")
                        
        except Exception as e:
            log.error(f"[-] Error fetching Bug Bounty scopes: {e}")
            
        return found
