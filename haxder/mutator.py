import logging
from typing import Set
import re
import os

log = logging.getLogger("haxder")

class PermutationEngine:
    """
    Generates advanced active permutations (mutations) of discovered passive subdomains.
    Supports Number Incrementing (api1 -> api2) and large external permutation dictionaries.
    """
    def __init__(self, alterations_file: str = None):
        self.words = set([
            "dev", "api", "test", "stage", "staging", "prod", "v1", "v2", 
            "beta", "admin", "corp", "intra", "internal", "web", "app", 
            "db", "sql", "vpn", "mail", "gw", "portal", "cloud", "demo",
            "uat", "ops", "sys", "auth", "login", "cdn", "static"
        ])
        
        if alterations_file and os.path.exists(alterations_file):
            try:
                with open(alterations_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        w = line.strip().lower()
                        if w and not w.startswith('#'):
                            self.words.add(w)
                log.info(f"[*] Loaded {len(self.words)} alteration words from {alterations_file}")
            except Exception as e:
                log.error(f"[-] Error loading alterations file: {e}")

    def mutate(self, subdomains: Set[str], base_domain: str) -> Set[str]:
        mutated: Set[str] = set()
        
        # Regex to find numbers at the end of a string (e.g. api1, api2)
        num_pattern = re.compile(r'(\d+)$')

        for sub in subdomains:
            if sub == base_domain:
                continue

            prefix = sub.replace("." + base_domain, "")
            parts = prefix.split('.')
            
            for part in parts:
                if len(part) > 15:
                    continue
                
                # 1. Dictionary-based permutations
                for word in self.words:
                    mutated.add(f"{part}-{word}.{base_domain}")
                    mutated.add(f"{word}-{part}.{base_domain}")
                    mutated.add(f"{part}{word}.{base_domain}")
                    mutated.add(f"{word}{part}.{base_domain}")
                    mutated.add(f"{part}.{word}.{base_domain}")
                    mutated.add(f"{word}.{part}.{base_domain}")

                # 2. Number Incrementing Engine
                # If the part ends with a number (e.g. 'api1'), generate 0-9 variants
                match = num_pattern.search(part)
                if match:
                    base_str = part[:match.start()]
                    for i in range(10):
                        mutated.add(f"{base_str}{i}.{base_domain}")
                else:
                    # If no number, try appending numbers 1-3
                    for i in range(1, 4):
                        mutated.add(f"{part}{i}.{base_domain}")

        log.debug(f"Permutation Engine generated {len(mutated)} candidate subdomains.")
        return mutated
