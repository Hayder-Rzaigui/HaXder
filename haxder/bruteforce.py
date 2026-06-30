import logging
from typing import Set
import os

log = logging.getLogger("haxder")

class BruteForceEngine:
    """
    Generates subdomains by appending words from a wordlist to the base domain.
    """
    def __init__(self, wordlist_path: str = None):
        self.wordlist_path = wordlist_path
        self.words = set()

    def load_words(self):
        if not self.wordlist_path:
            return
            
        if not os.path.exists(self.wordlist_path):
            log.error(f"Wordlist not found: {self.wordlist_path}")
            return
            
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    word = line.strip().lower()
                    if word and not word.startswith('#'):
                        self.words.add(word)
            log.info(f"Loaded {len(self.words)} words from {self.wordlist_path}")
        except Exception as e:
            log.error(f"Error reading wordlist: {e}")

    def generate(self, base_domain: str) -> Set[str]:
        candidates: Set[str] = set()
        for word in self.words:
            candidates.add(f"{word}.{base_domain}")
            
        if candidates:
            log.debug(f"BruteForce Engine generated {len(candidates)} candidate subdomains.")
        return candidates
