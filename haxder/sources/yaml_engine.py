import yaml
import re
import logging
from typing import Set, Dict, Any
from haxder.sources.base import BaseSource
import urllib.parse

log = logging.getLogger("haxder")

class YamlSource(BaseSource):
    """
    Dynamically executes a passive OSINT source defined by a YAML configuration.
    Allows users to add new API sources simply by creating a YAML file.
    """
    def __init__(self, config: Dict[str, Any]):
        super().__init__(name=config.get("name", "UnknownYamlSource"))
        self.config = config
        self.url_template = config.get("request", {}).get("url", "")
        self.method = config.get("request", {}).get("method", "GET").upper()
        self.headers = config.get("request", {}).get("headers", {})
        
        # Parse extraction rules
        self.extraction = config.get("extraction", {})
        self.regex_pattern = self.extraction.get("regex", "")
        if self.regex_pattern:
            self.regex = re.compile(self.regex_pattern, re.IGNORECASE)
        else:
            self.regex = None
            
        self.json_path = self.extraction.get("json", "") # Future support for JSON parsing
        
    async def fetch(self, session, domain: str) -> Set[str]:
        found: Set[str] = set()
        if not self.url_template:
            return found
            
        url = self.url_template.replace("{{domain}}", urllib.parse.quote(domain))
        
        try:
            async with session.request(self.method, url, headers=self.headers, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    if self.regex:
                        # Extract via Regex
                        matches = self.regex.findall(text)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            # Clean up and validate
                            clean = match.strip().lower()
                            if clean.endswith(domain) and clean != domain:
                                found.add(clean)
                                
        except Exception as e:
            log.debug(f"[{self.name}] Error fetching YAML source: {e}")
            
        return found
