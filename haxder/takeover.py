import json
import logging
import os
from typing import List, Dict, Optional

log = logging.getLogger("haxder")


class TakeoverEngine:
    """
    Detects Subdomain Takeover vulnerabilities by matching HTTP responses
    and CNAME records against known cloud provider fingerprints.
    """

    def __init__(self, signatures_path: str = "signatures.json"):
        self.signatures: List[Dict] = self._load_signatures(signatures_path)

    def _load_signatures(self, path: str) -> List[Dict]:
        if not os.path.exists(path):
            log.warning("Signatures file not found at %s. Takeover engine disabled.", path)
            return []

        try:
            with open(path, "r", encoding="utf-8") as fh:
                signatures = json.load(fh)
            log.debug("Loaded %d takeover signatures from %s", len(signatures), path)
            return signatures
        except Exception as exc:
            log.error("Error parsing signatures file %s: %s", path, exc)
            return []

    def _cname_matches(self, required_cnames: List[str], actual_cnames: List[str]) -> bool:
        if not actual_cnames:
            return False
        return any(
            required.lower() in actual.lower()
            for required in required_cnames
            for actual in actual_cnames
        )

    def check_takeover(self, cnames: List[str], http_response_body: str) -> Optional[str]:
        """
        Returns the name of the vulnerable service if a takeover is possible, else None.
        """
        if not self.signatures or not http_response_body:
            return None

        for sig in self.signatures:
            fingerprint = sig.get("fingerprint", "")
            if not fingerprint or fingerprint not in http_response_body:
                continue

            service = sig.get("service")
            required_cnames = sig.get("cname", [])

            # No CNAME constraint defined for this signature - body match is enough
            if not required_cnames:
                return service

            # CNAMEs are defined - prefer a confirmed match against the resolved chain
            if self._cname_matches(required_cnames, cnames):
                return service

            # DNS resolution can occasionally miss the CNAME chain even though the
            # response body still matches a known vulnerable-service fingerprint.
            # Flag it, but mark it as a body-only match so it can be triaged separately.
            return f"{service} (Body Match)"

        return None
