import asyncio
import logging
import aiodns

log = logging.getLogger("haxder")

class DnsAuditor:
    """
    Audits domain DNS records for email security configurations (SPF & DMARC).
    Helps detect vulnerabilities allowing email spoofing.
    """
    def __init__(self, timeout: float = 5.0):
        self.resolver = aiodns.DNSResolver(timeout=timeout, tries=2)

    async def _query_txt(self, domain: str) -> list:
        try:
            answers = await self.resolver.query(domain, 'TXT')
            txt_records = []
            for ans in answers:
                if hasattr(ans, 'text'):
                    # Convert to string if it is bytes
                    txt_val = ans.text.decode('utf-8', errors='ignore') if isinstance(ans.text, bytes) else str(ans.text)
                    txt_records.append(txt_val)
            return txt_records
        except Exception:
            return []

    async def audit_domain(self, domain: str) -> dict:
        """
        Audits a base domain's SPF and DMARC policies.
        Returns:
            dict containing status, findings, and parsed records.
        """
        log.debug(f"[*] Auditing DNS Email Security records for {domain}...")
        
        # 1. Fetch SPF Record
        txt_records = await self._query_txt(domain)
        spf_record = None
        for record in txt_records:
            if record.strip().lower().startswith("v=spf1"):
                spf_record = record.strip()
                break

        # 2. Fetch DMARC Record
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records = await self._query_txt(dmarc_domain)
        dmarc_record = None
        for record in dmarc_records:
            if record.strip().lower().startswith("v=dmarc1"):
                dmarc_record = record.strip()
                break

        # 3. Analyze records
        spf_status = "Safe"
        spf_finding = ""
        if not spf_record:
            spf_status = "Vulnerable"
            spf_finding = "Missing SPF record. Anyone can spoof emails pretending to come from this domain."
        else:
            spf_lower = spf_record.lower()
            if "+all" in spf_lower or "?all" in spf_lower:
                spf_status = "Warning"
                spf_finding = "Weak SPF configuration (+all or ?all). Policy allows/ignores unauthorized senders."
            elif "~all" in spf_lower:
                spf_status = "Warning"
                spf_finding = "SPF uses SoftFail (~all). Spoofed emails might still land in the inbox."
            elif "-all" in spf_lower:
                spf_status = "Safe"
                spf_finding = "Strong SPF configuration (-all). Strict rejection policy."

        dmarc_status = "Safe"
        dmarc_finding = ""
        if not dmarc_record:
            dmarc_status = "Vulnerable"
            dmarc_finding = "Missing DMARC record. Mail servers cannot verify spoofing reports."
        else:
            dmarc_lower = dmarc_record.lower()
            if "p=none" in dmarc_lower:
                dmarc_status = "Warning"
                dmarc_finding = "DMARC policy set to none (p=none). Emails are monitored but spoofing is not blocked."
            elif "p=quarantine" in dmarc_lower:
                dmarc_status = "Safe"
                dmarc_finding = "DMARC policy set to quarantine. Unverified emails will go to junk folder."
            elif "p=reject" in dmarc_lower:
                dmarc_status = "Safe"
                dmarc_finding = "Strong DMARC policy set to reject. Unverified emails will be dropped."

        return {
            "domain": domain,
            "spf": {
                "record": spf_record or "None",
                "status": spf_status,
                "finding": spf_finding
            },
            "dmarc": {
                "record": dmarc_record or "None",
                "status": dmarc_status,
                "finding": dmarc_finding
            }
        }
