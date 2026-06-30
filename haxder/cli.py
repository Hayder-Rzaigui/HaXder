import argparse
import asyncio
import csv
import datetime
import json
import logging
import os
import re
import sys
from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich.panel import Panel
from rich.box import SQUARE, HEAVY_HEAD
from rich.text import Text
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.logging import RichHandler

from haxder.enumerator import SubdomainEnumerator
from haxder.resolver import SubdomainResolver
from haxder.mutator import PermutationEngine
from haxder.bruteforce import BruteForceEngine
from haxder.prober import HttpProber
from haxder.takeover import TakeoverEngine
from haxder.webhooks import Notifier
from haxder.db import Database
from haxder.utils.resolvers import ResolversUpdater
from haxder.utils.asn import ASNLookup
from haxder.utils.bounty import BountyScopeFetcher
from haxder.extractor import UrlExtractor
from haxder.vuln_engine import VulnEngine
import aiohttp

# ---------------------------------------------------------------------------
# Corporate Enterprise theme
# A restrained, professional palette: steel blue for primary/info,
# slate gray for secondary/neutral text, muted teal for success,
# amber for warnings, and a desaturated red for critical findings.
# ---------------------------------------------------------------------------
HAXDER_THEME = Theme({
    "brand":        "bold #4C8BF5",     # primary accent (headers, banner)
    "brand.dim":    "#7C93B5",          # secondary accent (rules, borders)
    "info":         "#5C9CE6",          # informational step messages
    "success":      "#3DA88A",          # completed steps
    "warning":      "#D8A23B",          # non-fatal issues
    "danger":       "bold #C75450",     # failures
    "critical":     "bold white on #8B2E2E",  # takeover / vuln highlight
    "muted":        "#8C97A8",          # secondary / neutral text
    "label":        "bold #2E3B4E",     # field labels
    "value":        "#37475A",          # field values
})

console = Console(theme=HAXDER_THEME)
silent_console = Console(stderr=True, theme=HAXDER_THEME)


def print_banner():
    """Render the corporate-style startup banner."""
    title = Text("HAXDER", style="bold #FFFFFF on #1F4E8C", justify="center")
    subtitle = Text("Enterprise Attack Surface Management", style="brand.dim", justify="center")
    panel = Panel(
        Text.assemble(title, "\n", subtitle),
        box=SQUARE,
        border_style="brand.dim",
        padding=(1, 4),
        expand=False,
    )
    console.print(panel, justify="center")


def print_step(message: str):
    console.print(f"  [brand]›[/brand] [info]{message}[/info]")


def print_success(message: str):
    console.print(f"  [success]✓[/success] [success]{message}[/success]")


def print_warning(message: str):
    console.print(f"  [warning]⚠[/warning] [warning]{message}[/warning]")


def print_error(message: str):
    console.print(f"  [danger]✗[/danger] [danger]{message}[/danger]")


def print_section(label: str):
    console.print(Rule(f"[label]{label}[/label]", style="brand.dim", align="left"))

def setup_logging(verbose: bool, silent: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    if silent:
        logging.basicConfig(level=logging.CRITICAL, stream=sys.stderr)
    else:
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=verbose)]
        )
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)

def validate_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    return bool(re.match(pattern, domain))

def write_output_file(output_path: str, target_domain: str, resolved_data: dict, probe_data: dict, takeover_data: dict):
    """
    Writes scan results to disk in JSON or CSV format, inferred from the file
    extension. When scanning multiple domains in one run (e.g. via --asn,
    --cidr, or --program), results are merged into the same file rather than
    overwritten, so each domain's findings are preserved.
    """
    ext = os.path.splitext(output_path)[1].lower()

    rows = []
    for sub, data in sorted(resolved_data.items()):
        rows.append({
            "domain": target_domain,
            "subdomain": sub,
            "ips": data.get("ips", []),
            "cnames": data.get("cnames", []),
            "status": probe_data.get(sub, {}).get("status", "N/A"),
            "title": probe_data.get(sub, {}).get("title", "N/A"),
            "takeover_risk": takeover_data.get(sub, ""),
        })

    if ext == ".csv":
        file_exists = os.path.exists(output_path)
        with open(output_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "subdomain", "ips", "cnames", "status", "title", "takeover_risk"])
            if not file_exists:
                writer.writeheader()
            for row in rows:
                writer.writerow({
                    **row,
                    "ips": ";".join(row["ips"]),
                    "cnames": ";".join(row["cnames"]),
                })
    else:
        # Default to JSON for .json or any other/missing extension.
        existing = {}
        if os.path.exists(output_path):
            try:
                with open(output_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                    if not isinstance(existing, dict):
                        existing = {}
            except (json.JSONDecodeError, OSError):
                existing = {}

        existing[target_domain] = rows
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

class UniqueQueue:
    def __init__(self, q: asyncio.Queue):
        self.q = q
        self.seen = set()

    async def put(self, item):
        if item not in self.seen:
            self.seen.add(item)
            await self.q.put(item)

async def run_pipeline_for_domain(target_domain: str, args, enumerator: SubdomainEnumerator, db: Database, notifier: Notifier):
    if not args.quiet:
        console.print()
        print_section(f"Target: {target_domain}")

    previous_subs = db.get_previous_subdomains(target_domain) if args.monitor else set()
    
    subdomain_queue = asyncio.Queue()
    unique_sub_queue = UniqueQueue(subdomain_queue)
    resolved_queue = asyncio.Queue()
    
    resolved_data = {}
    
    resolver = None
    if not args.skip_resolve:
        resolver = SubdomainResolver(threads=args.concurrency, resolvers_file=args.resolver_file)

    async def output_worker():
        while True:
            item = await resolved_queue.get()
            if item is None:
                break
            
            sub = item["subdomain"]
            
            if args.monitor and sub in previous_subs:
                resolved_queue.task_done()
                continue
                
            resolved_data[sub] = {"ips": item["ips"], "cnames": item["cnames"]}
            
            if args.quiet:
                if args.stdout_format == "jsonl":
                    sys.stdout.write(json.dumps(item) + "\n")
                else:
                    sys.stdout.write(f"{sub}\n")
                sys.stdout.flush()
                
            resolved_queue.task_done()

    out_task = asyncio.create_task(output_worker())

    resolver_workers = []
    if resolver:
        for _ in range(args.concurrency):
            worker = asyncio.create_task(resolver.resolve_worker(subdomain_queue, resolved_queue, target_domain))
            resolver_workers.append(worker)

    enum_progress_cb = None
    if not args.quiet:
        progress = Progress(
            SpinnerColumn(style="brand"),
            TextColumn("[info]{task.description}[/info]"),
            BarColumn(complete_style="brand", finished_style="success", style="muted"),
            TaskProgressColumn(style="value"),
            console=console, transient=True
        )
        progress.start()
        enum_task_progress = progress.add_task("Passive enumeration...", total=len(enumerator.sources))
        def enum_progress_cb(source_name):
            progress.advance(enum_task_progress)

    discovered_passive = await enumerator.enumerate(target_domain, progress_callback=enum_progress_cb, out_queue=unique_sub_queue)
    
    if not args.quiet:
        progress.stop()
        print_success(f"Passive enumeration complete — {len(discovered_passive)} subdomains found")

    discovered_all = set(discovered_passive)
    
    if args.permute and discovered_passive:
        if not args.quiet:
            print_step("Running permutation engine...")
        engine = PermutationEngine(alterations_file=args.permute_list)
        mutated = engine.mutate(discovered_passive, target_domain)
        for m in mutated:
            await unique_sub_queue.put(m)
        discovered_all.update(mutated)

    if args.brute:
        if not args.quiet:
            print_step("Running active dictionary brute force...")
        bf_engine = BruteForceEngine(wordlist_path=args.dict_file)
        bf_engine.load_words()
        bf_candidates = bf_engine.generate(target_domain)
        for b in bf_candidates:
            await unique_sub_queue.put(b)
        discovered_all.update(bf_candidates)

    if not args.skip_resolve:
        for _ in range(args.concurrency):
            await subdomain_queue.put(None)
        await asyncio.gather(*resolver_workers)
    else:
        for sub in discovered_all:
            if args.monitor and sub in previous_subs:
                continue
            if args.quiet:
                sys.stdout.write(f"{sub}\n")
                sys.stdout.flush()
            resolved_data[sub] = {"ips": [], "cnames": []}
            
    await resolved_queue.put(None)
    await out_task
    
    if args.deep_scan and not args.quiet:
        print_step("Starting recursive enumeration on active subdomains...")
        for sub in list(resolved_data.keys()):
            if sub != target_domain:
                recursive_subs = await enumerator.enumerate(sub, progress_callback=None)
                for r_sub in recursive_subs:
                    if args.monitor and r_sub in previous_subs:
                        continue
                    if r_sub not in resolved_data:
                        resolved_data[r_sub] = {"ips": [], "cnames": []}

    db.save_subdomains(target_domain, set(resolved_data.keys()).union(previous_subs))

    probe_data = {}
    takeover_data = {}
    if (args.http_check or args.check_takeover) and resolved_data:
        # Parse ports
        ports = [int(p.strip()) for p in args.port_list.split(',')] if args.port_list else [80, 443]
        prober = HttpProber(threads=args.concurrency, ports=ports)
        takeover_engine = TakeoverEngine() if args.check_takeover else None
        
        active_subs = list(resolved_data.keys())
        if not args.quiet:
            print_step(f"Running HTTP probing — {len(ports)} ports across {len(active_subs)} targets...")
            
        probe_data = await prober.probe_all(active_subs)
            
        if args.check_takeover:
            for sub, data in probe_data.items():
                cnames = resolved_data.get(sub, {}).get("cnames", [])
                vuln_service = takeover_engine.check_takeover(cnames, data.get("body", ""))
                if vuln_service:
                    takeover_data[sub] = vuln_service
        
        if not args.quiet:
            print_success("HTTP probing and analysis complete")
            if args.check_takeover and takeover_data:
                console.print(f"  [critical] ⚠ {len(takeover_data)} POTENTIAL SUBDOMAIN TAKEOVER(S) DETECTED [/critical]")

    # URL Extraction & Secret Scanning
    secret_findings = []
    if args.harvest and resolved_data:
        extractor = UrlExtractor(threads=args.concurrency)
        if not args.quiet:
            print_step("Running Wayback URL extraction and secret scanning...")
        urls = await extractor.get_urls(target_domain)
        if urls:
            secret_findings = await extractor.scan_secrets(urls)
            if not args.quiet:
                print_success(f"Extracted {len(urls)} URLs — {len(secret_findings)} exposed secret(s) found")

    # Native Vulnerability Scanning
    vuln_findings = []
    if args.vuln_scan and resolved_data:
        vuln_engine = VulnEngine()
        active_targets = []
        for sub, data in probe_data.items():
            if data.get("status") != "ERR":
                port_str = ""
                # A simplistic way to guess URL for vuln engine based on active probes
                # Ideally, prober would return the full URL that succeeded, but we'll use https default
                active_targets.append(f"https://{sub}")
                
        if not active_targets:
            active_targets = list(resolved_data.keys())
            
        vuln_findings = await vuln_engine.scan(active_targets, threads=args.concurrency)
        if not args.quiet and vuln_findings:
            console.print(f"  [critical] ⚠ Vulnerability engine found {len(vuln_findings)} potential issue(s) [/critical]")

    # Worker Node Submission
    if args.worker_of:
        master_url = args.worker_of.rstrip('/') + "/api/worker/submit"
        payload = {
            "target_domain": target_domain,
            "subdomains": list(resolved_data.keys())
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(master_url, json=payload, timeout=10) as resp:
                    if resp.status == 200:
                        if not args.quiet:
                            print_success(f"Results submitted to master node ({args.worker_of})")
        except Exception as e:
            if not args.quiet:
                print_error(f"Failed to submit to master node: {e}")

    # DNS Email Security Audit
    dns_audit_results = {}
    if resolved_data and not args.skip_resolve:
        from haxder.dns_audit import DnsAuditor
        if not args.quiet:
            print_step("Running DNS email security (SPF/DMARC) audit...")
        try:
            auditor = DnsAuditor()
            dns_audit_results = await auditor.audit_domain(target_domain)
            if not args.quiet:
                spf_status = dns_audit_results.get("spf", {}).get("status", "N/A")
                dmarc_status = dns_audit_results.get("dmarc", {}).get("status", "N/A")
                print_success(f"DNS audit complete — SPF: {spf_status} | DMARC: {dmarc_status}")
        except Exception as e:
            if not args.quiet:
                print_error(f"DNS audit failed: {e}")

    # Report Generation
    if args.html_report and resolved_data:
        from haxder.reporter import ReportGenerator
        if not args.quiet:
            print_step(f"Generating interactive HTML report: {args.html_report}...")
        try:
            reporter = ReportGenerator(
                target_domain=target_domain,
                resolved_data=resolved_data,
                probe_data=probe_data,
                takeover_data=takeover_data,
                secret_findings=secret_findings,
                vuln_findings=vuln_findings,
                dns_audit_results=dns_audit_results
            )
            reporter.generate_html(args.html_report)
            if not args.quiet:
                print_success(f"Report saved to {args.html_report}")
        except Exception as e:
            if not args.quiet:
                print_error(f"Failed to generate report: {e}")

    if notifier:
        msg = f"[*] HaXder Scan Completed for `{target_domain}`\n"
        if args.monitor:
            msg += f"[+] NEW Discovered: **{len(resolved_data)}** subdomains\n"
        else:
            msg += f"[+] Discovered: **{len(discovered_all)}** subdomains\n"
            msg += f"[+] Active/Resolved: **{len(resolved_data)}** subdomains"
        if args.check_takeover and takeover_data:
            msg += f"\n[!] Potential Takeovers: **{len(takeover_data)}**"
        await notifier.send_notification(msg)

        # SIEM / JSON Webhook Integration
        siem_payload = {
            "target_domain": target_domain,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "summary": {
                "total_subdomains": len(discovered_all) if 'discovered_all' in locals() else len(resolved_data),
                "resolved_subdomains": len(resolved_data),
                "vulnerabilities_found": len(vuln_findings),
                "secrets_found": len(secret_findings),
                "takeover_risks": len(takeover_data)
            },
            "dns_audit": dns_audit_results,
            "subdomains": [
                {
                    "subdomain": sub,
                    "ips": data.get("ips", []),
                    "cnames": data.get("cnames", []),
                    "status_code": probe_data.get(sub, {}).get("status", "N/A"),
                    "title": probe_data.get(sub, {}).get("title", "N/A"),
                    "takeover_risk": takeover_data.get(sub, ""),
                    "missing_headers": probe_data.get(sub, {}).get("missing_headers", [])
                }
                for sub, data in resolved_data.items()
            ],
            "vulnerabilities": vuln_findings,
            "secrets": secret_findings
        }
        await notifier.send_siem_data(siem_payload)

    if args.save:
        write_output_file(args.save, target_domain, resolved_data, probe_data, takeover_data)
        if not args.quiet:
            print_success(f"Results saved to {args.save}")

    if not args.quiet:
        mode_tag = " · Diff Mode" if args.monitor else ""

        table = Table(
            box=HEAVY_HEAD,
            border_style="brand.dim",
            header_style="bold white on #1F4E8C",
            row_styles=["value"],
            pad_edge=False,
            expand=True,
            show_lines=False,
        )
        table.add_column("SUBDOMAIN", style="bold #2E3B4E", no_wrap=True, ratio=3)
        table.add_column("RESOLVED IP(S)", style="#3B6FB6", ratio=3)
        if args.http_check or args.check_takeover:
            table.add_column("STATUS", justify="center", ratio=1)
            table.add_column("PAGE TITLE", style="muted", ratio=3)
        if args.check_takeover:
            table.add_column("TAKEOVER RISK", justify="center", ratio=2)

        for sub, res_dict in sorted(resolved_data.items()):
            ips = res_dict.get("ips", [])
            ip_str = "\n".join(ips) if ips else "[danger]not resolved[/danger]"
            row_data = [sub, ip_str]

            if args.http_check or args.check_takeover:
                status = probe_data.get(sub, {}).get("status", "N/A")
                title = probe_data.get(sub, {}).get("title", "N/A") or "[muted]—[/muted]"
                if status == "200":
                    status_str = f"[success]{status}[/success]"
                elif status == "ERR":
                    status_str = f"[danger]{status}[/danger]"
                else:
                    status_str = f"[warning]{status}[/warning]"
                row_data.extend([status_str, title])

            if args.check_takeover:
                if sub in takeover_data:
                    row_data.append(f"[critical] {takeover_data[sub]} [/critical]")
                else:
                    row_data.append("[muted]—[/muted]")

            table.add_row(*row_data)

        panel = Panel(
            table,
            title=f"[bold white]SCAN RESULTS[/bold white]  ·  [brand.dim]{target_domain}{mode_tag}[/brand.dim]",
            title_align="left",
            subtitle=f"[muted]{len(resolved_data)} host(s) resolved[/muted]",
            subtitle_align="right",
            box=SQUARE,
            border_style="brand.dim",
            padding=(1, 1),
        )
        console.print()
        console.print(panel)


async def async_main(args):
    if args.refresh_resolvers:
        updater = ResolversUpdater(args.resolver_file)
        await updater.update()
        if not args.quiet:
            print_success("Resolvers updated")

    target_domains = []
    if args.target:
        target_domains.append(args.target.strip().lower())
    if args.as_number:
        asn_targets = await ASNLookup.get_domains(args.as_number)
        target_domains.extend(asn_targets)
    if args.ip_range:
        cidr_targets = await ASNLookup.get_domains(args.ip_range)
        target_domains.extend(cidr_targets)
    if args.bounty_scope:
        prog_targets = await BountyScopeFetcher.get_program_scope(args.bounty_scope)
        target_domains.extend(prog_targets)

    target_domains = list(set([d for d in target_domains if validate_domain(d)]))

    if not target_domains:
        if not args.quiet:
            print_error("No valid target domains provided or discovered from ASN/CIDR")
        sys.exit(1)

    if not args.quiet:
        print_banner()
        console.print(f"  [label]Targets loaded:[/label] [value]{len(target_domains)}[/value]\n")

    db = Database()
    notifier = Notifier(config_path=args.conf) if args.alert else None
    enumerator = SubdomainEnumerator(config_path=args.conf)

    for domain in target_domains:
        await run_pipeline_for_domain(domain, args, enumerator, db, notifier)

def main():
    parser = argparse.ArgumentParser(description="HaXder - The Ultimate Subdomain Enumeration Framework")
    
    # Inputs
    parser.add_argument("-T", "--target", dest="target", help="Target domain (e.g., example.com)")
    parser.add_argument("--as-number", dest="as_number", help="Target ASN (e.g., AS15169) to discover associated domains")
    parser.add_argument("--ip-range", dest="ip_range", help="Target CIDR (e.g., 104.16.0.0/24) to discover associated domains")
    parser.add_argument("--bounty-scope", dest="bounty_scope", help="Target Bug Bounty program (e.g., yahoo) to fetch in-scope domains")
    
    # Core Engine
    parser.add_argument("-C", "--concurrency", dest="concurrency", type=int, default=500, help="Number of concurrent connections")
    parser.add_argument("-K", "--conf", dest="conf", help="Path to YAML config file", default="config.yaml")
    parser.add_argument("-R", "--resolver-file", dest="resolver_file", help="Path to DNS resolvers", default="resolvers.txt")
    parser.add_argument("--refresh-resolvers", dest="refresh_resolvers", action="store_true", help="Download the latest trusted resolvers")
    parser.add_argument("--skip-resolve", dest="skip_resolve", action="store_true", help="Skip DNS validation")
    parser.add_argument("--monitor", dest="monitor", action="store_true", help="Continuous Monitoring: output only new subdomains")
    parser.add_argument("--deep-scan", dest="deep_scan", action="store_true", help="Run enumeration recursively")
    
    # Alteration & Bruteforce
    parser.add_argument("--permute", dest="permute", action="store_true", help="Enable Advanced Permutation Engine")
    parser.add_argument("--permute-list", dest="permute_list", help="Path to custom wordlist for Permutation/Alteration engine")
    parser.add_argument("-B", "--brute", dest="brute", action="store_true", help="Enable Active Dictionary Brute Forcing")
    parser.add_argument("-D", "--dict-file", dest="dict_file", help="Path to wordlist for brute forcing", default="wordlists/subdomains.txt")
    
    # Probing & Vulnerabilities
    parser.add_argument("--http-check", dest="http_check", action="store_true", help="Enable HTTP/Port Probing")
    parser.add_argument("--port-list", dest="port_list", help="Comma-separated ports to probe (e.g., 80,443,8080)", default="80,443")
    parser.add_argument("--check-takeover", dest="check_takeover", action="store_true", help="Enable Subdomain Takeover Detection")
    parser.add_argument("--harvest", dest="harvest", action="store_true", help="Extract URLs and scan JS files for secrets/API keys")
    parser.add_argument("--vuln-scan", dest="vuln_scan", action="store_true", help="Enable Native Vulnerability Engine (YAML Templates)")
    
    # Web Dashboard & Distributed
    parser.add_argument("--gui", dest="gui", action="store_true", help="Start the HaXder Web GUI Dashboard")
    parser.add_argument("--master-mode", dest="master_mode", action="store_true", help="Start the Web GUI as a Master Node for distributed scanning")
    parser.add_argument("--worker-of", dest="worker_of", help="URL of the Master Node to submit results to (e.g., http://master:8000)")
    parser.add_argument("--gui-port", dest="gui_port", type=int, default=8000, help="Port for the Web GUI Dashboard / Master Node")
    
    # Output & Notify
    parser.add_argument("-O", "--save", dest="save", help="Output file path (JSON or CSV based on extension)")
    parser.add_argument("-F", "--stdout-format", dest="stdout_format", choices=["table", "jsonl"], default="table", help="Format for stdout")
    parser.add_argument("-Q", "--quiet", dest="quiet", action="store_true", help="Quiet mode (stdout is raw subdomains only)")
    parser.add_argument("-V", "--debug", dest="debug", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--alert", dest="alert", action="store_true", help="Send webhooks notifications")
    parser.add_argument("--html-report", dest="html_report", help="Path to save the interactive HTML report (e.g., report.html)")

    args = parser.parse_args()

    if args.gui or args.master_mode:
        setup_logging(args.debug, False)
        from haxder.web import run_server
        run_server(port=args.gui_port, master_mode=args.master_mode)
        sys.exit(0)

    setup_logging(args.debug, args.quiet)
        
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        if not args.quiet:
            print_warning("Interrupted by user. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
