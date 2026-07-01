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
from rich.table import Table
from rich.theme import Theme
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.logging import RichHandler

from haxder.discovery import SubdomainEnumerator
from haxder.dns_resolve import SubdomainResolver
from haxder.permutations import PermutationEngine
from haxder.dictionary_scan import BruteForceEngine
from haxder.http_scan import HttpProber
from haxder.takeover_check import TakeoverEngine
from haxder.alerts import Notifier
from haxder.storage import Database
from haxder.helpers.resolver_update import ResolversUpdater
from haxder.helpers.asn_lookup import ASNLookup
from haxder.helpers.bounty_scope import BountyScopeFetcher
from haxder.url_harvester import UrlExtractor
from haxder.vuln_scan import VulnEngine
import aiohttp

# Slate / amber / teal palette - kept intentionally distinct from the
# default rich "bold cyan / bold green / bold red" combo so output has
# its own visual identity rather than looking like generic tool boilerplate.
HAXDER_THEME = Theme({
    "brand":    "bold turquoise2",
    "info":     "bold steel_blue1",
    "success":  "bold sea_green3",
    "warning":  "bold dark_orange3",
    "danger":   "bold bright_red",
    "accent":   "bold plum2",
    "muted":    "grey62",
    "header":   "bold white on grey19",
})

console = Console(theme=HAXDER_THEME)
silent_console = Console(stderr=True, theme=HAXDER_THEME)

def print_banner():
    title = Text("H A X D E R", style="brand", justify="center")
    subtitle = Text("Attack Surface Recon Framework", style="muted", justify="center")
    author = Text("— Hayder Rzaigui —", style="accent", justify="center")
    body = Text.assemble(title, "\n", subtitle, "\n", author)
    panel = Panel(
        Align.center(body),
        box=box.HEAVY,
        border_style="brand",
        padding=(1, 6),
    )
    console.print(Align.center(panel))
    console.print()

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
        console.rule(f"[info]Scanning Target » {target_domain}[/info]", style="accent")
        console.print()

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
            SpinnerColumn(style="accent"), TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="brand", finished_style="success"), TaskProgressColumn(), console=console, transient=True
        )
        progress.start()
        enum_task_progress = progress.add_task("[info]Passive enumeration in progress...", total=len(enumerator.sources))
        def enum_progress_cb(source_name):
            progress.advance(enum_task_progress)

    discovered_passive = await enumerator.enumerate(target_domain, progress_callback=enum_progress_cb, out_queue=unique_sub_queue)
    
    if not args.quiet:
        progress.stop()
        console.print(f"[success]✓ Passive Enumeration complete. Found {len(discovered_passive)} subdomains.[/success]")

    discovered_all = set(discovered_passive)
    
    if args.permute and discovered_passive:
        if not args.quiet:
            console.print("[info]▸ Running Permutation Engine...[/info]")
        engine = PermutationEngine(alterations_file=args.permute_list)
        mutated = engine.mutate(discovered_passive, target_domain)
        for m in mutated:
            await unique_sub_queue.put(m)
        discovered_all.update(mutated)

    if args.brute:
        if not args.quiet:
            console.print("[info]▸ Running Active Dictionary Brute Forcing...[/info]")
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
        console.print(f"[info]▸ Starting Recursive Enumeration on active subdomains...[/info]")
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
            console.print(f"[info]▸ Running Port/HTTP Probing on {len(ports)} ports across {len(active_subs)} targets...[/info]")
            
        probe_data = await prober.probe_all(active_subs)
            
        if args.check_takeover:
            for sub, data in probe_data.items():
                cnames = resolved_data.get(sub, {}).get("cnames", [])
                vuln_service = takeover_engine.check_takeover(cnames, data.get("body", ""))
                if vuln_service:
                    takeover_data[sub] = vuln_service
        
        if not args.quiet:
            console.print(f"[success]✓ HTTP Probing & Analysis complete.[/success]")
            if args.check_takeover and takeover_data:
                console.print(f"[danger]✗ Found {len(takeover_data)} POTENTIAL SUBDOMAIN TAKEOVERS![/danger]")

    # URL Extraction & Secret Scanning
    secret_findings = []
    if args.harvest and resolved_data:
        extractor = UrlExtractor(threads=args.concurrency)
        if not args.quiet:
            console.print(f"[info]▸ Running Wayback URL Extraction & Secret Scanning...[/info]")
        urls = await extractor.get_urls(target_domain)
        if urls:
            secret_findings = await extractor.scan_secrets(urls)
            if not args.quiet:
                console.print(f"[success]✓ Extracted {len(urls)} URLs. Found {len(secret_findings)} exposed secrets in JS files.[/success]")

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
            console.print(f"[danger]✗ Vulnerability Engine found {len(vuln_findings)} potential issues![/danger]")

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
                            console.print(f"[success]✓ Successfully submitted results to Master Node ({args.worker_of}).[/success]")
        except Exception as e:
            if not args.quiet:
                console.print(f"[danger]✗ Failed to submit to Master Node: {e}[/danger]")

    # DNS Email Security Audit
    dns_audit_results = {}
    if resolved_data and not args.skip_resolve:
        from haxder.mail_dns_check import DnsAuditor
        if not args.quiet:
            console.print(f"[info]▸ Running DNS Email Security (SPF/DMARC) Audit...[/info]")
        try:
            auditor = DnsAuditor()
            dns_audit_results = await auditor.audit_domain(target_domain)
            if not args.quiet:
                spf_status = dns_audit_results.get("spf", {}).get("status", "N/A")
                dmarc_status = dns_audit_results.get("dmarc", {}).get("status", "N/A")
                console.print(f"[success]✓ DNS Audit Complete. SPF: {spf_status} | DMARC: {dmarc_status}[/success]")
        except Exception as e:
            if not args.quiet:
                console.print(f"[danger]✗ DNS Audit failed: {e}[/danger]")

    # Report Generation
    if args.html_report and resolved_data:
        from haxder.report_builder import ReportGenerator
        if not args.quiet:
            console.print(f"[info]▸ Generating interactive HTML report: {args.html_report}...[/info]")
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
                console.print(f"[success]✓ Report successfully saved to {args.html_report}[/success]")
        except Exception as e:
            if not args.quiet:
                console.print(f"[danger]✗ Failed to generate report: {e}[/danger]")

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
            console.print(f"[success]✓ Results saved to {args.save}[/success]")

    if not args.quiet:
        table_title = f"Results — {target_domain}" + (" [monitor mode]" if args.monitor else "")
        table = Table(
            title=table_title,
            title_style="bold brand",
            box=box.ROUNDED,
            border_style="grey50",
            header_style="header",
            row_styles=["", "on grey11"],
            pad_edge=False,
            expand=False,
        )
        table.add_column("Subdomain", style="accent", no_wrap=True)
        table.add_column("Resolved IPs", style="steel_blue1")
        if args.http_check or args.check_takeover:
            table.add_column("Status", justify="center")
            table.add_column("Title", style="muted")
        if args.check_takeover:
            table.add_column("Takeover Risk", justify="center")

        for sub, res_dict in sorted(resolved_data.items()):
            ips = res_dict.get("ips", [])
            ip_str = "\n".join(ips) if ips else "[danger]unresolved[/danger]"
            row_data = [sub, ip_str]
            if args.http_check or args.check_takeover:
                status = probe_data.get(sub, {}).get("status", "N/A")
                title = probe_data.get(sub, {}).get("title", "N/A")
                status_str = f"[success]{status}[/success]" if status == "200" else f"[warning]{status}[/warning]" if status != "ERR" else f"[danger]{status}[/danger]"
                row_data.extend([status_str, title])
            if args.check_takeover:
                row_data.append(f"[bold black on dark_orange3] RISK: {takeover_data[sub]} [/bold black on dark_orange3]" if sub in takeover_data else "[muted]—[/muted]")
            table.add_row(*row_data)
        
        console.print(table)
        console.print()


async def async_main(args):
    if args.refresh_resolvers:
        updater = ResolversUpdater(args.resolver_file)
        await updater.update()
        if not args.quiet:
            console.print(f"[success]✓ Resolvers updated.[/success]")

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
            console.print("[danger]Error: No valid target domains provided or discovered from ASN/CIDR.[/danger]")
        sys.exit(1)

    if not args.quiet:
        print_banner()
        console.print(f"[info]▸ Loaded [bold]{len(target_domains)}[/bold] base domain(s) to scan.[/info]\n")

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
    parser.add_argument("-K", "--conf", dest="conf", help="Path to YAML config file", default="settings.yaml")
    parser.add_argument("-R", "--resolver-file", dest="resolver_file", help="Path to DNS resolvers", default="dns_resolvers.txt")
    parser.add_argument("--refresh-resolvers", dest="refresh_resolvers", action="store_true", help="Download the latest trusted resolvers")
    parser.add_argument("--skip-resolve", dest="skip_resolve", action="store_true", help="Skip DNS validation")
    parser.add_argument("--monitor", dest="monitor", action="store_true", help="Continuous Monitoring: output only new subdomains")
    parser.add_argument("--deep-scan", dest="deep_scan", action="store_true", help="Run enumeration recursively")
    
    # Alteration & Bruteforce
    parser.add_argument("--permute", dest="permute", action="store_true", help="Enable Advanced Permutation Engine")
    parser.add_argument("--permute-list", dest="permute_list", help="Path to custom wordlist for Permutation/Alteration engine")
    parser.add_argument("-B", "--brute", dest="brute", action="store_true", help="Enable Active Dictionary Brute Forcing")
    parser.add_argument("-D", "--dict-file", dest="dict_file", help="Path to wordlist for brute forcing", default="dictionaries/subdomain_dictionary.txt")
    
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
    parser.add_argument("-Q", "--quiet", "--silent", dest="quiet", action="store_true", help="Silent mode: suppress banner and status output, print raw scan data only")
    parser.add_argument("-V", "--debug", dest="debug", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--alert", dest="alert", action="store_true", help="Send webhooks notifications")
    parser.add_argument("--html-report", dest="html_report", help="Path to save the interactive HTML report (e.g., report.html)")

    args = parser.parse_args()

    if args.gui or args.master_mode:
        setup_logging(args.debug, False)
        from haxder.dashboard import run_server
        run_server(port=args.gui_port, master_mode=args.master_mode)
        sys.exit(0)

    setup_logging(args.debug, args.quiet)
        
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        if not args.quiet:
            console.print("\n[warning]! Interrupted by user. Exiting...[/warning]")
        sys.exit(0)

if __name__ == "__main__":
    main()
