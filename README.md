<div align="center">
  <h1>HaXder v0.3.0 Enterprise Edition</h1>
  <p><b>Async Passive Subdomain Discovery, Active Brute-Forcing & Attack Surface Management Toolkit</b></p>
  <p><i>Built for Red Teamers, Penetration Testers, and Enterprise Security Teams</i></p>

  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
  [![Async](https://img.shields.io/badge/Engine-AsyncIO-lightgrey.svg)]()
</div>

---

**HaXder** maps a domain's exposed surface by combining passive OSINT collection with active validation. It pulls candidate hostnames from a dozen-plus public and premium data sources, expands that list with dictionary brute-forcing and permutation guessing, then runs every candidate through async DNS resolution with wildcard awareness so what comes out the other end is a short list of real, reachable hosts rather than a wall of noise.

**Author & Lead Developer:** **Hayder Rzaigui**

---

## Key Features

- **Async-First Engine:** Runs on `asyncio` + `aiohttp` and comfortably sustains 500+ concurrent connections during a scan.
- **Wide OSINT Footprint:** Queries 11+ data sources — `Shodan`, `VirusTotal`, `ProjectDiscovery Chaos`, `BufferOver`, `crt.sh`, `HackerTarget`, `AlienVault OTX`, `CertSpotter`, `URLScan`, `Anubis`, `SecurityTrails`, and the `WaybackMachine`.
- **Master/Worker Distribution:** Run one Master node plus any number of Worker nodes on separate hosts to spread a large scan across machines.
- **Wayback Crawling + JS Secret Scanning:** Pulls historical URLs out of the Wayback Machine and inspects fetched JavaScript for leaked keys or tokens.
- **SPF/DMARC Auditing:** Flags weak or missing email-auth DNS records that open the door to spoofing.
- **YAML Vulnerability Templates:** Runs lightweight, user-defined YAML checks against live targets to catch common misconfigurations.
- **Takeover Risk Detection:** Matches CNAME chains and response fingerprints against a local signature set to surface dangling-DNS **takeover risk** (S3, GitHub Pages, Heroku, and others).
- **Interactive HTML Reporting:** Outputs a self-contained dark-themed report with charts, sortable tables, and a vulnerability summary.
- **Webhook/SIEM Notifications:** Ships structured JSON scan telemetry to **Slack**, **Discord**, or a generic SIEM webhook.
- **Built-In HTTP Prober:** Hits every resolved host to capture status code, page title, and missing security headers (CSP, HSTS, X-Frame-Options).
- **Custom Terminal UI:** A dedicated slate/teal/amber theme built on `rich` — bordered result tables, a styled banner, and status glyphs instead of default library colors.

---

## Architecture

```mermaid
graph LR
    subgraph Input["Input Layer"]
        User[/Operator Input/]
        Engine{{haxder.runner}}
        Dict[(Dictionary File)]
    end

    subgraph Discovery["Discovery Layer"]
        Harvest[[haxder.discovery]]
        Feeds{{OSINT Feed Pool}}
        Guess[[haxder.dictionary_scan]]
        Combine((Candidate Pool))
        Expand[[haxder.permutations]]
    end

    subgraph Validation["Validation Layer"]
        Check[[haxder.dns_resolve]]
        Names[(Name Servers)]
        Scan[[haxder.http_scan]]
        Hosts[(Live Hosts)]
    end

    subgraph Output["Output & Alerting"]
        View[/Rich Terminal UI/]
        Ship{{Webhook Dispatch}}
        Save[(JSON / CSV Export)]
    end

    User --> Engine
    Engine -- "target domain" --> Harvest
    Harvest <-- "concurrent lookups" --> Feeds
    Engine -- "wordlist path" --> Guess
    Dict --> Guess
    Harvest --> Combine
    Guess --> Combine
    Combine -- "permutation pass" --> Expand
    Expand --> Check
    Check <-- "A/CNAME queries + wildcard filter" --> Names
    Check --> Scan
    Scan -- "HTTP fetch + takeover fingerprint" --> Hosts
    Hosts --> Engine
    Engine --> View
    Engine --> Ship
    Engine --> Save
```

---

## Installation

**1. Grab the source:**
Pull the repository down into whatever working directory you use for tooling.

**2. Install requirements:**
Everything HaXder depends on is pinned in `requirements.txt`:
```bash
pip install -r requirements.txt
```

**3. (Optional) Install in editable mode:**
Useful if you want a bare `haxder` command instead of always typing `python -m`:
```bash
pip install -e .
```

---

## Usage

Give HaXder a domain and a few flags — the rest runs on its own.

```bash
python -m haxder.runner -T target.com --deep-scan --check-takeover --stdout-format jsonl --save findings.json
```

### Command-Line Arguments

| Flag | Long Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `-T` | `--target` | Target base domain (e.g., `tesla.com`) | **Required*** |
| | `--as-number` | Target ASN (e.g., `AS15169`) to discover associated domains | `None` |
| | `--ip-range` | Target CIDR (e.g., `104.16.0.0/24`) to discover associated domains | `None` |
| | `--bounty-scope` | Target bug bounty program (e.g., `yahoo`) to fetch in-scope domains | `None` |
| `-C` | `--concurrency` | Number of concurrent async connections for DNS resolution | `500` |
| `-K` | `--conf` | Path to YAML config file containing API keys | `settings.yaml` |
| `-R` | `--resolver-file` | Path to text file containing custom DNS resolvers | `dns_resolvers.txt` |
| | `--refresh-resolvers` | Download the latest trusted resolver list | `False` |
| | `--skip-resolve`| Skip the DNS validation phase and return all discovered subdomains | `False` |
| | `--monitor` | Continuous monitoring mode: only output subdomains not seen in a previous scan | `False` |
| | `--deep-scan` | Run enumeration recursively against every resolved subdomain | `False` |
| | `--permute`| Enable the permutation engine to guess hidden environments (dev-, staging-, etc.) | `False` |
| | `--permute-list` | Path to a custom wordlist for the permutation engine | `None` |
| `-B` | `--brute`| Enable active dictionary brute forcing | `False` |
| `-D` | `--dict-file` | Path to custom wordlist for brute forcing | `dictionaries/subdomain_dictionary.txt` |
| | `--http-check` | Enable active HTTP probing (Status Code & Title) | `False` |
| | `--port-list` | Comma-separated ports to probe (e.g., `80,443,8080`) | `80,443` |
| | `--check-takeover` | Enable Subdomain Takeover Vulnerability Engine | `False` |
| | `--harvest` | Extract historic URLs (Wayback) and scan JS files for leaked secrets/API keys | `False` |
| | `--vuln-scan` | Enable the native vulnerability engine (YAML templates) | `False` |
| | `--gui` | Launch the HaXder Web GUI Dashboard | `False` |
| | `--master-mode` | Start the Web GUI as a Master Node for distributed scanning | `False` |
| | `--worker-of` | URL of a Master Node to submit this scan's results to (e.g., `http://master:8000`) | `None` |
| | `--gui-port` | Port for the Web GUI Dashboard / Master Node | `8000` |
| `-O` | `--save` | Output file path to save results (e.g., `results.json`) | `None` |
| `-F` | `--stdout-format` | Stdout display format (`table`, `jsonl`) — independent of `-O`'s file format | `table` |
| `-Q` | `--quiet` / `--silent` | Suppress the banner and all status/progress output; print only raw scan data to stdout. `--silent` is an alias of `--quiet` for scripted/enterprise pipelines. | `False` |
| `-V` | `--debug` | Enable detailed debug logging for troubleshooting | `False` |
| | `--alert` | Send completion notification via configured webhooks (Slack/Discord) | `False` |
| | `--html-report` | Path to save an interactive HTML report (e.g., `report.html`) | `None` |

\* Required unless `--as-number`, `--ip-range`, or `--bounty-scope` is supplied instead.

### Silent / Enterprise Mode

For scripted pipelines, cron jobs, or piping into other tools, use `-Q`, `--quiet`, or `--silent` (all equivalent). This suppresses the startup banner, progress bars, and every status line, leaving stdout with nothing but the raw scan data — one resolved subdomain per line by default, or one JSON object per line with `-F jsonl`:

```bash
# Plain text, one subdomain per line — ideal for piping into another tool
python -m haxder.runner -T example.com --brute --http-check --silent

# JSON Lines output, still fully silent
python -m haxder.runner -T example.com --brute --http-check --silent -F jsonl
```

### Example Commands

**Everything on — bruteforce, probing, URL/secret extraction, takeover and vuln checks, HTML report:**
```bash
python -m haxder.runner -T example.com --brute --http-check --harvest --check-takeover --vuln-scan --html-report report.html
```

**Distributed run (one Master, one or more Workers):**
```bash
# Master host: serves the Web GUI and accepts Worker submissions
python -m haxder.runner --master-mode --gui-port 8000

# Worker host: scans and pushes results back to the Master
python -m haxder.runner -T example.com --worker-of http://master_ip:8000
```

**High-concurrency scan, results written to JSON:**
```bash
python -m haxder.runner -T example.com -C 1000 -O results.json
```

**Continuous monitoring with vuln checks and Slack/Discord alerts on completion:**
```bash
python -m haxder.runner -T example.com --monitor --vuln-scan --check-takeover --alert
```

---

## Configuration & API Keys

Copy `settings.yaml.example` to `settings.yaml` and drop in your API keys to unlock the premium sources. Any key that's missing or invalid is skipped silently — the rest of the scan keeps going.

Premium sources and notification channels supported out of the box:
- **SecurityTrails**, **Shodan**, **VirusTotal**, **ProjectDiscovery Chaos**
- **Slack** & **Discord** webhooks

---

<div align="center">
  <b>Developed by Hayder Rzaigui</b> <br>
  <i>Tooling built by a practitioner, for practitioners</i>
</div>
