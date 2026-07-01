import json
import os
import datetime

class ReportGenerator:
    """
    Generates premium, interactive HTML reports summarizing HaXder scan findings.
    Features:
      - Stat cards for key performance metrics.
      - DNS Email Security (SPF & DMARC) Compliance cards.
      - HTTP Security Headers compliance inspection.
      - Chart.js integration for visual analytics.
      - Interactive tables with searching, pagination, and filtering.
      - Dark-mode responsive design.
    """
    def __init__(self, target_domain: str, resolved_data: dict, probe_data: dict, takeover_data: dict, secret_findings: list, vuln_findings: list, dns_audit_results: dict = None):
        self.target_domain = target_domain
        self.resolved_data = resolved_data
        self.probe_data = probe_data
        self.takeover_data = takeover_data
        self.secret_findings = secret_findings
        self.vuln_findings = vuln_findings
        self.dns_audit_results = dns_audit_results or {}

    def generate_html(self, output_path: str):
        # Calculate Stats
        total_subdomains = len(self.resolved_data)
        resolved_subs = sum(1 for s in self.resolved_data.values() if s.get("ips"))
        unresolved_subs = total_subdomains - resolved_subs
        takeover_count = len(self.takeover_data)
        secret_count = len(self.secret_findings)
        vuln_count = len(self.vuln_findings)

        # Port/status distribution
        port_counts = {}
        status_counts = {}
        for sub, data in self.probe_data.items():
            status = data.get("status", "ERR")
            status_counts[status] = status_counts.get(status, 0) + 1
            port = data.get("port")
            if port:
                port_counts[str(port)] = port_counts.get(str(port), 0) + 1

        # Vuln severity distribution
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vuln_findings:
            sev = v.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["info"] += 1

        # Prepare JSON string safe data for frontend Charts
        dns_chart_data = json.dumps([resolved_subs, unresolved_subs])
        port_labels = json.dumps(list(port_counts.keys()))
        port_values = json.dumps(list(port_counts.values()))
        vuln_labels = json.dumps([k.capitalize() for k in severity_counts.keys()])
        vuln_values = json.dumps(list(severity_counts.values()))

        # Subdomains Table Data
        subdomains_list = []
        for sub, res_dict in self.resolved_data.items():
            ips = res_dict.get("ips", [])
            cnames = res_dict.get("cnames", [])
            probe = self.probe_data.get(sub, {})
            subdomains_list.append({
                "subdomain": sub,
                "ips": ", ".join(ips) if ips else "N/A",
                "cnames": ", ".join(cnames) if cnames else "N/A",
                "status": probe.get("status", "N/A"),
                "title": probe.get("title", "N/A"),
                "takeover": self.takeover_data.get(sub, ""),
                "missing_headers": probe.get("missing_headers", [])
            })
        subdomains_json = json.dumps(subdomains_list)

        # Extract SPF / DMARC
        spf_data = self.dns_audit_results.get("spf", {"record": "None", "status": "Vulnerable", "finding": "Audit not performed or missing record."})
        dmarc_data = self.dns_audit_results.get("dmarc", {"record": "None", "status": "Vulnerable", "finding": "Audit not performed or missing record."})

        spf_record = spf_data.get("record", "None")
        spf_status = spf_data.get("status", "Vulnerable")
        spf_finding = spf_data.get("finding", "")

        dmarc_record = dmarc_data.get("record", "None")
        dmarc_status = dmarc_data.get("status", "Vulnerable")
        dmarc_finding = dmarc_data.get("finding", "")

        # Determine overall DNS compliance color class
        spf_badge_class = "badge-green" if spf_status == "Safe" else "badge-yellow" if spf_status == "Warning" else "badge-red"
        dmarc_badge_class = "badge-green" if dmarc_status == "Safe" else "badge-yellow" if dmarc_status == "Warning" else "badge-red"

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HaXder Scan Report - {self.target_domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --border-color: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-purple: #8b5cf6;
            --shadow-glow: rgba(59, 130, 246, 0.15);
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: 'Outfit', sans-serif;
            margin: 0;
            padding: 0;
        }}

        .navbar {{
            background-color: var(--card-bg);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }}

        .navbar .logo {{
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .navbar .logo span {{
            color: var(--accent-blue);
        }}

        .navbar .timestamp {{
            font-size: 14px;
            color: var(--text-secondary);
            background-color: rgba(255, 255, 255, 0.05);
            padding: 6px 12px;
            border-radius: 20px;
            border: 1px solid var(--border-color);
        }}

        .container {{
            max-width: 1400px;
            margin: 40px auto;
            padding: 0 20px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: var(--accent-blue);
            box-shadow: 0 10px 25px var(--shadow-glow);
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent-blue);
        }}

        .stat-card.resolved::before {{ background: var(--accent-green); }}
        .stat-card.vulns::before {{ background: var(--accent-red); }}
        .stat-card.takeovers::before {{ background: var(--accent-yellow); }}
        .stat-card.secrets::before {{ background: var(--accent-purple); }}

        .stat-card h3 {{
            margin: 0;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
        }}

        .stat-card .value {{
            font-size: 36px;
            font-weight: 700;
            margin-top: 10px;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }}

        .chart-box {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            height: 350px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}

        .chart-box h4 {{
            margin: 0 0 15px 0;
            align-self: flex-start;
            font-size: 16px;
            color: var(--text-primary);
        }}

        .chart-container {{
            width: 100%;
            height: 260px;
            position: relative;
        }}

        .section-header {{
            font-size: 22px;
            font-weight: 600;
            margin: 40px 0 20px 0;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }}

        .section-header span {{
            background-color: rgba(59, 130, 246, 0.1);
            color: var(--accent-blue);
            font-size: 14px;
            padding: 4px 10px;
            border-radius: 20px;
        }}

        /* Compliance Card Grid */
        .compliance-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .compliance-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .compliance-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            font-size: 16px;
        }}

        .compliance-code {{
            background-color: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px;
            font-family: monospace;
            font-size: 13px;
            color: var(--text-secondary);
            word-break: break-all;
        }}

        .compliance-finding {{
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.4;
        }}

        .table-controls {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-bottom: none;
            padding: 20px;
            border-radius: 12px 12px 0 0;
            display: flex;
            justify-content: space-between;
            gap: 20px;
            flex-wrap: wrap;
        }}

        .search-box {{
            flex-grow: 1;
            max-width: 400px;
            position: relative;
        }}

        .search-box input {{
            width: 100%;
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 10px 15px;
            color: var(--text-primary);
            font-family: inherit;
            outline: none;
            box-sizing: border-box;
            transition: border-color 0.3s;
        }}

        .search-box input:focus {{
            border-color: var(--accent-blue);
        }}

        .filter-tabs {{
            display: flex;
            gap: 10px;
        }}

        .filter-btn {{
            background-color: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-family: inherit;
            transition: all 0.3s;
        }}

        .filter-btn:hover, .filter-btn.active {{
            background-color: var(--accent-blue);
            border-color: var(--accent-blue);
            color: #fff;
        }}

        .table-responsive {{
            width: 100%;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 0 0 12px 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            background-color: var(--card-bg);
        }}

        th {{
            background-color: rgba(255, 255, 255, 0.02);
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 14px;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
        }}

        td {{
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tr:hover td {{
            background-color: rgba(255, 255, 255, 0.01);
        }}

        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin: 2px;
        }}

        .badge-green {{ background-color: rgba(16, 185, 129, 0.1); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.2); }}
        .badge-red {{ background-color: rgba(239, 68, 68, 0.1); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.2); }}
        .badge-yellow {{ background-color: rgba(245, 158, 11, 0.1); color: var(--accent-yellow); border: 1px solid rgba(245, 158, 11, 0.2); }}
        .badge-purple {{ background-color: rgba(139, 92, 246, 0.1); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.2); }}
        .badge-gray {{ background-color: rgba(156, 163, 175, 0.1); color: var(--text-secondary); border: 1px solid rgba(156, 163, 175, 0.2); }}

        .severity-critical {{ background-color: #ef4444; color: white; }}
        .severity-high {{ background-color: #f97316; color: white; }}
        .severity-medium {{ background-color: #eab308; color: black; }}
        .severity-low {{ background-color: #3b82f6; color: white; }}
        .severity-info {{ background-color: #6b7280; color: white; }}

        .pagination {{
            display: flex;
            justify-content: flex-end;
            align-items: center;
            padding: 15px 20px;
            background-color: var(--card-bg);
            border-top: 1px solid var(--border-color);
            gap: 10px;
        }}

        .pagination-btn {{
            background-color: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
        }}

        .pagination-btn:hover:not(:disabled) {{
            background-color: var(--accent-blue);
            border-color: var(--accent-blue);
        }}

        .pagination-btn:disabled {{
            opacity: 0.4;
            cursor: not-allowed;
        }}

        .empty-state {{
            padding: 40px;
            text-align: center;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>

    <nav class="navbar">
        <div class="logo">HaXder <span>Enterprise Report</span></div>
        <div class="timestamp">Target: <strong>{self.target_domain}</strong> &nbsp;|&nbsp; Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
    </nav>

    <div class="container">
        
        <!-- Stats cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Targets</h3>
                <div class="value">{total_subdomains}</div>
            </div>
            <div class="stat-card resolved">
                <h3>Resolved DNS</h3>
                <div class="value">{resolved_subs}</div>
            </div>
            <div class="stat-card vulns">
                <h3>Vulnerabilities</h3>
                <div class="value">{vuln_count}</div>
            </div>
            <div class="stat-card takeovers">
                <h3>Subdomain Takeovers</h3>
                <div class="value">{takeover_count}</div>
            </div>
            <div class="stat-card secrets">
                <h3>Exposed Secrets</h3>
                <div class="value">{secret_count}</div>
            </div>
        </div>

        <!-- Analytical Charts -->
        <div class="charts-grid">
            <div class="chart-box">
                <h4>DNS Resolution Ratio</h4>
                <div class="chart-container">
                    <canvas id="dnsChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <h4>Vulnerability Breakdown</h4>
                <div class="chart-container">
                    <canvas id="vulnChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <h4>Open Port Distribution</h4>
                <div class="chart-container">
                    <canvas id="portChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Compliance Section (DNS Email Security SPF/DMARC) -->
        <div class="section-header">
            DNS Email Security Auditing (Anti-Spoofing Status)
        </div>
        <div class="compliance-grid">
            <div class="compliance-card">
                <div class="compliance-card-header">
                    <span>SPF (Sender Policy Framework)</span>
                    <span class="badge {spf_badge_class}">{spf_status}</span>
                </div>
                <div class="compliance-code">{spf_record}</div>
                <div class="compliance-finding">{spf_finding}</div>
            </div>
            <div class="compliance-card">
                <div class="compliance-card-header">
                    <span>DMARC (Domain-based Message Authentication)</span>
                    <span class="badge {dmarc_badge_class}">{dmarc_status}</span>
                </div>
                <div class="compliance-code">{dmarc_record}</div>
                <div class="compliance-finding">{dmarc_finding}</div>
            </div>
        </div>

        <!-- Findings: Vulnerabilities (If present) -->
        <div class="section-header">
            Discovered Vulnerabilities <span>{vuln_count}</span>
        </div>
        
        <div class="table-responsive" style="margin-bottom: 40px;">
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%">Template ID</th>
                        <th style="width: 35%">Vulnerability Name</th>
                        <th style="width: 15%">Severity</th>
                        <th style="width: 35%">Matched Endpoint</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''<tr>
                        <td><code>{v.get("id")}</code></td>
                        <td>{v.get("name")}</td>
                        <td><span class="badge severity-{v.get("severity", "info").lower()}">{v.get("severity", "info").upper()}</span></td>
                        <td><a href="{v.get("matched_at")}" target="_blank" style="color:var(--accent-blue); text-decoration:none;">{v.get("matched_at")}</a></td>
                    </tr>''' for v in self.vuln_findings) if self.vuln_findings else '<tr><td colspan="4" class="empty-state">No vulnerabilities detected.</td></tr>'}
                </tbody>
            </table>
        </div>

        <!-- Findings: Exposed Secrets (If present) -->
        <div class="section-header">
            Exposed API Keys & Secrets <span>{secret_count}</span>
        </div>
        
        <div class="table-responsive" style="margin-bottom: 40px;">
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%">File URL</th>
                        <th style="width: 25%">Secret Type</th>
                        <th style="width: 50%">Extracted Token (Redacted)</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''<tr>
                        <td><a href="{s.get("url")}" target="_blank" style="color:var(--accent-blue); text-decoration:none; word-break:break-all;">{s.get("url")}</a></td>
                        <td><span class="badge badge-purple">{s.get("type")}</span></td>
                        <td><code>{s.get("secret")}</code></td>
                    </tr>''' for s in self.secret_findings) if self.secret_findings else '<tr><td colspan="3" class="empty-state">No exposed credentials detected.</td></tr>'}
                </tbody>
            </table>
        </div>

        <!-- Subdomain Infrastructure Inventory -->
        <div class="section-header">
            Subdomain Infrastructure Inventory <span>{total_subdomains}</span>
        </div>

        <div class="table-controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search by subdomain, IP, or Title..." oninput="handleSearch()">
            </div>
            <div class="filter-tabs">
                <button class="filter-btn active" id="btn-all" onclick="filterType('all')">All</button>
                <button class="filter-btn" id="btn-resolved" onclick="filterType('resolved')">Resolved</button>
                <button class="filter-btn" id="btn-unresolved" onclick="filterType('unresolved')">Unresolved</button>
                <button class="filter-btn" id="btn-takeover" onclick="filterType('takeover')">Takeover Risks</button>
            </div>
        </div>

        <div class="table-responsive">
            <table id="subdomainsTable">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Resolved IPs</th>
                        <th>CNAMEs</th>
                        <th>Status</th>
                        <th>HTML Title</th>
                        <th>Missing Security Headers</th>
                        <th>Takeover Status</th>
                    </tr>
                </thead>
                <tbody id="tableBody">
                    <!-- Dynamic rendering via JS for searching & pagination -->
                </tbody>
            </table>
            
            <div class="pagination">
                <button class="pagination-btn" id="prevBtn" onclick="prevPage()">Previous</button>
                <span id="pageIndicator" style="font-size: 14px; color: var(--text-secondary);">Page 1 of 1</span>
                <button class="pagination-btn" id="nextBtn" onclick="nextPage()">Next</button>
            </div>
        </div>

    </div>

    <script>
        // Set up Chart.js
        const dnsCtx = document.getElementById('dnsChart').getContext('2d');
        new Chart(dnsCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Resolved', 'Unresolved'],
                datasets: [{{
                    data: {dns_chart_data},
                    backgroundColor: ['#10b981', '#374151'],
                    borderColor: '#111827',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#f3f4f6' }} }}
                }}
            }}
        }});

        const vulnCtx = document.getElementById('vulnChart').getContext('2d');
        new Chart(vulnCtx, {{
            type: 'bar',
            data: {{
                labels: {vuln_labels},
                datasets: [{{
                    label: 'Vulnerabilities by Severity',
                    data: {vuln_values},
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280'],
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ grid: {{ color: '#1f2937' }}, ticks: {{ color: '#f3f4f6', stepSize: 1 }} }},
                    x: {{ grid: {{ display: false }}, ticks: {{ color: '#f3f4f6' }} }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});

        const portCtx = document.getElementById('portChart').getContext('2d');
        new Chart(portCtx, {{
            type: 'bar',
            data: {{
                labels: {port_labels},
                datasets: [{{
                    label: 'Open Subdomains per Port',
                    data: {port_values},
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ grid: {{ color: '#1f2937' }}, ticks: {{ color: '#f3f4f6', stepSize: 1 }} }},
                    x: {{ grid: {{ display: false }}, ticks: {{ color: '#f3f4f6' }} }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});

        // Data inventory & interactive pagination/filtering
        const rawData = {subdomains_json};
        let filteredData = [...rawData];
        
        let currentPage = 1;
        const itemsPerPage = 20;
        let currentFilter = 'all';
        let searchQuery = '';

        function renderTable() {{
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';
            
            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = Math.min(startIndex + itemsPerPage, filteredData.length);
            const pageData = filteredData.slice(startIndex, endIndex);

            if (pageData.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No matching assets found.</td></tr>';
                document.getElementById('pageIndicator').innerText = 'Page 0 of 0';
                document.getElementById('prevBtn').disabled = true;
                document.getElementById('nextBtn').disabled = true;
                return;
            }}

            pageData.forEach(item => {{
                let statusBadge = `<span class="badge badge-gray">${{item.status}}</span>`;
                if (item.status === '200') statusBadge = `<span class="badge badge-green">${{item.status}}</span>`;
                else if (item.status !== 'ERR' && item.status !== 'N/A') statusBadge = `<span class="badge badge-yellow">${{item.status}}</span>`;
                
                let takeoverBadge = '<span class="badge badge-gray">Safe</span>';
                if (item.takeover) {{
                    takeoverBadge = `<span class="badge badge-red">VULN: ${{item.takeover}}</span>`;
                }}

                // Format missing security headers as mini badges
                let headersHTML = '';
                if (item.status === 'ERR' || item.status === 'N/A') {{
                    headersHTML = '<span style="color:var(--text-secondary)">-</span>';
                }} else if (!item.missing_headers || item.missing_headers.length === 0) {{
                    headersHTML = '<span class="badge badge-green">Secure</span>';
                }} else {{
                    item.missing_headers.forEach(h => {{
                        let shortName = h.replace("Content-Security-Policy", "CSP")
                                         .replace("Strict-Transport-Security", "HSTS")
                                         .replace("X-Frame-Options", "XFO")
                                         .replace("X-Content-Type-Options", "XCTO");
                        headersHTML += `<span class="badge badge-yellow" title="Missing: ${{h}}">${{shortName}}</span> `;
                    }});
                }}

                const row = `<tr>
                    <td style="font-weight:600; color:var(--accent-blue);">${{item.subdomain}}</td>
                    <td>${{item.ips}}</td>
                    <td>${{item.cnames}}</td>
                    <td>${{statusBadge}}</td>
                    <td>${{item.title}}</td>
                    <td>${{headersHTML}}</td>
                    <td>${{takeoverBadge}}</td>
                </tr>`;
                tbody.innerHTML += row;
            }});

            const totalPages = Math.ceil(filteredData.length / itemsPerPage);
            document.getElementById('pageIndicator').innerText = `Page ${{currentPage}} of ${{totalPages}}`;
            document.getElementById('prevBtn').disabled = currentPage === 1;
            document.getElementById('nextBtn').disabled = currentPage === totalPages;
        }}

        function handleSearch() {{
            searchQuery = document.getElementById('searchInput').value.toLowerCase();
            applyFilters();
        }}

        function filterType(type) {{
            currentFilter = type;
            
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(`btn-${{type}}`).classList.add('active');
            
            applyFilters();
        }}

        function applyFilters() {{
            filteredData = rawData.filter(item => {{
                // Text search match
                const matchesSearch = item.subdomain.toLowerCase().includes(searchQuery) ||
                                      item.ips.toLowerCase().includes(searchQuery) ||
                                      item.title.toLowerCase().includes(searchQuery);
                                      
                // Tab filter match
                let matchesFilter = true;
                if (currentFilter === 'resolved') {{
                    matchesFilter = item.ips !== 'N/A';
                }} else if (currentFilter === 'unresolved') {{
                    matchesFilter = item.ips === 'N/A';
                }} else if (currentFilter === 'takeover') {{
                    matchesFilter = !!item.takeover;
                }}

                return matchesSearch && matchesFilter;
            }});

            currentPage = 1;
            renderTable();
        }}

        function prevPage() {{
            if (currentPage > 1) {{
                currentPage--;
                renderTable();
            }}
        }}

        function nextPage() {{
            const totalPages = Math.ceil(filteredData.length / itemsPerPage);
            if (currentPage < totalPages) {{
                currentPage++;
                renderTable();
            }}
        }}

        // Initial render
        renderTable();
    </script>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
