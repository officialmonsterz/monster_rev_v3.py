# MONSTER_REV v3 — Reverse IP Intelligence Engine

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Proprietary-red)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

Aggregates reverse DNS/IP data from **7 APIs**, performs port scanning, detects high-value "gold" targets, and generates comprehensive reports. Built for authorized penetration testers and security researchers.

## Features

- **7 API Aggregators** — Shodan, VirusTotal, SecurityTrails, IPdata, IP2Location, ViewDNS, WhoisXML
- **Port Scanning** — Identifies open ports with service fingerprinting (120+ gold ports)
- **Gold Detection Engine** — Scores targets based on open ports, API sources, threat data, and domain richness
- **Interactive Menu** — Step-by-step wizard for input, configuration, scanning, and reporting
- **CLI Mode** — Quick single-IP scans: `python monster_rev_v3.py --ip 8.8.8.8`
- **Real-Time Streaming** — Results appear as each API responds, no waiting for completion
- **Target Scoring** — Identifies high-value targets (FTP+SSH+MySQL+money ports = highest score)
- **Hydra Command Generation** — Auto-generates brute-force commands for found services
- **SQLite Cache** — Avoids redundant API calls (24-hour TTL)
- **Rate Limiting** — Per-API rate control to stay within free-tier limits
- **Windows Compatible** — Full support with SelectorEventLoop fix

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- API keys for at least 2-3 of the supported services (free tiers available)

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/monster-rev-v3.git
cd monster-rev-v3

# Install dependencies
pip install aiohttp

# Create config from template
python monster_rev_v3.py
# (This generates config.json — edit it with your API keys)

Configuration
Edit config.json with your API keys:



API	Free Tier	Get Key
Shodan	100 queries/month	https://account.shodan.io
VirusTotal	4 req/min, 500/day	https://virustotal.com/gui/my-apikey
SecurityTrails	50 queries/month	https://securitytrails.com/app/api
IPdata	1,500 requests/day	https://ipdata.co
IP2Location	500 queries/month	https://www.ip2location.com/web-service/ip2whois
ViewDNS	1,000 queries/day	https://viewdns.info/api
WhoisXML	1,000 queries/month	https://whoisxmlapi.com/reverse-ip-api
Usage
Interactive Mode (Recommended)
bash



python monster_rev_v3.py
Follow the step-by-step wizard:

Choose input method (single IP, multiple IPs, file, or CIDR range)
Configure port scan depth
Toggle gold detection settings
Review and launch scan
Generate reports
CLI Mode
bash



# Quick scan a single IP
python monster_rev_v3.py --ip 8.8.8.8

# Scan with custom config file
python monster_rev_v3.py --ip 1.1.1.1 --config my_config.json
Example Output



============================================================
  MONSTER_REV v3 v3.0.0
  Reverse IP Intelligence Engine
============================================================

--- Target 1/10 ---
  Scanning: 69.13.205.28
============================================================
  [+] shodan: responded (1 results)
  [+] virustotal: responded (0 results)
  [+] ip2location: responded (1 results)
  [+] viewdns: responded (182 results)
  [+] whoisxml: responded (300 results)
  [*] Open ports (12):
       21/ftp, 22/ssh, 53/dns, 80/http, 110/pop3, ...
  [GOLD] Score: 37
         Port 21 (vulnerable_services) w=3
         Port 22 (secret_storage) w=4
         Port 53 (database) w=3
         Multi-source (5 sources) w=2
  [*] Total unique domains: 15
Reports
Generated in the results/ directory:

results.json — Full structured data for all targets
gold_report.txt — High-value targets ranked by score
port_report.txt — Open ports with banners per target
hydra_commands.txt — Ready-to-use brute-force command templates
Gold Detection Scoring
The engine scores targets based on:

Open ports — Weighted by category (database=3, marketplace=2, secret_storage=4, blockchain=5, vulnerable_services=3)
Multi-source confirmation — +2 when 3+ APIs return data
Domain richness — +1 for 5+ domains, +2 for 10+
Vulnerabilities — +2 per CVE (from Shodan)
Threat score — +3 for high-threat IPs (from IPdata)
Score 10+ = high-value target worth deeper investigation.

License
Proprietary — For authorized penetration testing and security research only. Unauthorized use is prohibited.

Disclaimer
This tool is intended for authorized security testing only. Users must have explicit permission to scan target systems. The authors are not responsible for misuse.

Contributing
Pull requests welcome. For major changes, open an issue first to discuss.
