# Recon Frameworks
```table-of-contents
```
## Tool Overview
| `Tool`          | `Language` | `Key Features`                         | `Focus`                                    |
| --------------- | ---------- | -------------------------------------- | ------------------------------------------ |
| **FinalRecon**      | Python     | Modular, Fast, CLI-based.              | Web Recon (Headers, SSL, Whois, Crawling). |
| **Recon-ng**        | Python     | Modular (Metasploit-like), DB support. | General OSINT (APIs, GeoIP, Contacts).     |
| **theHarvester**    | Python     | Scrapes search engines & Shodan.       | Emails, Subdomains, IPs.                   |
| **SpiderFoot**      | Python     | 100+ Data sources, Web GUI available.  | Automation, Asset Discovery.               |
| **OSINT Framework** | Web        | Collection of tools/links.             | Resource directory (not a scanner).        |
## FinalRecon
### Features
- **Header Info:** Server details, security headers.
- **SSL Info:** Certificate validity, issuer.
- **Whois:** Domain registration details.
- **Crawler:** Extracts links, images, `robots.txt`, `sitemap.xml`.
- **DNS/Subdomains:** Enumerates records and finds subdomains via APIs.
### Installation
```shell
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
```
### Usage Arguments
| **Option**         | **Argument** | **Description**                             |
| -------------- | -------- | --------------------------------------- |
| `-h`, `--help` |          | Show help message.                      |
| `--url`        | URL      | Target URL (Required).                  |
| `--headers`    |          | Get Header Information.                 |
| `--sslinfo`    |          | Get SSL Certificate Information.        |
| `--whois`      |          | Perform Whois Lookup.                   |
| `--crawl`      |          | Crawl Target (Extract links/resources). |
| `--dns`        |          | DNS Enumeration.                        |
| `--sub`        |          | Sub-Domain Enumeration.                 |
| `--dir`        |          | Directory Search.                       |
| `--wayback`    |          | Fetch Wayback Machine URLs.             |
| `--ps`         |          | Fast Port Scan.                         |
| `--full`       |          | Run ALL modules (Full Recon).           |
### Examples
```shell
# Basic Recon (Headers + Whois)
./finalrecon.py --headers --whois --url http://target.com

# Full Scan (Noisy)
./finalrecon.py --full --url http://target.com

# Subdomain & DNS only
./finalrecon.py --sub --dns --url http://target.com
```
## theHarvester
```shell
# Basic Search (Google, Bing, LinkedIn)
# -d: Domain | -l: Limit results | -b: Source
theHarvester -d target.com -l 500 -b google,bing,linkedin

# Search all sources
theHarvester -d target.com -l 500 -b all
```
## Recon-ng
```shell
# Start the console
recon-ng

# Inside the console:
workspaces create <PROJECT_NAME>
modules load hacker_target
options set SOURCE <DOMAIN>
run
show hosts
```