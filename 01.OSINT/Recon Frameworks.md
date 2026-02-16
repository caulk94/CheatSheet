# Automated Recon Frameworks
## 1. The "Swiss Army Knife" (All-in-One)
### FinalRecon
**Install:** `git clone https://github.com/thewhiteh4t/FinalRecon.git && cd FinalRecon && pip3 install -r requirements.txt` 
**Docs:** [https://github.com/thewhiteh4t/FinalRecon](https://github.com/thewhiteh4t/FinalRecon)
```shell
# Description: Modular web reconnaissance tool (Headers, SSL, Whois, Crawling, DNS).
# Syntax: python3 finalrecon.py --url <target> [flags]

# ⚠️ OPSEC: High Noise (Active Crawling & Scanning).
# Full Scan (Headers, SSL, Whois, DNS, Subdomains, Crawl)
python3 finalrecon.py --full --url https://target.com

# Low Noise (Headers, Whois, SSL only)
python3 finalrecon.py --headers --whois --sslinfo --url https://target.com
```
### SpiderFoot (CLI)
**Install:** `pip3 install spiderfoot` or `git clone https://github.com/smicallef/spiderfoot` 
**Docs:** [https://github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)
```shell
# Description: Automated OSINT collection from 100+ public data sources.
# Syntax: spiderfoot -s <target> -m <modules>
# ⚠️ OPSEC: Variable. Passive if using APIs/Search Engines; Active if using probing modules.

# Basic Scan (All modules, passive & active)
spiderfoot -s target.com -q

# List available modules
spiderfoot -m
```
## 2. Email & People Hunting
### theHarvester
**Install:** `sudo apt install theharvester` 
**Docs:** [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)
```shell
# Description: Scrapes search engines (Google, Bing), LinkedIn, and Shodan for emails, subdomains, and names.
# Syntax: theHarvester -d <domain> -l <limit> -b <source>
# ⚠️ OPSEC: Passive (Scrapes third-party sources).

# Targeted Search (Google, Bing, LinkedIn)
theHarvester -d target.com -l 500 -b google,bing,linkedin

# Search All Sources (Can be slow)
theHarvester -d target.com -l 500 -b all
```
## 3. Modular Frameworks
### Recon-ng
**Install:** `sudo apt install recon-ng` 
**Docs:** [https://github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng)
**Workflow:** Recon-ng uses a Metasploit-like interactive shell.
```shell
# 1. Start Framework
recon-ng

# 2. Create Workspace (Isolates data per target)
[recon-ng] > workspaces create Project_Target

# 3. Install/Load Modules (e.g., HackerTarget for subdomains)
[recon-ng] > marketplace install hackertarget
[recon-ng] > modules load recon/domains-hosts/hackertarget

# 4. Configure & Run
[recon-ng][hackertarget] > options set SOURCE target.com
[recon-ng][hackertarget] > run

# 5. View Results
[recon-ng][hackertarget] > show hosts
```