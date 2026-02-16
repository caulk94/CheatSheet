# Google Hacking (Dorks)
## 1. Operator Quick Reference
**Description:** Essential operators for constructing custom queries. 
**Syntax:** `operator:value`
```shell
site:target.com        # Limit to domain
filetype:pdf           # specific extension (or ext:pdf)
inurl:admin            # "admin" is in the URL
intitle:"index of"     # "index of" is in the page title
intext:"password"      # "password" is in the body text
cache:target.com       # View Google's cached version
-www                   # Exclude results (e.g., exclude main site)
```
## 2. High-Value Dorks (Manual)
**⚠️ OPSEC:** Passive. Interaction is with Google, not the target. However, excessive rapid queries will trigger Google CAPTCHAs.
### Exposed Directories & Infrastructure
**Description:** Findings open directory listings (Directory Traversal) and cloud buckets.
```shell
# Directory Listings (Index of /)
site:target.com intitle:"index of"
site:target.com intitle:"index of" "parent directory"

# Cloud Storage (S3 Buckets)
site:s3.amazonaws.com "target"
site:blob.core.windows.net "target"
```
### Sensitive Configuration & Environment Files
**Description:** Hunting for leaked config files, logs, and environment variables.
```shell
# Configuration Files (extensions)
site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini

# Environment Files (Credentials)
site:target.com filetype:env
site:target.com filetype:env "DB_PASSWORD"

# Log Files
site:target.com ext:log
site:target.com inurl:log
```
### Database & Backup Files
**Description:** Locating accidental database dumps or SQL files.
```shell
site:target.com ext:sql | ext:dbf | ext:mdb
site:target.com "dump" "sql"
site:target.com "backup"
```
### Admin Portals & Login Interfaces
**Description:** Identifying administrative entry points.
```shell
site:target.com inurl:admin
site:target.com inurl:login
site:target.com intitle:"login"
site:target.com inurl:portal
site:target.com inurl:vpn
```
## 3. Automated Dorking Tools
### Pagodo (Passive Google Dork)
**Install:** `git clone https://github.com/opsdisk/pagodo.git && pip3 install -r requirements.txt` 
**Docs:** [https://github.com/opsdisk/pagodo](https://github.com/opsdisk/pagodo)
```shell
# Description: Automates searching using the Google Hacking Database (GHDB).
# Syntax: python3 pagodo.py -d <domain> -g <dork_file>
# ⚠️ OPSEC: High Noise (to Google). Will trigger CAPTCHA/Bans quickly. Use proxies.
python3 pagodo.py -d target.com -g dorks.txt -s -e 15.0 -l 50
```
### Katana (Crawler & Dorking)
**Install:** `go install github.com/projectdiscovery/katana/cmd/katana@latest` 
**Docs:** [https://github.com/projectdiscovery/katana](https://github.com/projectdiscovery/katana)
```shell
# Description: Next-gen crawling and spidering framework. Can find hidden endpoints.
# Syntax: katana -u <url> -d <depth>
# ⚠️ OPSEC: Active/High Noise. Hits the target directly.
katana -u https://target.com -d 5 -jc -kf -o katana_output.txt
```
### Go-Dork (CLI Dorker)
**Install:** `go install github.com/dwisiswant0/go-dork@latest` 
**Docs:** [https://github.com/dwisiswant0/go-dork](https://github.com/dwisiswant0/go-dork)
```shell
# Description: Simple CLI tool to query Google without a browser.
# Syntax: go-dork -q <query>
# ⚠️ OPSEC: Passive (hits Google).
go-dork -q "site:target.com ext:php"
```