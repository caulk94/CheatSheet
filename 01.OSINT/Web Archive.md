# Web History & Archives
## 1. Online Archives (Manual)
**Goal:** Find deleted pages, old versions of files, or bypass current WAFs/Paywalls.

| **Service**             | **URL**                       | **Description**                                              |
| ----------------------- | ----------------------------- | ------------------------------------------------------------ |
| Wayback Machine     | `https://web.archive.org`     | The largest archive. Browse site changes over time.          |
| Archive.today       | `https://archive.ph`          | Often captures snapshots that bypass modern blocks/paywalls. |
| Library of Congress | `http://loc.gov/webarchiving` | Good for government/official domain history.                 |
## 2. Automated Archiving Tools (CLI)
### Waybackurls
**Install:** `go install github.com/tomnomnom/waybackurls@latest` 
**Docs:** [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls)
```shell
# Description: Fetch all URLs that the Wayback Machine knows about for a domain.
# Syntax: echo <domain> | waybackurls
# ⚠️ OPSEC: Passive (Queries Archive.org, not the target).

# Basic Usage
echo "target.com" | waybackurls > urls_wayback.txt

# Filter for Specific Extensions (Config, Backup, Logs)
echo "target.com" | waybackurls | grep -E "\.json|\.txt|\.php|\.bak|\.old|\.zip"
```
### GAU (GetAllUrls)
**Install:** `go install github.com/lc/gau/v2/cmd/gau@latest` 
**Docs:** [https://github.com/lc/gau](https://github.com/lc/gau)
```shell
# Description: Fetches URLs from AlienVault's OTX, the Wayback Machine, and Common Crawl.
# Syntax: gau <domain>
# ⚠️ OPSEC: Passive.

# Get All URLs
gau target.com > urls_gau.txt

# Find Parameters (Potential XSS/SQLi targets)
gau target.com | grep "=" | sort -u > urls_params.txt
```
### Waybackrobots
**Install:** `go install github.com/mhmdiaa/waybackrobots@latest` 
**Docs:** [https://github.com/mhmdiaa/waybackrobots](https://github.com/mhmdiaa/waybackrobots)
```shell
# Description: Extracts 'Disallow' paths from old robots.txt files to find hidden directories.
# Syntax: waybackrobots <domain>
# ⚠️ OPSEC: Passive.
waybackrobots target.com
```
## 3. Historical Data Analysis (One-Liners)
### API Key Hunting (JS Files)
**Description:** Download old JavaScript files found in archives and grep for secrets.
```shell
# ⚠️ OPSEC: Active (curl hits the archived URL, but sometimes redirects to live site if archive is missing).
echo "target.com" | waybackurls | grep "\.js$" | sort -u | xargs -n1 -I{} curl -s "{}" | grep -iE "key|token|secret|password|auth"
```
### Parameter Discovery (Fuzzing Prep)
**Description:** Extract unique parameter names for fuzzing (e.g., `?id=`, `?user=`).
```shell
gau target.com | grep "?" | cut -d "?" -f 2 | cut -d "=" -f 1 | sort -u > param_names.txt
```
### Backup & Sensitive File Discovery
**Description:** Quickly isolate interesting file extensions from the noise.
```shell
echo "target.com" | waybackurls | grep -iE "\.bak|\.old|\.zip|\.sql|\.db|\.env"
```