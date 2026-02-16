# Port 80, 443 - HTTP/HTTPS
**Default Ports:** 80 (HTTP), 443 (HTTPS), 8080 (Proxy/Tomcat), 8443 (HTTPS Alt) 
**Key Insight:** The most common entry point. Enumeration must be layered: Fingerprint -> WAF Check -> Directory Fuzzing -> Vulnerability Scanning.
## 1. Basic Identification & Fingerprinting
**Goal:** Identify the Web Server (Apache/IIS/Nginx), Technology Stack (PHP/ASP), and CMS (WordPress/Joomla) _before_ launching heavy attacks.
### Banner Grabbing (Curl)
**Description:** Inspect HTTP headers for software versions and cookies. **Syntax:** `curl -I -v -k -L <URL>`
- `-I`: Head request (Headers only). 
- `-v`: Verbose (Show handshake and raw request/response).
- `-k`: Ignore SSL certificate errors (Critical for internal/self-signed certs).
- `-L`: Follow redirects.

```shell
# ⚠️ OPSEC: Low Noise. Looks like a standard browser request.
curl -I -v -k -L http://10.129.2.15
```
### WhatWeb (Tech Stack)
**Install:** `sudo apt install whatweb` 
**Description:** Identifies CMS, Web Server, Frameworks, Analytics, and WAF presence. 
**Syntax:** `whatweb -a 3 <TARGET>`

```shell
# -a 3: Aggressive scan (Requests valid pages to trigger 404s/cookies)
whatweb -a 3 https://10.129.2.15
```
## 2. WAF Detection
**Goal:** Determine if a Web Application Firewall (Cloudflare, AWS WAF, ModSecurity) is protecting the site _before_ brute-forcing.
### Wafw00f
**Install:** `sudo apt install wafw00f` 
**Description:** Sends specific payloads to trigger WAF responses and fingerprint them. 
**Syntax:** `wafw00f -a <TARGET>`

```shell
# -a: Find all matching WAFs (don't stop at the first one)
# ⚠️ OPSEC: Moderate Noise. Sends attack patterns.
wafw00f -a https://10.129.2.15
```
### Nmap WAF Script
```shell
nmap -p 80,443 --script http-waf-detect --script-args="http-waf-detect.aggro" 10.129.2.15
```
## 3. Directory & File Enumeration (Fuzzing)
**Goal:** Find hidden resources (admin panels, backups, config files) not linked in the application.
### Gobuster (Directory Mode)
**Install:** `sudo apt install gobuster` 
**Description:** Fast, standard directory brute-forcer. No recursion by default. 
**Syntax:** `gobuster dir -u <URL> -w <Wordlist> -x <Extensions>`

- `-k`: Skip SSL verification.
- `-t`: Threads (Default 10). Increase for speed, decrease for stealth.
- `-x`: Append extensions (e.g., searches for `admin`, `admin.php`, `admin.txt`).

```shell
# ⚠️ OPSEC: High Noise. Generates 404 logs.
gobuster dir -u https://10.129.2.15 -k -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x php,txt,html,sh,bak,zip
```
### Feroxbuster (Recursive & Smart)
**Install:** `sudo apt install feroxbuster` 
**Description:** Modern Rust-based tool. 
**Recursive** (scans subdirectories automatically) and filters 404s smartly. 
**Syntax:** `feroxbuster -u <URL> -w <Wordlist>`

```shell
# -n: No recursion (if you want to be faster/quieter)
# -k: Insecure SSL
feroxbuster -u https://10.129.2.15 -k -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
```
## 4. Vulnerability Scanning
**Goal:** Automated detection of CVEs and misconfigurations.
### Nuclei (Modern Standard)
**Install:** `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` 
**Description:** Template-based scanner. Extremely fast and community-driven. 
**Syntax:** `nuclei -u <URL> -t <Template_Dir>`

```shell
# Basic Scan (Checks for default credentials, exposed panels, tokens)
nuclei -u https://10.129.2.15

# Targeted CVE Scan
# Checks specifically for Critical/High CVEs
nuclei -u https://10.129.2.15 -t cves/ -s critical,high
```
### Nikto (Legacy / Config)
**Install:** `sudo apt install nikto` 
**Description:** Great for finding outdated server versions, default files, and missing headers. 
**Syntax:** `nikto -h <URL>`

```shell
# Tuning 'b' (Software ID) saves time by skipping general exploits.
# ⚠️ OPSEC: Very High Noise. Easily flagged by IDS.
nikto -h https://10.129.2.15 -Tuning b
```
## 5. Crawling / Spidering
**Goal:** Map the entire application structure by following links (JavaScript, modify params).
### Gospider
**Install:** `go install github.com/jaeles-project/gospider@latest` 
**Description:** Fast Golang spider. Extracts URLs from JS files and sitemaps. 
**Syntax:** `gospider -s <URL> -o <Output_Dir>`

```shell
# -c: Concurrent requests | -d: Depth
gospider -s "https://10.129.2.15" -o output_crawl -c 10 -d 2
```
## 6. Well-Known URIs (RFC Standards)
**Goal:** Check these standard paths manually or via curl. They often contain contact info, policy details, or asset links.

| **URI Suffix**                          | **Description**                                                                   | **Reference** |
| ----------------------------------- | ----------------------------------------------------------------------------- | --------- |
| `/robots.txt`                       | Directives for crawlers. Often reveals sensitive paths (`/admin`, `/backup`). | Standard  |
| `/sitemap.xml`                      | Map of all intended public pages.                                             | Standard  |
| `/.well-known/security.txt`         | Security contact info (emails, GPG keys).                                     | RFC 9116  |
| `/.well-known/openid-configuration` | OAuth 2.0 / OpenID Connect config (Endpoints, Scopes).                        | OpenID    |
| `/.well-known/assetlinks.json`      | Android App Links verification.                                               | Google    |
| `/.well-known/mta-sts.txt`          | Mail Transfer Agent Strict Transport Security policy.                         | RFC 8461  |
| `/.git/`                            | Exposed Git repository (Critical Vulnerability).                              |           |