# HTTP - HTTPS
```table-of-contents
```
## Basic Identification & Headers
```shell
# Banner Grabbing (Curl)
# -I: Headers only | -v: Verbose (see handshake) | -k: Ignore SSL errors
curl -I -v -k http://<TARGET>

# WhatWeb (Technology Identification)
# Identifies CMS, Web Server, Frameworks, WAF presence
whatweb -a 3 <TARGET>
```
## WAF Detection
```shell
# Wafw00f
# -a: Find all matching WAFs
wafw00f -a <TARGET>

# Nmap WAF Script
nmap -p 80,443 --script http-waf-detect <IP>
```
## Directory & File Enumeration (Fuzzing)
```shell
# Gobuster (Directory Mode)
# -u: URL | -w: Wordlist | -x: Extensions to look for
gobuster dir -u http://<TARGET> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x php,txt,html,sh

# Feroxbuster (Recursive & Fast)
# Automatically handles recursion and 404 filtering
feroxbuster -u http://<TARGET> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
```
## Vulnerability Scanning
### Nikto (Legacy)
```shell
# Basic Scan
nikto -h <TARGET>

# Tuning (Save time)
# b: Software Identification
nikto -h <TARGET> -Tuning b
```
### Nuclei (Modern Standard)
```shell
# Scan with default templates
nuclei -u http://<TARGET>

# Scan for specific tech (e.g., CVEs)
nuclei -u http://<TARGET> -t cves/
```
## Crawling / Spidering
### ReconSpider (Python)
```shell
# Basic Usage
python3 ReconSpider.py http://<TARGET>
```
### Gospider / Hakrawler (Golang alternatives)
```shell
# Fast crawling
gospider -s "http://<TARGET>" -o output -c 10 -d 1
```
## Well-Known URIs
| **URI Suffix**                     | **Description**                                                           | **Status**      | **Reference**                  |
| ------------------------------ | --------------------------------------------------------------------- | ----------- | -------------------------- |
| `security.txt`                 | Contact info for security researchers to report vulnerabilities.      | Permanent   | RFC9116                    |
| `/.well-known/change-password` | Standard URL to redirect users to a password change page.             | Provisional | W3C                        |
| `openid-configuration`         | Configuration details for OpenID Connect (OAuth 2.0).                 | Permanent   | OpenID Specs               |
| `assetlinks.json`              | Verifies ownership of digital assets (apps) associated with a domain. | Permanent   | Google Digital Asset Links |
| `mta-sts.txt`                  | SMTP MTA Strict Transport Security policy to improve email security.  | Permanent   | RFC8461                    |

