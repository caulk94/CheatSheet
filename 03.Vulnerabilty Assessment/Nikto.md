# Nikto
**Role:** Web Server Scanner. 
**Key Insight:** Nikto is **extremely noisy**. It generates thousands of 404 errors. Use it for "Smash and Grab" or when stealth is not a requirement (e.g., CTFs). It excels at finding **outdated software versions** and **default files**.
## 1. Basic Usage
**Goal:** Run a default scan against a target.
### Standard Scan
```shell
# Basic Scan (HTTP)
# -h: Host (IP or Domain)
nikto -h http://10.129.2.15

# Force SSL (HTTPS)
# -ssl: Forces SSL connection (useful if auto-detection fails)
nikto -h 10.129.2.15 -ssl
```
### Specific Port / Protocol
```shell
# Scan alternative port (e.g., 8080, 8443)
nikto -h 10.129.2.15 -p 8080
```
## 2. Tuning & Optimization (Critical)
**Goal:** Reduce scan time by targeting specific vulnerability classes. 
**Syntax:** `nikto -h <Target> -Tuning <Flags>`

| **Flag** | **Description**      | **Use Case**                             |
| -------- | -------------------- | ---------------------------------------- |
| `1`      | *Interesting File* | Logs, Secret files, Admin panels.        |
| `2`      | *Misconfiguration* | Default files, Verbose errors.           |
| `3`      | *Info Disclosure*  | Path traversal patterns.                 |
| `4`      | *Injection*        | XSS, Script, HTML injection.             |
| `8`      | *Embedded*         | IoT/Embedded device specific checks.     |
| `9`      | *SQL Injection*    | Basic SQLi patterns.                     |
| `b`      | *Software ID*      | Identifies version strings (Apache/IIS). |
```shell
# Fast Scan (Software ID & Misconfigurations only)
# ⚠️ OPSEC: Lower Noise (fewer requests).
nikto -h 10.129.2.15 -Tuning 2b

# Full vulnerability scan (Injection & File Disclosure)
nikto -h 10.129.2.15 -Tuning 1349
```
## 3. Evasion & Identity
**Goal:** Bypass basic WAF filters or User-Agent blocks.
### User-Agent Spoofing
**Context:** Some servers block the default "Nikto" user agent.
```shell
# Masquerade as a legitimate browser
nikto -h 10.129.2.15 -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
```
### Evasion Techniques (IDS/WAF)
**Note:** These fragment packets but modern WAFs usually reassemble them.
```shell
# -evasion 1: Random URI encoding (non-UTF8)
# -evasion B: Binary URL encoding
nikto -h 10.129.2.15 -evasion 1
```
## 4. Output & Integration
**Goal:** Save results for reporting or import into Metasploit.
```shell
# Save to HTML (Readable Report)
nikto -h 10.129.2.15 -o scan_results.html -Format htm

# Save to CSV (Data Analysis)
nikto -h 10.129.2.15 -o scan_results.csv -Format csv
```