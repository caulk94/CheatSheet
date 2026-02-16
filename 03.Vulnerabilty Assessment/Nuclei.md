# Nuclei
**Role:** Template-based Vulnerability Scanner. **Key Insight:** Nuclei is **fast** and **highly specific**. Instead of checking "everything," you can ask it to check "only for CVE-2023-XXXX" or "only for exposed panels." This makes it surgical and less prone to false positives.
## 1. Update (Critical)
**Goal:** Ensure you have the latest binary and, more importantly, the latest community templates.
```shell
# Update the Engine (Binary)
nuclei -update

# Update the Templates (Definitions)
# Run this DAILY. New CVEs are added constantly.
nuclei -update-templates
```
## 2. Basic Scanning
**Goal:** Run a general scan against a single host or a list of hosts.
### Single Target
```shell
# Basic Scan (Runs default templates)
nuclei -u https://target.com
```
### List of Targets (Mass Scan)
**Context:** You have a list of subdomains from `subfinder`.
```shell
# -list: File containing URLs (one per line)
nuclei -list live_subdomains.txt
```
## 3. Targeted Scans (The Power of Nuclei)
**Goal:** Narrow the scope to find high-value bugs (CVEs, config leaks) without generating gigabytes of noise.
### Filter by Directory (Templates)
```shell
# Scan ONLY for CVEs (The "Kill Chain" scan)
nuclei -u https://target.com -t cves/

# Scan ONLY for Misconfigurations
nuclei -u https://target.com -t misconfiguration/

# Scan for a Specific Year's CVEs
nuclei -u https://target.com -t cves/2023/
```
### Filter by Tags (Logic)
**Description:** Use tags to group templates across directories. 
**Syntax:** `-tags <tag1,tag2>`
```shell
# Search for Critical CVEs and Exposed Panels
nuclei -u https://target.com -tags cve,panel,exposure

# Search for Specific Tech (e.g., WordPress bugs)
nuclei -u https://target.com -tags wordpress
```
### Filter by Severity
**Description:** Ignore "Info" or "Low" findings to focus on shellable bugs. 
**Syntax:** `-severity <level>`
```shell
# Show only Critical and High vulnerabilities
nuclei -u https://target.com -severity critical,high
```
## 4. Rate Limiting & Optimization
**Goal:** Avoid crashing the target server or getting WAF-blocked.
```shell
# Limit Request Rate
# -rl: Requests per second (Default is 150 - High!)
# ⚠️ OPSEC: Set to < 50 for stealth.
nuclei -u https://target.com -rate-limit 50

# Concurrency (Parallel Templates)
# -c: Number of templates to run in parallel (Default 25)
nuclei -u https://target.com -c 10

# Timeout & Retries
# -timeout: Seconds to wait | -retries: Retry failed reqs
nuclei -u https://target.com -timeout 5 -retries 1
```
## 5. Output & Debugging
**Goal:** Save results for reporting or debug connection issues.
```shell
# Save to File (Text)
nuclei -u https://target.com -o results.txt

# JSON Output (For tools/parsing)
nuclei -u https://target.com -json -o results.json

# Verbose Mode (See what is happening)
# -v: Show executed templates | -debug: Show Request/Response
nuclei -u https://target.com -v
```