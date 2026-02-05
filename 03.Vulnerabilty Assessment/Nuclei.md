# Nuclei
```table-of-contents
```
## Update
```shell
nuclei -update
nuclei -update-templates
```
## Scanning Commands
### Basic Scans
```shell
# Scan a single target
nuclei -u https://target.com

# Scan a list of URLs
nuclei -list urls.txt
```
### Targeted Scans (Templates & Tags)
```shell
# Scan ONLY for CVEs (Critical)
nuclei -u https://target.com -t cves/

# Scan for specific year CVEs
nuclei -u https://target.com -t cves/2023/

# Scan by Tags (e.g., cve, misconfig, exposure, panel)
nuclei -u https://target.com -tags cve,misconfig

# Scan for specific severity
nuclei -u https://target.com -severity critical,high
```
### Rate Limiting & Optimization
```shell
# Limit requests per second (Stealthier)
nuclei -u https://target.com -rate-limit 50

# Follow redirects and show verbose output
nuclei -u https://target.com -L -v
```