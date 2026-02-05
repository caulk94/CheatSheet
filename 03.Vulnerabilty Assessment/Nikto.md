# Nikto
```table-of-contents
```
## Basic Usage
```shell
# Standard Scan
nikto -h http://target.com

# Scan specific port (e.g., HTTP on 8080)
nikto -h http://target.com -p 8080

# Scan with SSL (Force HTTPS)
nikto -h target.com -ssl
```
## Tuning & Evasion
```shell
# Tuning Options (Save time)
# 1=Injection, 2=Misconfig, b=Software ID
nikto -h target.com -Tuning b

# User Agent Spoofing (Bypass simple filters)
nikto -h target.com -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```
## Output
```shell
# Save to HTML file
nikto -h target.com -o scan_result.html -Format htm
```
### Tuning Reference Table
| **Flag** | **Description**                     |
| ---- | ------------------------------- |
| `1`  | Interesting File / Seen in logs |
| `2`  | Misconfiguration / Default File |
| `3`  | Information Disclosure          |
| `4`  | Injection (XSS/Script/HTML)     |
| `8`  | Embedded Devices                |
| `9`  | SQL Injection                   |
| `b`  | Browser Identification          |
