# Domain & Infrastructure Enumeration
## 1. Registration & Ownership (Passive)
### WHOIS
**Install:** Native on most Linux distros (`sudo apt install whois`) 
**Docs:** [https://linux.die.net/man/1/whois](https://linux.die.net/man/1/whois)
```shell
# Description: detailed registration info (Registrar, Admin emails, Creation dates).
# Syntax: whois <domain>
# ⚠️ OPSEC: Low Noise. Queries the Registrar DB, not the target directly.
whois target.com
```
### IP/ASN Lookup (Team Cymru)
**Description:** Identifies the Autonomous System Number (ASN) and IP range owner via Netcat. 
**Syntax:** `whois -h whois.cymru.com <IP_Address>`
```shell
# Example: Check who owns a specific IP
# ⚠️ OPSEC: Low Noise.
whois -h whois.cymru.com 203.0.113.5
```
## 2. DNS Enumeration
### Dig (Standard Records)
**Install:** Native (`dnsutils` or `bind-utils`) 
**Docs:** [https://linux.die.net/man/1/dig](https://linux.die.net/man/1/dig)
```shell
# Description: Extract Name Servers (NS), Mail Servers (MX), and TXT records (SPF/DMARC).
# Syntax: dig <record_type> <domain> +short

# Name Servers
dig ns target.com +short

# Mail Exchangers
dig mx target.com +short

# TXT (Look for SPF ranges, verification codes)
dig txt target.com +short
```
### DNS Zone Transfer (AXFR)
**Description:** Attempts to request a full copy of the DNS zone. 
**Syntax:** `dig axfr @<nameserver> <domain>`
```shell
# Example: Try against ALL found Name Servers.
# ⚠️ OPSEC: High Noise / Detectable. Most modern DNS servers deny this.
dig axfr @ns1.target.com target.com
```
## 3. Subdomain Discovery (Passive)
### Certificate Transparency (crt.sh)
**Description:** Queries public SSL/TLS certificate logs to find subdomains. 
**URL:** [https://crt.sh](https://crt.sh)
```shell
# Description: One-liner to fetch, clean, and sort subdomains from crt.sh.
# Syntax: curl ... | jq ... | sed ...
# ⚠️ OPSEC: Passive (HTTPS traffic to crt.sh, not target).
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*.//g' | sort -u > subdomains_crt.txt
```
### Assetfinder
**Install:** `go install github.com/tomnomnom/assetfinder@latest` 
**Docs:** [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder)
```shell
# Description: Fast Golang tool to find domains and subdomains from various sources.
# Syntax: assetfinder --subs-only <domain>
# ⚠️ OPSEC: Passive.
assetfinder --subs-only target.com > subdomains_assetfinder.txt
```
### Amass (Passive Mode)
**Install:** `sudo apt install amass` or `go install github.com/owasp-amass/amass/v4/...@master` 
**Docs:** [https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass)
```shell
# Description: Comprehensive scraping of OSINT sources.
# Syntax: amass enum -passive -d <domain> -o <output_file>
# ⚠️ OPSEC: Passive.
amass enum -passive -d target.com -o subdomains_amass.txt
```
## 4. Subdomain Discovery (Active)
### Gobuster DNS
**Install:** `sudo apt install gobuster` 
**Docs:** [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)
```shell
# Description: Bruteforces subdomains using a wordlist.
# Syntax: gobuster dns -d <target> -w <wordlist> -o <output>
# ⚠️ OPSEC: High Noise. Generates thousands of DNS queries.
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o subdomains_brute.txt
```
## 5. Data Correlation & Resolution
### Resolving Domains to IPs
**Description:** Takes a list of domains and finds their live IP addresses. 
**Syntax:** Bash loop or `massdns`.
```shell
# 1. Merge all subdomain lists
cat subdomains_*.txt | sort -u > all_domains.txt

# 2. Resolve IPs (Bash Loop)
# ⚠️ OPSEC: Moderate Noise (DNS traffic).
for domain in $(cat all_domains.txt); do 
    host $domain | grep "has address" | cut -d" " -f4 >> live_ips_raw.txt
done

# 3. Clean and Unique IPs
sort -u live_ips_raw.txt > live_ips.txt
```
## 6. Infrastructure Intelligence
### Shodan CLI
**Install:** `pip install shodan` 
**Docs:** [https://cli.shodan.io/](https://cli.shodan.io/) 
**Setup:** `shodan init <YOUR_API_KEY>`
```shell
# Description: Query Shodan database for open ports/banners on resolved IPs.
# Syntax: shodan host <IP>
# ⚠️ OPSEC: Passive (Queries Shodan DB).
for ip in $(cat live_ips.txt); do 
    echo "---[ $ip ]---"
    shodan host $ip
done
```