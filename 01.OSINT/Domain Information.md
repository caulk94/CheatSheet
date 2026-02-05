# Domain Information
```table-of-contents
```
## WHOIS & Registration
```shell
# Basic Lookup
whois target.com

# IPs and Netblocks (BGP)
# useful to find the ASN and IP ranges owned by the organization
whois -h whois.cymru.com <IP>
```
## DNS Enumeration
```shell
# Name Servers (NS)
dig ns target.com +short

# Mail Servers (MX)
dig mx target.com +short

# TXT Records (SPF, DMARC, Verification codes)
dig txt target.com +short

# Zone Transfer (AXFR) - The "Holy Grail"
# Try this against EVERY Nameserver found in the NS step
dig axfr @ns1.target.com target.com
```
## Certificate Transparency (crt.sh)
```shell
# Get JSON Output
curl -s "https://crt.sh/?q=target.com&output=json" | jq .

# Extract Clean Subdomain List (One-Liner)
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*.//g' | sort -u > crt_subdomains.txt
```
## Subdomain Discovery
### Passive (Fast)
```shell
# Assetfinder (Go tool - minimal setup)
assetfinder --subs-only target.com > assets.txt

# Amass (The heavy hitter - passive)
amass enum -passive -d target.com -o amass_out.txt
```
### Active (Bruteforce)
```shell
# Gobuster DNS
# Requires a wordlist (e.g., Seclists)
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o gobuster_out.txt
```
## Data Correlation (Resolving IPs)
```shell
# 1. Merge all lists and sort
cat crt_subdomains.txt assets.txt | sort -u > unique_domains.txt

# 2. Resolve IPs (Bash loop)
# Filters out domains that don't resolve
for domain in $(cat unique_domains.txt); do 
    host $domain | grep "has address" | cut -d" " -f4 >> live_ips.txt
done

# 3. Clean up IP list
sort -u live_ips.txt > final_ips.txt
```
## Shodan (Command Line)
```shell
# Quick Host Check
# Note: Requires Shodan CLI initialized
for ip in $(cat final_ips.txt); do 
    echo "---[ $ip ]---"; 
    shodan host $ip; 
done
```