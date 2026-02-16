# DNS (Domain Name System)
**Default Ports:** 53 (UDP - Standard Queries), 53 (TCP - Zone Transfers) 
**Key Insight:** DNS is the map of the network. It reveals hidden subdomains, internal IPs, and mail servers.
## 1. Theory & Record Types
**Goal:** Understand what you are looking for.

|Record|Description|Pentest Utility|
|---|---|---|
|**A**|IPv4 Address|Target IP (Direct mapping).|
|**AAAA**|IPv6 Address|Target IPv6 (Often bypassed by firewalls).|
|**CNAME**|Alias|Check for **Subdomain Takeover** (pointing to dead services).|
|**MX**|Mail Exchange|Phishing targets & Mail servers.|
|**NS**|Name Server|The authoritative servers you should query directly.|
|**TXT**|Text / Notes|SPF/DMARC info, Verification keys, Internal notes.|
|**SOA**|Start of Authority|Admin email (`hostmaster@target.com`), Serial Number.|
|**SRV**|Service Locator|Finds **Active Directory Controllers**, SIP, LDAP.|
|**PTR**|Pointer|Reverse DNS (IP -> Hostname).|
## 2. Manual Enumeration (DIG)
**Concept:** Always query the **Target Name Server** directly (`@<IP>`) to bypass caching and get authoritative answers.
### Standard Queries
```shell
# 1. Identify Name Servers (NS)
dig ns target.com @10.129.2.15

# 2. Get IP Address (A)
dig a target.com @10.129.2.15

# 3. Mail Servers (MX)
dig mx target.com @10.129.2.15

# 4. Version Query (Chaos Class)
# Often blocked, but can reveal BIND version.
dig CH TXT version.bind @10.129.2.15
```
### Reverse Lookup (PTR)
**Goal:** Map a range of IPs back to hostnames to find hidden servers.
```shell
# Single IP
dig -x 10.129.2.15 @10.129.2.15

# Range Sweep (Bash Loop)
# ⚠️ OPSEC: High Noise (DNS Queries).
for ip in $(seq 1 254); do dig -x 10.129.2.$ip @10.129.2.15 +short; done
```
## 3. Zone Transfer (AXFR) - The "Holy Grail"
**Description:** Attempts to download the _entire_ DNS zone file (all subdomains and IPs) from the server. 
**Condition:** The server must be misconfigured to allow AXFR from unauthorized IPs.
### Manual AXFR (DIG)
```shell
# Syntax: dig axfr <DOMAIN> @<NameServer_IP>
# Try this against EVERY Name Server found (ns1, ns2, etc.)
dig axfr target.htb @10.129.2.15

# Internal Zone Guessing
# If you are inside, try 'internal.target.htb'
dig axfr internal.target.htb @10.129.2.15
```
### Automated AXFR (Fierce)
**Tool:** `fierce` 
**Description:** Perl script that locates non-contiguous IP space and hostnames via DNS.
```
# Scan and attempt Zone Transfer
fierce --domain target.htb --dns-servers 10.129.2.15
```
## 4. Subdomain Discovery (Active & Passive)
**Goal:** Find subdomains that aren't public linked (`dev.target.com`, `vpn.target.com`).
### Passive (OSINT - No Packet to Target)
**Tool:** `Subfinder` / `crt.sh`
```shell
# Subfinder (Queries public sources like VirusTotal, Censys, etc.)
subfinder -d target.com -v > passive_subs.txt

# Certificate Transparency (crt.sh) - Manual via Curl
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*.//g' | sort -u
```
### Active (Brute Force)
**Tool:** `Gobuster DNS` 
**Description:** Guesses subdomains using a wordlist. 
**Syntax:** `gobuster dns -d <Domain> -w <Wordlist> -r <NameServer>`
```shell
# ⚠️ OPSEC: High Noise.
gobuster dns -d target.htb -r 10.129.2.15 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```
### Active (Virtual Host / VHost)
**Description:** Used when multiple domains share the same IP (Common in web hosting/CTFs). The DNS A record exists, but the web server routes based on the `Host` header. 
**Tool:** `ffuf`
```shell
# Fuzz the Host Header
# -fs: Filter size (exclude default response size)
ffuf -w subdomains.txt -u http://10.129.2.15 -H "HOST: FUZZ.target.htb" -fs 10918
```
## 5. Domain Takeover
**Concept:** A subdomain points (CNAME) to a third-party service (e.g., AWS S3, GitHub Pages, Heroku) that has been deleted or unclaimed. You can claim that resource and control the subdomain.
### Detection
1. Enumerate Subdomains (`subfinder`, `sublist3r`). 
2. Check CNAMEs (`dig cname sub.target.com`).
3. If CNAME points to `target.s3.amazonaws.com` AND visiting it gives "NoSuchBucket", it's vulnerable.
```shell
# Check CNAME manually
dig cname support.target.com

# Automated Check (SubJack / Can-I-Take-Over-XYZ)
# (Requires installation of specific tools)
```
## 6. DNS Spoofing (MITM)
**Context:** You are on the local network (LAN) and want to redirect traffic. 
**Tool:** `Ettercap` / `Bettercap`
### Ettercap Configuration
**File:** `/etc/ettercap/etter.dns` 
**Goal:** Redirect `target.com` to YOUR IP (`192.168.1.105`).
```shell
# Edit /etc/ettercap/etter.dns
target.com      A   192.168.1.105
*.target.com    A   192.168.1.105
```

**Execution:**
```shell
# Launch Ettercap with DNS Spoofing plugin
sudo ettercap -T -q -i eth0 -P dns_spoof -M arp // //
```
## 7. Post-Exploitation (Local Linux)
**Context:** You compromised a DNS Server (Bind9).
```shell
# Main Config (Look for "allow-transfer" or "allow-query")
cat /etc/bind/named.conf.local
cat /etc/bind/named.conf.options

# Zone Files (The actual database of domains)
ls /etc/bind/zones/
cat /etc/bind/zones/db.target.com
```