# DNS
```table-of-contents
```
## DNS Theory & Records
| **Record** | **Description**        | **Pentesting Utility**             |
| ---------- | ---------------------- | ---------------------------------- |
| `A`        | IPv4 Address           | Target IPv4                        |
| `AAAA`     | IPv6 Address           | Target IPv6                        |
| `CNAME`    | Canonical Name (Alias) | Check for Subdomain Takeover       |
| `MX`       | Mail Exchange          | Phishing targets / Mail servers    |
| `NS`       | Name Server            | The authoritative servers to query |
| `TXT`      | Text / Notes           | SPF/DMARC info, Verification keys  |
| `PTR`      | Pointer (Reverse DNS)  | Mapping IPs to Hostnames           |
| `SOA`      | Start of Authority     | Admin email, Zone Serial Number    |
| `SRV`      | Service Locator        | Finds AD Controllers, SIP, etc.    |
## Manual Enumeration (DIG)
```shell
# 1. Identify Name Servers (NS)
# Always query the NS directly (@IP) to bypass caching
dig ns <DOMAIN> @<IP>

# 2. Version Query (Chaos Class)
# Can reveal BIND version (often blocked)
dig CH TXT version.bind @<IP>

# 3. Mail Servers (MX)
dig mx <DOMAIN> @<IP>

# 4. Any Query (Noisy)
# Requests all available records. Often blocked/deprecated (RFC 8482).
dig any <DOMAIN> @<IP>

# 5. Reverse Lookup (PTR)
dig -x <IP> @<IP>
```
### Quick Reference: Other Tools
| **Tool**   | **Description**            | **Use Case**                                     |
| ---------- | -------------------------- | ------------------------------------------------ |
| `dig`      | Versatile DNS lookup tool. | Manual queries, troubleshooting, zone transfers. |
| `nslookup` | Simpler, legacy tool.      | Basic A/MX checks.                               |
| `host`     | Simplified output.         | Quick IP resolution.                             |
## Zone Transfer (AXFR)
```shell
# Try Zone Transfer on specific domain
dig axfr <DOMAIN> @<IP>

# Internal Zone Transfer (Guessing internal naming)
dig axfr internal.<DOMAIN> @<IP>

# Fierce (Automated tool)
fierce --domain <DOMAIN> --dns-servers <IP>
```
## Passive Recon (CT Logs)
### Certificate Transparency (crt.sh)
```shell
# Get JSON Output and parse with jq
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq -r '.[].name_value' | sed 's/\*.//g' | sort -u

# Example for Facebook dev domains
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
## Active Subdomain Discovery
### Automated Tools
```shell
# Gobuster DNS (Preferred)
gobuster dns -d <DOMAIN> -r <IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# DNSenum (Classic)
dnsenum --enum <DOMAIN> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```
### Manual Bash Loop (Slow but stealthy)
```shell
for sub in $(cat subdomains.txt); do
    dig $sub.<DOMAIN> @<IP> +short
done
```
## Virtual Host Discovery (VHost)
### Gobuster VHost
```shell
# append-domain adds the base domain to the wordlist automatically
gobuster vhost -u http://<TARGET_IP> -w wordlist.txt --append-domain --domain <DOMAIN>
```
### Ffuf VHost
```shell
# Fuzzing the Host header
# -fs: Filter size (exclude default response size)
ffuf -w wordlist.txt -u http://<IP> -H "HOST: FUZZ.<DOMAIN>" -fs <SIZE>
```
### Manual Verification (Curl)
```shell
# If you found 'admin.target.htb' via fuzzing:
curl -s http://<IP> -H "Host: admin.target.htb"
```
## Post-Exploitation (Local Config)
```shell
# Main Configuration
cat /etc/bind/named.conf.local
cat /etc/bind/named.conf.options

# Zone Files (Contains the actual records)
ls /etc/bind/zones/
cat /etc/bind/db.<DOMAIN>

# Reverse Zone Files
cat /etc/bind/db.10.129.14
```