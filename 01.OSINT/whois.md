# whois
```table-of-contents
```
## CLI Basic Usage
```shell
# Domain Lookup
# Returns registrar, dates (creation/expiry), and name servers
whois target.com

# IP Lookup
# Crucial to find the Organization Name and ASN
whois 157.240.20.35
```
## Netblock & CIDR Identification
```shell
# 1. Get the Organization Handle/ID from an IP
whois <IP> | grep -i "OrgId\|NetHandle"

# 2. Query the OrgID to find all IP ranges (CIDR)
# Example: If OrgId is 'MSFT'
whois -h whois.arin.net "o ! MSFT"
# OR simply grep the range from the initial IP query
whois <IP> | grep -i "CIDR\|NetRange"
```
## Advanced Options (Specific Servers)
```shell
# Specify a server (-h)
# Useful for TLDs like .io, .tv, or specific regions (RIPE, APNIC)
whois -h whois.radb.net <IP>
whois -h whois.iana.org com
whois -h whois.nic.io target.io

# RIPE (Europe) specific flags
whois -h whois.ripe.net -r -B <IP>
```
## Reverse Whois & History (Web Tools)
- **ViewDNS.info:** Reverse Whois lookup by email or name.
- **Whoxy.com:** Good API for historical ownership.
- **DomainTools:** The industry standard (Paid/Enterprise).
### Curl One-Liner (ViewDNS API)
```shell
# Retrieve reverse whois data (requires free API key)
curl "https://api.viewdns.info/reversewhois/?q=admin@target.com&apikey=YOUR_API_KEY&output=json" | jq .
```