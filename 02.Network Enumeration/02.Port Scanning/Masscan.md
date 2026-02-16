# Masscan
**Install:** `sudo apt install masscan` 
**Docs:** [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan)
## Operational Usage
**Concept:** Asynchronous scanner (like `zmap`). It does NOT do service enumeration (versions), only discovery (Open/Closed). It is significantly faster than Nmap but less accurate on unstable networks.
### 1. High-Speed All-Port Scan
**Description:** Scans all 65535 TCP ports. Requires defining the interface (`-e`) on VPNs. 
**Syntax:** `sudo masscan -p1-65535 <IP> --rate=<packets_per_sec> -e <interface>`
```shell
# ⚠️ OPSEC: Critical Noise. Rates >1000 can crash consumer routers/firewalls.
# -e tun0: Essential for HackTheBox/TryHackMe/VPNs (Masscan doesn't auto-detect VPN routing well).
sudo masscan -p1-65535 10.129.2.15 --rate=1000 -e tun0
```
### 2. Large Network Scanning (CIDR)
**Description:** Scans a whole subnet for top ports. 
**Syntax:** `sudo masscan -p<ports> <CIDR> --rate=<packets_per_sec>`
```shell
# Scan top ports on a /24 subnet
sudo masscan -p80,443,445,3389,22 10.129.2.0/24 --rate=10000
```
### 3. Output Processing
**Description:** Masscan output is best handled by saving to a file and extracting the ports for Nmap.
```shell
# 1. Save results to binary or Grepable format
sudo masscan -p1-65535 10.129.2.15 --rate=1000 -e tun0 -oG masscan_out.txt

# 2. Extract Ports (One-Liner)
# Converts Masscan format into a comma-separated list for Nmap
cat masscan_out.txt | grep "Host:" | awk '{print $4}' | cut -d "/" -f 1 | sort -n | tr '\n' ',' | sed 's/,$//' > open_ports.txt

# 3. Feed to Nmap
nmap -p $(cat open_ports.txt) -sC -sV 10.129.2.15
```