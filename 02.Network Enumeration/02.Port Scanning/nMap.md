# Nmap
**Install:** `sudo apt install nmap` 
**Docs:** [https://nmap.org/book/man.html](https://nmap.org/book/man.html)
## 1. The "Golden Standard" Workflow
_Follow this sequence to balance speed and accuracy._
### 1. Insane Speed (CTF / Lab / Internal)
**Description:** Extreme speed. Forces 5000 packets/sec. Only use on stable networks (LAN/VPN) where you don't care about detection. 
**Syntax:** `nmap -p- --min-rate=5000 -n -Pn <IP>`
```shell
# ⚠️ OPSEC: Critical Noise. Will trigger every IDS. High risk of packet loss on weak networks.
# -n: No DNS resolution (speed) | -Pn: Skip ping (assume alive)
sudo nmap -p- --min-rate=5000 -n -Pn -vv 10.129.2.15 -oN rapid_scan.txt
```
### 2. Aggressive / Standard (Pentest Best Practice)
**Description:** The "Sweet Spot". Fast enough (1-2 mins for 65k ports) but reliable. Standard for commercial penetration testing. 
**Syntax:** `nmap -p- --min-rate=1000 -T4 <IP>`
```shell
# ⚠️ OPSEC: High Noise. Detected by modern SOCs, but generally accepted in white-box tests.
sudo nmap -p- --min-rate=1000 -T4 -vv 10.129.2.15 -oA full_scan
```
### 3. Polite / Slow (Legacy Systems)
**Description:** Use when the target is fragile (OT/IoT devices, old Windows servers) and might crash under high load. 
**Syntax:** `nmap -p- -T2 <IP>`
```shell
# ⚠️ OPSEC: Moderate Noise. Reduces risk of DoS, but scan will take HOURS.
# T2: 0.4 seconds wait between probes.
sudo nmap -p- -T2 -v 10.129.2.15 -oN safe_scan.txt
```
### 4. Stealth & Evasion (Red Team / IDS Bypass)
**Description:** Attempts to hide the scan origin or blend in. Uses fragmentation and decoys. 
**Syntax:** `nmap -sS -T2 -f -D RND:5 <IP>`
```shell
# ⚠️ OPSEC: Low/Moderate Noise. Harder to attribute, but patterns may still be flagged.
# -f: Fragment packets (bypass simple packet filters)
# -D RND:10: Use 10 random IP addresses as decoys (hide your real IP)
# --source-port 53: Mimic DNS traffic (often allowed through firewalls)
sudo nmap -sS -p 80,443,445,3389 -T2 -f -D RND:10 --source-port 53 10.129.2.15 -oN stealth_scan.txt
```
### 5. UDP Quick Check (The "Forgotten" Ports)
**Description:** UDP is slow and stateless. Do NOT scan all UDP ports unless necessary. Scan the top 1000 most common. 
**Syntax:** `nmap -sU --top-ports 1000 <IP>`
```shell
# ⚠️ OPSEC: Moderate Noise. Very slow.
sudo nmap -sU --top-ports 200 -v 10.129.2.15 -oN udp_top200.txt
```
## 2. Live Host Discovery (Ping Sweeps)
_Identify active hosts before scanning ports._
```shell
# Local Network (ARP) - Best for internal
sudo nmap -sn 192.168.1.0/24

# External/VPN (ICMP Echo + TCP ACK)
# --disable-arp-ping forces ICMP usage even on local LANs
sudo nmap -sn 10.10.10.0/24 --disable-arp-ping

# Assume Online (No Ping)
# CRITICAL: Use this if the host blocks ICMP/Ping but has open ports.
sudo nmap -Pn -n 10.129.2.15
```

**One-Liner: Extract Alive IPs**
```shell
# Scans subnet and saves only the IPs that responded to a file.
sudo nmap 10.129.2.0/24 -sn -oG - | awk '/Up$/{print $2}' > alive_hosts.txt
```
## 3. Scan Techniques
### TCP Scanning
```shell
# SYN Scan (Stealthy, Default) - Requires Sudo
# Sends SYN -> Receives SYN-ACK -> Sends RST. No full connection.
sudo nmap -sS 10.129.2.15

# Connect Scan (Noisy) - No Sudo
# Completes the full 3-way handshake. Logs heavily on the target.
nmap -sT 10.129.2.15
```
### Service & Version Detection
```shell
# Version Detection (Standard)
nmap -sV 10.129.2.15

# Version Intensity (0-9)
# 9 tries every probe. 0 tries only the most likely.
nmap -sV --version-intensity 5 10.129.2.15
```
## 4. Nmap Scripting Engine (NSE)
_Located in `/usr/share/nmap/scripts/`_
```shell
# Default Scripts (Safe, valuable recon)
nmap -sC 10.129.2.15

# Vulnerability Scanning (Vulners/Vuln category)
# ⚠️ OPSEC: Very High Noise. Can crash unstable services.
nmap --script vuln 10.129.2.15

# Targeted Script (e.g., SMB Enumeration)
nmap --script smb-os-discovery 10.129.2.15

# Script Arguments
nmap --script http-title --script-args http.useragent="Mozilla 5" 10.129.2.15
```
## 5. Firewall Evasion & Timing
### Evasion Techniques
```shell
# Fragment Packets (Bypass simple packet inspection)
sudo nmap -f 10.129.2.15

# Decoys (Hide your IP among fakes)
# RND:5 generates 5 random IP addresses as decoys.
sudo nmap -D RND:5 10.129.2.15

# Source Port Manipulation
# Mimic traffic from DNS (53) or Kerberos (88) to bypass strict firewalls.
sudo nmap --source-port 53 10.129.2.15
```
### Performance Tuning
```shell
# Timing Templates
# T0 (Paranoid) ... T3 (Normal) ... T4 (Aggressive/CTF) ... T5 (Insane)
nmap -T4 10.129.2.15

# Min Rate (Force packet speed)
# Dangerous: Can cause packet loss if the network is weak.
nmap --min-rate 1000 10.129.2.15
```
## 6. Output & Debugging
```shell
# Save in All Formats (Normal, Grepable, XML) - RECOMMENDED
nmap -oA scan_results 10.129.2.15

# Trace Packets (See exactly what is sent/received)
nmap --packet-trace 10.129.2.15

# Reason (Why is a port marked closed/filtered?)
nmap --reason 10.129.2.15
```