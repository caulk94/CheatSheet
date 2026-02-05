# nMap
```table-of-contents
```
## The Golden Standards
```shell
# 1. Fast TCP Scan (All Ports)
# Finds open ports quickly using high rates.
sudo nmap -p- --min-rate=1000 -T4 -v <IP>

# 2. Comprehensive Scan (Specific Ports)
# Run this ON the ports found in step 1.
# -sC: Default scripts | -sV: Versions | -A: Aggressive (OS+Traceroute)
sudo nmap -p <PORTS> -sC -sV -A <IP> -oA full_scan

# 3. UDP Quick Scan (Top 100)
# UDP is slow, so stick to top ports unless you have a specific reason.
sudo nmap -sU --top-ports 100 -v <IP>
```
## Live Host Discovery (Ping Sweeps)
```shell
# Ping Sweep (No Port Scan) - Local Network (ARP)
sudo nmap -sn 192.168.1.0/24

# Ping Sweep - disable ARP (if VPN/External)
sudo nmap -sn 10.10.10.0/24 --disable-arp-ping

# No Ping (Treat all hosts as online)
# USE THIS if the host blocks ICMP/Ping probes!
sudo nmap -Pn -n <IP>
```
### Utility One-Liners (Extracting IPs)
```shell
# Scan network and extract only alive IPs to a file
sudo nmap 10.129.2.0/24 -sn -oG - | awk '/Up$/{print $2}' > alive_hosts.txt
```
## Port Scanning Techniques
### TCP Scanning
```shell
# SYN Scan (Stealthy, requires sudo, Default)
sudo nmap -sS <IP>

# Connect Scan (No sudo, Noisy, completes 3-way handshake)
nmap -sT <IP>

# Scan Specific Ports
nmap -p 80,443,8080 <IP>

# Scan Port Ranges
nmap -p 1-65535 <IP>
```
### UDP Scanning
```shell
# Top 1000 UDP ports
sudo nmap -sU --top-ports 1000 <IP>

# Specific UDP port (e.g., SNMP or TFTP)
sudo nmap -sU -p 161,69 <IP>
```
## Service & Script Enumeration (NSE)
### Service Detection
```shell
# Detect Versions on Open Ports
nmap -sV <IP>

# Set Version Intensity (0-9)
nmap -sV --version-intensity 5 <IP>
```
### Nmap Scripting Engine (NSE)
```shell
# Default Scripts (Safe and useful)
nmap -sC <IP>

# Vulnerability Scan (Run vulners/vuln category)
nmap --script vuln <IP>

# Specific Script (e.g., SMB)
nmap --script smb-os-discovery <IP>

# Pass Arguments to Script
nmap --script http-title --script-args http.useragent="Mozilla 5" <IP>
```
## Performance & Timing
```shell
# Timing Templates (T0=Paranoid ... T5=Insane)
# T4 is the standard for CTFs. T2 is for stealth.
nmap -T4 <IP>

# Min Rate (Force packet speed - Dangerous but fast)
nmap --min-rate 1000 <IP>

# Give up on slow hosts
nmap --host-timeout 30m <IP>
```
## Evasion & Firewalls
```shell
# Fragment Packets (Bypass simple packet filters)
sudo nmap -f <IP>

# Decoys (Hide your IP among fakes)
sudo nmap -D RND:5 <IP>

# Source Port Manipulation
# (Some firewalls allow traffic if it comes from port 53 or 88)
sudo nmap --source-port 53 <IP>

# Mac Address Spoofing
sudo nmap --spoof-mac Cisco <IP>
```
## Output Formats
```shell
# Save in All Formats (Normal, Grepable, XML) - RECOMMENDED
nmap -oA <basename> <IP>

# Save only Normal
nmap -oN scan.txt <IP>

# Convert XML to HTML Report
xsltproc target.xml -o target.html
```
## Debugging
```shell
# Trace Packets (See what is actually sent)
nmap --packet-trace <IP>

# Show Reason (Why is a port marked closed/filtered?)
nmap --reason <IP>
```