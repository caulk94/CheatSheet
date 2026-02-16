# TCPDump
**Install:** Native on most Linux distros (`sudo apt install tcpdump`) 
**Docs:** [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)
### 1. The Essentials (Quick Start)
**Description:** The fundamental flags you need 99% of the time. 
**Syntax:** `sudo tcpdump -i <interface> -n <flags>`
- `-i tun0`: Interface (VPN/Ethernet).
- `-n`: **No DNS resolution** (Critical for speed).
- `-v`: Verbose (Packet details).
- `-w`: Write to `.pcap` file.
- `-r`: Read from `.pcap` file.

```shell
# Standard Listening (Verbose, No DNS, VPN interface)
# ⚠️ OPSEC: Passive. Listening does not generate traffic unless you are resolving DNS (-n prevents this).
sudo tcpdump -i tun0 -n -v
```
### 2. Operational Filters (The Art of Analysis)
#### Host & Network Filtering
**Description:** Isolate traffic to/from specific targets.
```shell
# Traffic to/from specific IP
sudo tcpdump -i eth0 host 10.129.2.15

# Traffic COMING FROM Target (Inbound)
sudo tcpdump -i eth0 src 10.129.2.15

# Traffic GOING TO Target (Outbound)
sudo tcpdump -i eth0 dst 10.129.2.15

# Whole Subnet
sudo tcpdump -i eth0 net 10.129.2.0/24
```
#### Port & Protocol Filtering
**Description:** Focus on specific services or exclude noise (like SSH).
```shell
# Specific Port
sudo tcpdump -i eth0 port 80

# Exclude SSH (Port 22) - Essential to remove your own traffic noise
sudo tcpdump -i eth0 host 10.129.2.15 and not port 22

# Protocol Specific (ICMP/TCP/UDP)
sudo tcpdump -i eth0 icmp
```
### 3. Payload Inspection (Reading Data)
#### ASCII & Hex Dump
**Description:** View the actual content of packets (credentials, HTTP headers, file data).
```shell
# ASCII Mode (Great for HTTP, FTP, Telnet)
# -A: Print in ASCII
# -l: Line buffered (View output instantly, don't wait for buffer to fill)
sudo tcpdump -i eth0 port 80 -A -l

# Hex + ASCII Mode (Best for binary/mixed data)
# -X: Print Hex and ASCII
sudo tcpdump -i eth0 host 10.129.2.15 -X
```
### 4. Real-World Pentest Scenarios
#### Scenario A: Troubleshooting Reverse Shells
**Context:** You executed a payload, but no shell appeared. Is the server trying to connect back? 
**Command:** Listen for _any_ traffic from the target IP on your VPN interface.
```shell
# If you see SYNs coming in but no connection, your firewall might be blocking it.
sudo tcpdump -i tun0 host 10.129.2.15
```
#### Scenario B: Hunting Cleartext Credentials
**Context:** Passive sniffing on a compromised host or during a Man-in-the-Middle attack. 
**Command:** Filter for plaintext protocols and print ASCII.
```shell
# Sniff HTTP, FTP, Telnet, POP3, IMAP
sudo tcpdump -i eth0 "port 80 or port 21 or port 23 or port 110" -A -l | grep -iE 'user|pass|login'
```
#### Scenario C: Detecting ICMP (Ping)
**Context:** Verifying if a host is reachable or if OS command injection is working via ping.
```shell
sudo tcpdump -i tun0 icmp
```
### 5. Advanced Flag Filtering
**Description:** Filter based on TCP flags (SYN, ACK, FIN, RST). Useful for detecting port scans or specific handshake failures.
```shell
# Show only SYN packets (Connection Attempts)
# "tcp[13] & 2 != 0" is the bitmask for SYN
sudo tcpdump -i eth0 "tcp[tcpflags] & (tcp-syn) != 0"

# Show SYN-ACK (Responses to your SYN scan)
sudo tcpdump -i eth0 "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
```