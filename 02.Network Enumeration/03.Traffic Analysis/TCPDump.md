# TCPDump
```table-of-contents
```
## The Essentials (Flags)
```shell
# -i : Interface (e.g., tun0, eth0, any)
# -n : No DNS resolution (Show IPs, not names - FASTER)
# -v : Verbose (Use -vv or -vvv for more detail)
# -c : Count (Stop after N packets)
sudo tcpdump -i tun0 -n -v
```
## Reading & Writing (PCAP)
```shell
# Save traffic to a file (.pcap)
sudo tcpdump -i eth0 -w capture.pcap

# Read a saved file
sudo tcpdump -r capture.pcap
```
## Inspecting Payloads (ASCII & HEX)
```shell
# Print output in ASCII (Great for HTTP/FTP)
sudo tcpdump -i eth0 -A

# Print output in Hex and ASCII (Best for binary/mixed data)
sudo tcpdump -i eth0 -X
```
## Filtering (The Art of Tcpdump)
### Host & Network
```shell
# Traffic to/from a specific IP
sudo tcpdump -i eth0 host 10.10.10.5

# Traffic COMING FROM a specific IP
sudo tcpdump -i eth0 src 10.10.10.5

# Traffic GOING TO a specific IP
sudo tcpdump -i eth0 dst 10.10.10.5

# Whole Network
sudo tcpdump -i eth0 net 10.10.10.0/24
```
### Ports & Protocols
```shell
# Specific Port
sudo tcpdump -i eth0 port 80

# Port Range
sudo tcpdump -i eth0 portrange 1000-2000

# Protocol Specific (icmp, tcp, udp)
sudo tcpdump -i eth0 icmp
```
### Logical Operators
```shell
# AND, OR, NOT (!)
# Example: Traffic from Target (10.10.10.5) excluding SSH (22)
sudo tcpdump -i eth0 host 10.10.10.5 and not port 22
```
## Practical Pentesting Scenarios
### 1. Troubleshooting Reverse Shells (Is it connecting back?)
```shell
# Listen on your VPN interface for traffic from the Target IP
sudo tcpdump -i tun0 host <TARGET_IP>
```
### 2. Hunting for Cleartext Credentials (HTTP/FTP/Telnet)
```shell
# -A (ASCII) | -l (Line buffered - see it instantly)
sudo tcpdump -i eth0 port 80 or port 21 or port 23 -A -l
```
### 3. Detecting Ping (ICMP)
```shell
sudo tcpdump -i tun0 icmp
```
### 4. Isolating TCP Flags (Advanced)
```shell
# Show only SYN packets (Connection attempts)
sudo tcpdump -i eth0 "tcp[tcpflags] & (tcp-syn) != 0"
```