# Live Host Discovery
## 1. Local Network (Layer 2 - ARP)
_Best for: Internal networks where you have a foothold. ARP is not routable, so this only works on the local subnet._
### arp-scan
**Install:** `sudo apt install arp-scan` 
**Docs:** [https://github.com/royhills/arp-scan](https://github.com/royhills/arp-scan)
```shell
# Description: Sends ARP requests to all hosts on the local subnet. Extremely fast and accurate.
# Syntax: sudo arp-scan -I <interface> <subnet_CIDR>
# ⚠️ OPSEC: High Noise (Broadcast traffic). Visible to anyone on the same LAN.

# Standard Scan
sudo arp-scan -I eth0 192.168.1.0/24
```
## 2. Ping Sweeps (Layer 3 - ICMP)
_Best for: Routed networks or initial discovery from an external position (if ICMP is allowed)._
### fping
**Install:** `sudo apt install fping` 
**Docs:** [https://fping.org/](https://fping.org/)
```shell
# Description: A more performant, scriptable version of ping. Sends ICMP Echo Requests to ranges.
# Syntax: fping -a -g <CIDR> 2>/dev/null
# ⚠️ OPSEC: Moderate Noise. Common firewall target.

# Scan a full subnet and show only alive hosts (-a)
fping -a -g 10.129.2.0/24 2>/dev/null > live_hosts.txt
```
### Bash One-Liner (Native)
**Description:** Use when no tools are available (Living off the Land).
```shell
# Description: Simple loop to ping a range of IPs sequentially.
# Syntax: for i in $(seq 1 254); do ping -c 1 -W 1 <network>.$i ...; done
# ⚠️ OPSEC: Low/Moderate Noise. Slow and sequential.

for i in $(seq 1 254); do 
    ping -c 1 -W 1 172.16.1.$i >/dev/null && echo "172.16.1.$i UP"
done
```