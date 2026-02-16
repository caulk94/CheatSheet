# Credentialed Domain Enumeration (From Windows)
**Context:** You are operating _inside_ the network using a compromised Windows host (C2 or RDP).
## 1. PowerView / SharpView
**Role:** Detailed AD reconnaissance without RSAT tools.
```powershell
# Get Current User Info
Get-DomainUser -Identity mmorgan

# Find Local Admins on a Machine
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# Find Users with SPNs (Kerberoasting Targets)
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

# Map Domain Trusts
Get-DomainTrustMapping
```
## 2. Native Active Directory Module
**Context:** If RSAT is installed (or if you import the DLL), this is OPSEC safe as it uses Microsoft signed binaries.
```powershell
# Import
Import-Module ActiveDirectory

# Get Domain Info
Get-ADDomain

# Get All Users with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Enumerate Groups
Get-ADGroup -Filter * | select name
Get-ADGroupMember -Identity "Backup Operators"
```
## Phase 05: Post-Exploitation - Credential Hunting
We have covered:
1. **Pillaging:** Finding local secrets (LaZagne, Findstr, Snaffler).
2. **Domain Recon (Linux):** CME, BloodHound, Impacket.
3. **Domain Recon (Windows):** PowerView, AD Module.