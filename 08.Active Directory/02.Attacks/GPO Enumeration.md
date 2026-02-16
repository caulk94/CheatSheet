# GPO Enumeration (Reconnaissance)
**Concept:** Group Policy Objects (GPOs) control the settings of computers and users. Enumerating them helps us find:
1. **Restricted Groups:** Who is pushed into the "Local Admins" group via policy?
2. **GPO Permissions:** Can we edit a GPO to push malware to the whole domain?
## 1. Enumerating GPOs
### PowerView
```powershell
# List all GPOs with their readable names
Get-DomainGPO | select displayname
```
### Built-in Cmdlets (RSAT)
```powershell
# Requires Active Directory RSAT tools installed
Get-GPO -All | Select DisplayName
```
## 2. Resolving GPO IDs (GUIDs)
GPOs are often referenced by a GUID (e.g., `{7CA9...}`). You need to resolve this to a human name to understand what it does.
```powershell
# Convert GUID to Name
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```
## 3. Hunting for GPO Abuse (ACLs)
**Goal:** Find GPOs that we (or a group we are in) can modify. If we can modify a GPO linked to an OU, we can execute code on every object in that OU.
```powershell
$sid = Convert-NameToSid "Domain Users"

# Find GPOs where 'Domain Users' have rights
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```
_Look for rights like `WriteProperty`, `GenericWrite`, or `GenericAll`._