# The Kerberos Double Hop Problem
**Concept:** Kerberos authentication works by default for **one hop**.
1. **Hop 1:** You authenticate from your Attack Machine to `Server A`. The DC gives `Server A` a service ticket for _itself_. `Server A` trusts you.
2. **The Failure (Hop 2):** You are now on `Server A`. You try to access `Server B`. `Server A` does not have your TGT (Ticket Granting Ticket) to show to the DC to request access for `Server B`. It cannot prove who you are to the second server.

**Symptoms:**
- You can access `Server A` fine.
- Running `dir \\ServerB\C$` from `Server A` fails.
- Running Active Directory modules (like PowerView) on `Server A` fails to query the DC.
## 1. Diagnosis
Verify if you are suffering from a Double Hop issue.

**Check 1: Empty Ticket Cache** Run `klist` inside your remote session. If it returns no tickets or only a self-referential ticket, you cannot authenticate further.
```powershell
[DEV01]: PS C:\Users\backupadm\Documents> klist

# Result:
# Current LogonId is 0:0x12345
# Cached Tickets: (0)  <-- PROBLEM. No TGT to forward.
```

**Check 2: Access Denied on Valid Creds** You know `backupadm` is a Domain Admin, but `Get-DomainUser` returns "Access Denied".
## 2. Workaround #1: Pass Credential Explicitly
**Concept:** Instead of relying on the (missing) cached Kerberos ticket, we manually build a `PSCredential` object inside the remote session and pass it to the command. This forces the command to start a _new_ authentication flow using the password/hash provided.

**Steps:**
1. **Enter Session:** Connect to the first hop.
```shell
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
```
2. **Create Credential Object:** Inside the session, recreate the credential.
```powershell
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
```
3. **Execute with Credential:** Use the `-Credential` flag (supported by most PowerView/AD cmdlets).
```powershell
Import-Module .\PowerView.ps1
Get-DomainUser -SPN -Credential $Cred | select samaccountname
```
## 3. Workaround #2: Register PSSession Configuration (The "RunAs" Fix)
**Concept:** We configure the intermediate server (`DEV01`) to automatically treat incoming connections to a specific endpoint as a specific user _locally_. This allows the server to act as that user directly, creating a fresh logon session with a valid TGT.

**Steps:**
1. **Register Configuration (One-time setup on Hop 1):** This requires Admin rights on `DEV01`.
```powershell
# Run this on DEV01
Register-PSSessionConfiguration -Name "BackupAdminSession" -RunAsCredential "INLANEFREIGHT\backupadm" -Force
```
2. **Connect using Configuration:** From your attacker machine, connect to the specific configuration name.
```powershell
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName "BackupAdminSession"
```
3. **Verify:** Now, `klist` should show a valid TGT, and you can hop to other servers.
```powershell
[DEV01]: PS C:\> klist
[DEV01]: PS C:\> Get-DomainUser -SPN
```
## 4. Workaround #3: Credential Guard & Restricted Admin
_Note: If "Restricted Admin" mode is enabled, or Credential Guard is active, you cannot forward TGTs even if you try. You must use resource-based constrained delegation or the explicit credential method above._