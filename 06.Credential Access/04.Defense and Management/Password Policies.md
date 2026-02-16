# Password Policies
## Importance of Policy Enumeration
Before starting a **Password Spray** attack, you **MUST** know the lockout policy.
- **Lockout Threshold:** How many failed attempts before the account locks? (e.g., 5 attempts).
- **Observation Window:** How long until the counter resets? (e.g., 30 minutes).
- **Strategy:** If the threshold is 5, spray only 2 passwords every 35 minutes.
## 1. Enumeration from Windows (CMD)
**Tool:** `net accounts` 
**Requirement:** Any valid domain user (even low privilege).
```powershell
C:\> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    5  <-- CRITICAL
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
```
## 2. Enumeration from Linux (CrackMapExec)
**Tool:** `crackmapexec` / `NetExec` 
**Requirement:** Valid credentials.
```shell
# Syntax: crackmapexec smb <DC_IP> -u <User> -p <Pass> --pass-pol
crackmapexec smb 172.16.5.5 -u guest -p "" --pass-pol
```
## 3. Fine-Grained Password Policies (FGPP)
**Context:** Domain Admins often have _stricter_ policies than standard users. The `net accounts` command only shows the default domain policy. FGPP overrides this. 
**Tool:** PowerView (PowerShell).
```powershell
# Get all policies
Get-DomainPolicy

# Check for specific granular policies
Get-DomainObject -SearchBase "CN=Password Settings Container,CN=System,DC=inlanefreight,DC=local"
```