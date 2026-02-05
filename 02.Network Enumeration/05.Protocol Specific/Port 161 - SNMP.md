# SNMP
```table-of-contents
```
## Discovery & Brute Force (Community Strings)
```shell
# OneSixtyOne (Fastest Brute Forcer)
# Checks a list of strings against the IP
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/snmp.txt <IP>

# Hydra (Alternative)
hydra -P /usr/share/wordlists/SecLists/Discovery/SNMP/snmp.txt udp://<IP>:161 snmp
```
## Enumeration & Data Extraction
```shell
# SNMPWalk (Standard tool)
# -v2c: Version 2c | -c: Community String
snmpwalk -v2c -c public <IP>

# SNMP-Check (Highly Recommended - Human Readable)
# Formats output into Process, User, Software, Network tables
snmp-check <IP> -c public

# Braa (Mass scanner for specific OIDs)
# Syntax: braa <community>@<IP>:<OID>
braa public@<IP>:.1.3.6.*
```
## Common OIDs Reference
| **OID**                  | **Description** | **Value**                               |
| ------------------------ | --------------- | --------------------------------------- |
| `1.3.6.1.2.1.1.1`        | SysDesc         | System Description (OS version, Kernel) |
| `1.3.6.1.2.1.1.5`        | SysName         | Hostname                                |
| `1.3.6.1.2.1.25.1.1`     | Uptime          | System Uptime                           |
| `1.3.6.1.2.1.25.4.2.1.2` | Processes       | List of running processes               |
| `1.3.6.1.2.1.25.6.3.1.2` | Software        | List of installed software              |
| `1.3.6.1.4.1.77.1.2.25`  | Users           | Windows Users list                      |
| `1.3.6.1.2.1.6.13.1.3`   | TCP Ports       | Open TCP ports (Netstat)                |
## Dangerous Settings & Write Access
### Critical Configurations
_Check `/etc/snmp/snmpd.conf` if you have shell access._

| **Setting**            | **Description**                                    | **Risk**                   |
| ---------------------- | -------------------------------------------------- | -------------------------- |
| `rwuser noauth`        | Provides full access to the OID tree without auth. | CRITICAL               |
| `rwcommunity <string>` | Provides Read-Write access to the OID tree.        | CRITICAL (RCE)         |
| `rocommunity <string>` | Provides Read-Only access.                         | HIGH (Info Disclosure) |
### Checking Configuration (Local)
```shell
# Read Config
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'

# Look for 'rwcommunity' (Read-Write)
grep "rwcommunity" /etc/snmp/snmpd.conf
```