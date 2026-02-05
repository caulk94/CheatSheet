# FTP
```table-of-contents
```
## Banner Grabbing & Enum_
```shell
# Netcat Banner Grab
nc -nv <IP> 21

# Telnet Banner Grab
telnet <IP> 21

# Nmap - Check Version & Anonymous Login
nmap -sV -sC -p 21 <IP>

# Nmap - Script Trace (Debug what scripts are doing)
nmap -sV -p 21 -sC -A <IP> --script-trace

# Check for Encryption (SSL/TLS)
openssl s_client -connect <IP>:21 -starttls ftp
```
## Active Interaction (Client)
### Recursive Download (LFTP)
```shell
# Connect
lftp -u anonymous,anonymous <IP>

# Inside lftp:
ls           # List files
mirror .     # Download EVERYTHING in current dir recursively
exit
```
### Standard Client (Legacy)
```shell
ftp <IP>
# User: anonymous / Pass: anonymous

# Commands:
ls -R        # Recursive list
binary       # Switch to binary mode (IMPORTANT for executables/images)
get file.txt # Download file
put shell.php # Upload file
```
### Mass Download (Wget)
```shell
# Download all available files via FTP
wget -m --no-passive ftp://anonymous:anonymous@<IP>
```
## Brute Force
```shell
# Hydra
# -l: user | -P: password list | -f: stop on found
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://<IP>

# Hydra (User list + Pass list)
hydra -L users.txt -P passwords.txt ftp://<IP>
```
## Post-Exploitation (Local Enum)
```shell
# Find Config Files
find / -name vsftpd.conf 2>/dev/null
cat /etc/vsftpd.conf | grep -v "#"

# Check Allowed/Denied Users
cat /etc/ftpusers
cat /etc/vsftpd.user_list

# Check Logs (Who connected?)
cat /var/log/vsftpd.log
```
## Default Config
```shell
/etc/vsftpd.conf # vsFTPd Config File
cat /etc/ftpusers # FTPUSERS
```