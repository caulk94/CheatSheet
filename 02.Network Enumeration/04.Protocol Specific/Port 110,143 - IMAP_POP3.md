# IMAP & POP3
**Default Ports:**
- **POP3:** 110 (Cleartext), 995 (SSL/TLS) 
- **IMAP:** 143 (Cleartext), 993 (SSL/TLS)

**Key Insight:** These protocols allow you to **read** emails. If you compromise credentials, check these services immediately for sensitive data (password resets, OTPs, internal configs).
## 1. Command Reference (Interaction)
_Note: IMAP requires a "Tag" (e.g., `A1`) before every command._

| **Command**                  | **Protocol** | **Description**                |
| ------------------------ | -------- | -------------------------- |
| `USER <user>`            | POP3     | Identify user.             |
| `PASS <pass>`            | POP3     | Authenticate.              |
| `LIST`                   | POP3     | List messages (ID & Size). |
| `RETR <ID>`              | POP3     | Read full message content. |
| `A1 LOGIN <user> <pass>` | IMAP     | Authenticate.              |
| `A1 LIST "" *`           | IMAP     | List all folders.          |
| `A1 SELECT INBOX`        | IMAP     | Select Inbox context.      |
| `A1 FETCH <ID> BODY[]`   | IMAP     | Read full message body.    |
## 2. Discovery & Banner Grabbing
**Goal:** Check if the service supports cleartext (vulnerable) or requires SSL.
### Cleartext (Port 110, 143)
```shell
# Manual Banner Grab
nc -nv 10.129.2.15 110
nc -nv 10.129.2.15 143
```
### Encrypted (Port 995, 993)
**Critical:** Netcat will hang on SSL ports. Use `openssl`.
```shell
# Connect to POP3S
openssl s_client -connect 10.129.2.15:995 -crlf -quiet

# Connect to IMAPS
openssl s_client -connect 10.129.2.15:993 -crlf -quiet
```
### Automated (Nmap)
```shell
# Scan all mail ports for version and scripts
nmap -p 110,143,993,995 -sV -sC 10.129.2.15
```
## 3. Manual Interaction (Looting Emails)
**Scenario:** You found valid credentials (`admin:password`) and want to read emails manually.
### POP3 Walkthrough (Download Specific Email)
```shell
# 1. Connect
telnet 10.129.2.15 110

# 2. Login
USER admin
PASS password

# 3. List Emails
LIST
# Output: 1 540 (Email ID 1, Size 540 bytes)

# 4. Read Email 1
RETR 1

# 5. Quit
QUIT
```
### IMAP Walkthrough (Read Inbox)
```shell
# 1. Connect (SSL)
openssl s_client -connect 10.129.2.15:993 -crlf -quiet

# 2. Login (Tag A1)
A1 LOGIN admin password

# 3. List Folders
A2 LIST "" *

# 4. Select Inbox
A3 SELECT INBOX

# 5. Read Email Body (ID 1)
A4 FETCH 1 BODY[]

# 6. Logout
A5 LOGOUT
```
## 4. Data Exfiltration (cURL)
**Description:** Use `curl` to script the downloading of emails without an interactive shell. Highly effective for "Smash and Grab".
```shell
# List Mailboxes (IMAPS)
# -k: Ignore SSL errors | -v: Verbose
curl -k 'imaps://10.129.2.15' --user user:password -v

# Download Specific Message (UID 1 from INBOX)
curl -k 'imaps://10.129.2.15/INBOX;UID=1' --user user:password
```
## 5. Brute Force (Hydra)
**Goal:** Guess passwords against the mail service.
```shell
# POP3
hydra -L users.txt -P passwords.txt pop3://10.129.2.15

# IMAP
hydra -L users.txt -P passwords.txt imap://10.129.2.15
```
## 6. Post-Exploitation (Dovecot Config)
**Context:** You have shell access to the mail server. Dovecot is the most common IMAP/POP3 server.
### Sensitive Configuration Files
**File:** `/etc/dovecot/dovecot.conf`

| **Setting**                          | **Risk**                                                  |
| -------------------------------- | ----------------------------------------------------- |
| `auth_debug = yes`               | Logs authentication details (Debugging).              |
| `auth_debug_passwords = yes`     | **CRITICAL:** Logs cleartext passwords of all users.  |
| `auth_verbose_passwords = plain` | Logs cleartext passwords for _failed_ login attempts. |
### Hunting in Logs
**Goal:** Find cleartext passwords left by debug modes.
```shell
# Grep for 'pass' in mail logs
grep -i "pass" /var/log/mail.log
grep -i "pass" /var/log/dovecot.log
```