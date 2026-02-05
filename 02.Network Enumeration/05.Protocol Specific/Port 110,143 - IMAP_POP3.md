# IMAP - POP3
```table-of-contents
```
## Command Reference
### POP3 Commands (Port 110/995)
| **Command**           | **Description**                                   |
| ----------------- | --------------------------------------------- |
| `USER <username>` | Identifies the user.                          |
| `PASS <password>` | Authenticates the user.                       |
| `STAT`            | Requests the number of emails and total size. |
| `LIST`            | Lists messages (ID and size).                 |
| `RETR <ID>`       | Retrieves the full email content by ID.       |
| `DELE <ID>`       | Marks an email for deletion.                  |
| `RSET`            | Resets the session (unmarks deleted emails).  |
| `QUIT`            | Closes the connection.                        |
### IMAP Commands (Port 143/993)
| **Command**             | **Description**                     |
| ----------------------- | ----------------------------------- |
| `1 LOGIN <user> <pass>` | Authenticates the user.             |
| `1 LIST "" *`           | Lists all directories/folders.      |
| `1 SELECT INBOX`        | Selects the Inbox to read messages. |
| `1 SEARCH ALL`          | Finds IDs of all messages.          |
| `1 FETCH <ID> BODY[]`   | Reads the entire email body.        |
| `1 FETCH <ID> all`      | Reads headers and metadata.         |
| `1 LOGOUT`              | Closes the connection.              |
## Discovery & Banner Grabbing
```shell
# Nmap - Discovery (Check Plaintext and SSL ports)
sudo nmap -p 110,143,993,995 -sV -sC <IP>

# Manual Banner Grab (Plaintext)
nc -nv <IP> 110
nc -nv <IP> 143

# Manual Banner Grab (SSL/TLS)
openssl s_client -connect <IP>:993
openssl s_client -connect <IP>:995
```
## Authentication & Attacks
### Manual Interaction (Testing Creds)
```shell
# POP3 Login
telnet <IP> 110
USER admin
PASS password
LIST

# IMAP Login (Note the 'A1' tag)
telnet <IP> 143
A1 LOGIN admin password
A2 LIST "" *
```
### Brute Force (Hydra)
```shell
# POP3 Brute Force
hydra -L users.txt -P rockyou.txt pop3://<IP>

# IMAP Brute Force
hydra -L users.txt -P rockyou.txt imap://<IP>
```
## Data Exfiltration (cURL)
```shell
# List Mailboxes (IMAP)
curl -k 'imaps://<IP>' --user <USER>:<PASS>

# Verbose Mode (Debug connection)
curl -k 'imaps://<IP>' --user <USER>:<PASS> -v

# Download Specific Message (via URL path)
# Syntax depends on server, usually folder/ID
curl -k 'imaps://<IP>/INBOX;UID=1' --user <USER>:<PASS>
```
## Post-Exploitation (Dovecot Config)
### Dangerous Settings (Logging)
_Check `/etc/dovecot/dovecot.conf` or `/etc/dovecot/conf.d/`._

| **Setting**                      | **Risk Description**                                     |
| -------------------------------- | -------------------------------------------------------- |
| `auth_debug = yes`               | Enables full logging of authentication debug info.       |
| `auth_debug_passwords = yes`     | **CRITICAL:** Logs the actual passwords sent by clients. |
| `auth_verbose_passwords = plain` | Logs passwords in plain text during failed attempts.     |
| `auth_anonymous_username`        | Defines the username for ANONYMOUS SASL login.           |
### Finding Configuration
```shell
# Find main config
find /etc -name dovecot.conf

# Grep for passwords in logs (if debug was on)
grep -i "pass" /var/log/mail.log
grep -i "pass" /var/log/dovecot.log
```