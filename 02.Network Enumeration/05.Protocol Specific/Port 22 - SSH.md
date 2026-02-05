# SSH
```table-of-contents
```
## Discovery & Auditing
```shell
# Banner Grabbing (Netcat)
nc -nv <IP> 22

# Nmap - Version & Script Scan
nmap -p 22 -sV -sC <IP>

# SSH Audit (Best tool for configuration analysis)
# Identifies weak ciphers/algorithms
./ssh-audit.py <IP>
```
## Authentication & Connection
```shell
# Standard Connection
ssh <USER>@<IP>

# Force Password Authentication
# Useful if the server keeps offering keys that get rejected
ssh -o PreferredAuthentications=password -v <USER>@<IP>

# Connect using a Private Key
# Permissions MUST be 600 or SSH will refuse it
chmod 600 id_rsa
ssh -i id_rsa <USER>@<IP>

# Connect with older algorithms (Legacy)
# Use this if you get "no matching key exchange method found"
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc <USER>@<IP>
```
## Tunneling & Pivoting
```shell
# Local Port Forwarding (L)
# Access a service on the Target (localhost:3306) via your machine (localhost:3306)
ssh -L 3306:127.0.0.1:3306 <USER>@<TARGET_IP>

# Remote Port Forwarding (R)
# Expose YOUR local service (8000) to the Target (8000)
# Useful to serve exploits/tools to a machine behind a firewall
ssh -R 8000:127.0.0.1:8000 <USER>@<TARGET_IP>

# Dynamic Port Forwarding (D) - SOCKS Proxy
# Creates a SOCKS proxy on your machine (9050).
# Combine with Proxychains to scan the internal network through the SSH host.
ssh -D 9050 <USER>@<TARGET_IP>
```
## Brute Force (Hydra)
```shell
# Brute Force User
hydra -l root -P rockyou.txt ssh://<IP>

# Brute Force SSH Keys
# If you found a folder of keys, check which one works
# Requires a specialized script or loop
for key in *.pub; do ssh -i "$key" user@<IP> "whoami"; done
```
## Post-Exploitation (Local)
### Configuration & Keys
```shell
# Server Config
cat /etc/ssh/sshd_config | grep -v "#" | sed -r '/^\s*$/d'

# Client Config (History of connected hosts)
cat ~/.ssh/known_hosts

# Authorized Keys (Who can log in?)
cat ~/.ssh/authorized_keys

# Private Keys (The Holy Grail)
cat ~/.ssh/id_rsa
```
### Dangerous Settings (sshd_config)
| **Setting**                      | **Description**                       | **Risk**                                |
| ---------------------------- | --------------------------------- | ----------------------------------- |
| `PasswordAuthentication yes` | Allows password login.            | Weak passwords can be brute-forced. |
| `PermitRootLogin yes`        | Allows direct root login.         | If root has a weak pass, game over. |
| `PermitEmptyPasswords yes`   | Allows login with blank password. | **CRITICAL**                        |
| `Protocol 1`                 | Uses legacy encryption.           | Susceptible to MITM.                |
| `StrictModes no`             | Ignores file permission checks.   | Keys might be readable by others.   |