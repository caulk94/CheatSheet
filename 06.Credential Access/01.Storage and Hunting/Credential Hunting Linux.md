# Credential Hunting Linux
```table-of-contents
```
## File Enumeration
### Configuration Files
**Search Command:**
```shell
# Find config files excluding standard library paths
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

**Grepping for Credentials:** Once files are identified, search inside them for keywords like `user`, `password`, or `pass`.
```shell
# Search specific file extensions for sensitive strings (ignoring comments)
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```
### Databases
```shell
# Find database files
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```
### Scripts & Notes
- **Scripts:** (`.py`, `.sh`, `.pl`, etc.) often contain hardcoded automation credentials. 
- **Notes:** Users often save credentials in text files in their home directories.
```shell
# Find scripts
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

# Find text files in home directories (excluding dotfiles)
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```
### Cronjobs
- **System-wide:** `/etc/crontab`
- **Hourly/Daily/etc:** `/etc/cron.*`
- **User-specific:** `/var/spool/cron/crontabs/`
```shell
# Check system crontab
cat /etc/crontab

# List all cron directories
ls -la /etc/cron.*/
```
### SSH Keys
```shell
# Find Private Keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

# Find Public Keys (useful for pivoting/identification)
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```
## History & Logs
### Shell History
```shell
# Check bash history for typical patterns
tail -n5 /home/*/.bash*
cat ~/.bash_history | grep -i "pass"
```
### Log Files
**Key Log Locations:**

| **Log File**                      | **Description**                          |
| ----------------------------- | ------------------------------------ |
| `/var/log/syslog`             | Generic system activity.             |
| `/var/log/auth.log`           | Authentication logs (Debian/Ubuntu). |
| `/var/log/secure`             | Authentication logs (RHEL/CentOS).   |
| `/var/log/apache2/access.log` | Web server access logs.              |
| `/var/log/cron`               | Cron job logs.                       |
**Grepping Logs:**
```shell
# Search logs for keywords like "password", "accepted", "session opened"
grep -rE "accepted|session opened|session closed|failure|failed|ssh|password changed|new user|delete user|sudo|COMMAND\=|logs" /var/log/ 2>/dev/null
```
## Memory & Automated Tools
### Mimipenguin
```shell
# Requires sudo/root
sudo python3 mimipenguin.py
```
### LaZagne
- **Browsers:** Firefox, Chrome, Opera. 
- **Sysadmin:** SSH, VNC, Filezilla, AWS.
- **Configuration:** Grub, fstab.
- **Wifi:** Network Manager.
```shell
# Run all modules
python3 laZagne.py all

# Run specific module (e.g., browsers)
python3 laZagne.py browsers
```
## Browser Credentials (Firefox)
**Location:** `~/.mozilla/firefox/<profile_folder>/`
### Manual Decryption (Firefox Decrypt)
[Firefox_decrypt](https://github.com/unode/firefox_decrypt)
```shell
# Usage: python3 firefox_decrypt.py <path_to_profile_optional>
python3 firefox_decrypt.py

# Output Example:
# Website:   https://www.inlanefreight.com
# Username: 'cry0l1t3'
# Password: 'FzXUxJemKm6g2lGh'
```