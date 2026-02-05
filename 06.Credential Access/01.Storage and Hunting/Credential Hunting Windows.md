# Credential Hunting Windows
```table-of-contents
```
# Credential Hunting on Windows
## Key Search Terms
| Category     | Keywords                                             |
| ------------ | ---------------------------------------------------- |
| **Auth**     | `Password`, `Passphrase`, `Passkey`, `Key`, `Login`  |
| **Identity** | `Username`, `User account`, `Creds`, `Credentials`   |
| **Config**   | `configuration`, `dbcredential`, `dbpassword`, `pwd` |
## Automated Discovery (LaZagne)
[LaZagne](https://github.com/AlessandroZ/LaZagne)
**Workflow:**
1. Transfer `lazagne.exe` to the target (via RDP clipboard, SMB, or HTTP). 
2. Execute via CMD or PowerShell.
```powershell
# Run all modules
C:\Users\bob\Desktop> lazagne.exe all

# Run with verbose output (to see what is being checked)
C:\Users\bob\Desktop> lazagne.exe all -vv
```
**Common Findings:**
- Browser passwords (Chrome, Firefox).
- WinSCP / Putty saved sessions.
- WiFi keys.
- RDP saved connections.
## Manual Search (CLI)
### Using `findstr`
**Command Breakdown:**
- `/S`: Searches matching files in the current directory and all subdirectories.
- `/I`: Specifies that the search is not case-sensitive.
- `/M`: Prints only the filename if a file contains a match.
- `/C`: Uses a specified string as a literal search string.
```powershell
# Search for "password" in common file types
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

cd C:\Users\Administrator\Documents; findstr /SIM /C:"password" *.*
```
## Common Locations & High-Value Targets
### System & Domain Artifacts
- **SYSVOL Share:** Look for passwords in scripts or Group Policy Preferences (GPP) (though patched in modern systems, legacy XMLs may exist). 
- **Unattend.xml:** Often contains local admin passwords in cleartext (leftover from installation).
    - `C:\Windows\Panther\`
    - `C:\Windows\Panther\Unattend\`
    - `C:\Windows\System32\sysprep\`
- **AD Description Fields:** Check User or Computer description fields in Active Directory; IT staff sometimes note passwords there.
### User & Application Artifacts
- **Web Configs:** `web.config` files in IIS directories (`C:\inetpub\wwwroot`) often contain DB connection strings.
- **KeePass Databases:** Look for `.kdbx` files. If found, exfiltrate and try to crack the master password.
- **User Documents:**
    - `pass.txt`, `passwords.docx`, `handover.xlsx`.
    - Check Sharepoint drives if mapped.
- **Sticky Notes:** Modern Sticky Notes are stored in a SQLite DB, but older ones are just files.