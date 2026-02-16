# Password Managers
## KeePass (`.kdbx`)
**Context:** KeePass is a local password manager. It does not store passwords in the cloud. 
**Target File:** Search for `*.kdbx`. 
**Key Files:** Sometimes KeePass uses a "Key File" (e.g., `key.jpg` or `secret.key`) _in addition_ to a password. You need **both** to open the database.
### Cracking KeePass
```shell
# 1. Extract Hash
# If a keyfile is used, add it: -k <path_to_keyfile>
keepass2john Database.kdbx > keepass.hash

# 2. Crack
john --wordlist=rockyou.txt keepass.hash
# OR
hashcat -m 13400 -a 0 keepass.hash rockyou.txt
```
### KeePass Config (Finding the Key File)
Check the XML config file to see if a key file was used recently.
- **Location:** `%APPDATA%\KeePass\KeePass.config.xml`
## Cloud Managers (1Password / LastPass)
**Context:** These store data in the cloud, but keep a cached local copy for offline access. 
**Strategy:** We generally cannot crack the local database easily (strong encryption). We target the **Memory**.
### Memory Dumping
If the user has the Password Manager unlocked in their browser or desktop app, the keys are in memory.
1. **Dump Process:** Dump the RAM of the browser (`chrome.exe`) or the app (`1Password.exe`).
2. **String Search:** Search the dump for JSON blobs or cleartext passwords.
    ```shell
    # Linux/Strings method on a memory dump
    strings browser_dump.dmp | grep "password"
    ```
## Browser Password Stores
**Chrome/Edge:**
- Stores passwords in `Login Data` (SQLite).
- Encrypted with DPAPI.
- **Exploit:** Use `mimikatz` or `LaZagne` to decrypt using the current user's session.
```powershell
# LaZagne
lazagne.exe browsers -v
```