# Nessus
**Role:** Automated Vulnerability Scanner. **Key Insight:** A **"Credentialed Scan"** (providing SSH/SMB creds) is 10x more valuable than a remote scan. It allows Nessus to log in and check local registry keys/packages rather than just guessing based on banners.
## 1. Management & Setup
**Goal:** Manage the background service and plugin updates.
### Service Management
```shell
# Start the Service (Web Server)
sudo systemctl start nessusd.service

# Check Status (Ensure it's active)
sudo systemctl status nessusd.service

# Stop Service (Save resources when not in use)
sudo systemctl stop nessusd.service
```
### Manual Update (CLI)
**Context:** The web GUI update often hangs or fails. Use the CLI for reliability.
```shell
# Update Plugins and Core Software
sudo /opt/nessus/sbin/nessuscli update --all

# Recompile Plugins (Fixes "Plugin Feed Failure" or corruption)
sudo /opt/nessus/sbin/nessuscli update --plugins-only
```
### User Management (CLI)
**Context:** You forgot the web login password.
```shell
# Change Password for an existing user
sudo /opt/nessus/sbin/nessuscli chpasswd <username>

# List Users
sudo /opt/nessus/sbin/nessuscli lsuser
```
## 2. Operational Workflow (Web GUI)
**URL:** `https://localhost:8834` 
**Note:** Ignore the SSL warning (Self-signed cert).
### Step 1: Policy Creation
- **Basic Network Scan:** Safe for most environments. Checks open ports and services. 
- **Advanced Scan:** Allows tuning (e.g., disable "Paranoid" checks to avoid crashing legacy services).
- **Web App Tests:** **Disable** these in a general network scan. They are slow and noisy. Use Burp Suite for web apps instead.
### Step 2: Authentication (Credentialed Scanning)
**Critical:** This converts the scan from a "Guess" to an "Audit".
- **Windows:** Add `Domain\User` and `Password` (SMB).
- **Linux:** Add `root` (or sudo user) and `SSH Key/Password`.
- **Why?** Without creds, Nessus only sees "Port 80 is open". With creds, it sees "Apache 2.4.49 is installed and vulnerable to Path Traversal".
### Step 3: Launch & Monitor
- **Targets:** Can be a single IP (`10.129.2.15`), a range (`10.129.2.1-50`), or a CIDR (`10.129.2.0/24`).
## 3. Common Findings Analysis
**Goal:** Prioritize the 100+ pages of results.

| **Severity**   | **Description**                                                             | **Action**                                                                           |
| ---------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| *Critical* | Remote Code Execution (RCE), Default Creds, Buffer Overflow (MS17-010). | **Exploit Immediately.** These are your entry points.                            |
| *High*     | Privilege Escalation, SQL Injection, Local File Inclusion.              | **Verify Manually.** Automated SQLi detectors often give false positives.        |
| *Medium*   | SMB Signing Disabled, SSL Weak Ciphers (Sweet32/Poodle).                | **Report Item.** Rarely leads to a shell directly, but useful for NTLM relaying. |
| *Info*     | Service Detection, Traceroute, DNS Names.                               | **Recon Data.** Use this to build your network map.                              |
## 4. Export & Integration
**Goal:** Get data out of Nessus for reporting or exploitation.
### Export Formats
- **.nessus:** XML format. **Best for importing** into other tools (Metasploit, Faraday). 
- **.html:** Human readable. Good for quick checks.
- **.csv:** Spreadsheet. Good for sorting thousands of hosts by vulnerability.
### Metasploit Integration
**Context:** Import scan results to auto-populate hosts in Metasploit.
```shell
# In msfconsole:
db_import /home/kali/Downloads/scan_results.nessus

# View imported hosts
hosts

# View imported vulns
vulns
```