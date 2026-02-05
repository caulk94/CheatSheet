# Web_Shells
```table-of-contents
```
## Common Web Shells
### Laudanum
- **Location:** `/usr/share/webshells/laudanum/` 
- **Usage:**
    1. Copy shell (e.g., `aspx/shell.aspx`).
    2. **Edit the file:** Add your IP to the allowed list (usually line 59).
    3. Upload to target.
### Antak (ASPX)
- **Location:** `/usr/share/nishang/Antak-WebShell/antak.aspx`
- **Usage:**
    1. Edit the file to set `Username` and `Password`.
    2. Upload to IIS server.
    3. Login and execute PowerShell commands.
### WhiteWinterWolf (PHP)
- **Usage:** Upload to an Apache/Nginx server and navigate to the file.
```shell
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php
```
## Bypassing Upload Restrictions
### Method: Content-Type Spoofing (Burp Suite)
1. **Intercept** the upload request with Burp Suite.
2. Locate `Content-Type: application/x-php`.
3. **Change** it to a safe type: `Content-Type: image/gif` or `image/jpeg`.
4. **Forward** the request.
5. Navigate to the uploaded file to execute it.
## Lab Reference: URL Paths
- **Common IIS Path:** `C:\inetpub\wwwroot`
- **Common Upload Path:** `/files/`, `/uploads/`, `/images/vendor/`
- **Laudanum/Antak access:** `http://<vHost>/files/shell.aspx`