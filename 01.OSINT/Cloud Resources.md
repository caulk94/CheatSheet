# Cloud Infrastructure & Resources
## 1. Passive Discovery (DNS & Dorks)
### CNAME Identification
**Description:** Checks subdomains for CNAME records pointing to known cloud providers (e.g., `herokuapp.com`, `amazonaws.com`, `azure.microsoft.com`). 
**Syntax:** `host -t CNAME <subdomain>`
```shell
# Example: Bash loop to check a list of subdomains
# ⚠️ OPSEC: Low Noise (DNS traffic).
for sub in $(cat subdomains.txt); do host -t CNAME $sub | grep "alias for"; done
```
### Google Dorks (Public Assets)
**Description:** Passive identification of exposed buckets and blobs via search engines.
```shell
# AWS S3 Buckets
site:s3.amazonaws.com "target-name"
site:amazonaws.com "target-name"

# Azure Blob Storage
site:blob.core.windows.net "target-name"

# Google Cloud & Drive
site:googleapis.com "target-name"
site:drive.google.com "target-name"
```
### GrayHatWarfare (Public Buckets DB)
**Description:** Search engine for open public buckets. 
**URL:** [https://grayhatwarfare.com](https://grayhatwarfare.com)
```shell
# Syntax: <domain/keyword> filetype:<extension>
target.com filetype:config
target.com filetype:sql
target.com filetype:pem
```
## 2. Automated Enumeration
### Cloud_Enum
**Install:** `git clone https://github.com/initstring/cloud_enum && pip3 install -r cloud_enum/requirements.txt` 
**Docs:** [https://github.com/initstring/cloud_enum](https://github.com/initstring/cloud_enum)
```shell
# Description: Multi-cloud (AWS, Azure, GCP) enumeration tool using keywords.
# Syntax: python3 cloud_enum.py -k <keyword>
# ⚠️ OPSEC: High Noise. Generates significant HTTP traffic.
python3 cloud_enum.py -k target_corp -k target_dev
```
## 3. Source Code Analysis (Secret & Asset Hunting)
### Preparation: Fetch Source Code
```shell
# Description: Recursively download web assets for local grepping.
# Syntax: wget -r -l<depth> -P <directory> <url>
# ⚠️ OPSEC: Moderate Noise. Looks like a scraper/crawler.
wget -r -l2 -P ./source_code/ https://www.target.com
```
### Grep: Cloud Assets
**Description:** Search local source code for references to cloud storage endpoints.
```shell
# AWS S3 Buckets
grep -rE "s3\.amazonaws\.com|[a-zA-Z0-9._-]+\.s3\.amazonaws\.com" ./source_code/

# Azure Blobs
grep -rE "[a-zA-Z0-9]+\.blob\.core\.windows\.net" ./source_code/

# Google Cloud Storage
grep -rE "storage\.googleapis\.com" ./source_code/
```
### Grep: Leaked Credentials & Keys
**Description:** specific regex patterns to identify hardcoded API keys and private keys.
```shell
# AWS Access Key ID (Starts with AKIA)
grep -rE "AKIA[0-9A-Z]{16}" .

# AWS Secret Access Key (Case insensitive)
grep -rE "(?i)aws_secret_access_key" .

# Generic API Tokens (api_key, access_token, secret_key)
grep -rE "(?i)(api_key|access_token|secret_key)" .

# RSA & SSH Private Keys
grep -rE "-----BEGIN RSA PRIVATE KEY-----" .
grep -rE "-----BEGIN OPENSSH PRIVATE KEY-----" .
```
## 4. Cloud Interaction
### AWS CLI
**Install:** `sudo apt install awscli` 
**Docs:** [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/)
```shell
# Description: Interact with discovered open S3 buckets without authentication.
# Syntax: aws s3 ls s3://<bucket_name> --no-sign-request
# ⚠️ OPSEC: Moderate Noise. Your IP will be logged in the bucket's access logs.
aws s3 ls s3://target-assets-dev --no-sign-request

# Description: Recursively copy bucket contents to local machine.
# Syntax: aws s3 cp s3://<bucket_name> <local_path> --recursive --no-sign-request
aws s3 cp s3://target-assets-dev ./loot/ --recursive --no-sign-request
```
## 5. Online Lookups
- **Domain.Glass:** `https://domain.glass/target.com` (Whois/DNS History)
- **ViewDNS IP History:** `https://viewdns.info/iphistory/?domain=target.com`