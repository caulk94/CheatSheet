# Cloud Resources
```table-of-contents
```
## Cloud Infrastructure Identification (CNAME)_
```shell
# Check CNAME records for cloud providers
# Look for: amazonaws.com, cloudapp.net, herokuapp.com, github.io
for i in $(cat subdomainlist); do 
    host $i | grep "alias for"
done

# Output Example:
# assets.target.com is an alias for target-assets.s3.amazonaws.com.
```
## Google Dorks (Public Buckets & Blobs)
### AWS S3 Buckets
```shell
site:s3.amazonaws.com "target"
site:amazonaws.com "target"
inurl:s3.amazonaws.com "target"
```
### Azure Blob Storage
```shell
site:blob.core.windows.net "target"
site:azure.microsoft.com "target"
```
### Google Cloud & Drive
```shell
site:googleapis.com "target"
site:drive.google.com "target"
site:docs.google.com "target"
```
## Source Code Analysis (Grepping)
```shell
# 1. Download source (if not already done)
wget -r -l2 -P source_code/ https://www.target.com

# 2. Grep for S3 Buckets
grep -rE "s3\.amazonaws\.com|[a-zA-Z0-9._-]+\.s3\.amazonaws\.com" ./source_code/

# 3. Grep for Azure Blobs
grep -rE "[a-zA-Z0-9]+\.blob\.core\.windows\.net" ./source_code/

# 4. Grep for Google Cloud Storage
grep -rE "storage\.googleapis\.com" ./source_code/
```
## GrayHatWarfare (Public Buckets Search)
```shell
# Search Query Syntax
target keywords filetype:pdf
target keywords filetype:conf
target keywords filetype:sql
```
## Hunting Leaked Keys (Source Code & Git)
```shell
# AWS Access Key ID (AKIA...)
grep -rE "AKIA[0-9A-Z]{16}" .

# AWS Secret Key
grep -rE "(?i)aws_secret_access_key" .

# Generic API Keys / Tokens
grep -rE "(?i)(api_key|access_token|secret_key)" .

# Searching specifically for Private Keys
grep -rE "-----BEGIN RSA PRIVATE KEY-----" .
grep -rE "-----BEGIN OPENSSH PRIVATE KEY-----" .
```
## Tools (Cloud Enumeration)
```shell
# Cloud Enum (Multi-cloud)
python3 cloud_enum.py -k target -k target_dev -k target_corp

# AWS CLI (If you found credentials)
# List bucket contents
aws s3 ls s3://bucket-name --no-sign-request
```
## Domain.Glass / ViewDNS
- URL: `https://domain.glass/target.com`
- URL: `https://viewdns.info/iphistory/?domain=target.com`