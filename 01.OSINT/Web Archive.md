# Web Archive
```table-of-contents
```
## Online Resources
| **Service**                 | **URL**                            | **Description**                                                   |
| ----------------------- | ------------------------------ | ------------------------------------------------------------- |
| **Wayback Machine**     | `https://archive.org/web/`     | The largest archive. Browse by date changes.                  |
| **Archive.today**       | `https://archive.ph/`          | Alternative snapshot tool, often bypasses paywalls or blocks. |
| **Library of Congress** | `http://loc.gov/webarchiving/` | Focused on government/official sites.                         |
## Automated Tools (CLI)
### waybackurls
```shell
# Basic Usage
echo "target.com" | waybackurls > urls.txt

# Filter for specific files (e.g., JSON or TXT)
echo "target.com" | waybackurls | grep -E "\.json|\.txt|\.php"
```
### gau (GetAllUrls)
```shell
# Get URLs
gau target.com > gau_urls.txt

# Get URLs and filter for parameters (potential XSS/SQLi)
gau target.com | grep "=" | sort -u > params.txt
```
### waybackrobots
```shell
# Usage
waybackrobots target.com
```
## Useful One-Liners
```shell
# 1. Find potential API keys in old JS files
echo "target.com" | waybackurls | grep "\.js$" | xargs -n1 -I{} curl -s {} | grep -iE "key|token|secret"

# 2. Find interesting parameters for fuzzing
gau target.com | grep "?" | cut -d "?" -f 2 | cut -d "=" -f 1 | sort -u > param_names.txt

# 3. Find backup files
echo "target.com" | waybackurls | grep -E "\.bak|\.old|\.zip|\.sql"
```