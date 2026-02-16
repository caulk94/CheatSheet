# People & Employee Enumeration
## 1. LinkedIn Enumeration (Passive)
### Google Dorks (Employees)
**Description:** Identify key personnel (SysAdmins, DevOps) and infer technology stacks from job postings.
```shell
# Find Employees
site:linkedin.com/in/ "Target Company"

# High-Value Targets (Privileged Access)
site:linkedin.com/in/ "Target Company" "System Administrator"
site:linkedin.com/in/ "Target Company" "DevOps"
site:linkedin.com/in/ "Target Company" "HR" (Social Engineering Targets)

# Technology Stack (via Job Descriptions)
site:linkedin.com/jobs "Target Company" "VPN"
site:linkedin.com/jobs "Target Company" "Firewall"
site:linkedin.com/jobs "Target Company" "Active Directory"
```
### CrossLinked (Scraper)
**Install:** `pip3 install crosslinked` or `git clone https://github.com/m8r0wn/CrossLinked` 
**Docs:** [https://github.com/m8r0wn/CrossLinked](https://github.com/m8r0wn/CrossLinked)
```shell
# Description: Scrapes LinkedIn data via search engines (Google/Bing) to generate valid email lists.
# Syntax: crosslinked -f <format> -t <timeout> <company_name>
# ⚠️ OPSEC: Passive (Hits Search Engines, not LinkedIn directly).
python3 crosslinked.py -f '{first}.{last}@target.com' -t 5 target_name
```
## 2. GitHub Recon (Code & Secrets)
### GitHub Search Dorks
**Description:** Search for leaked secrets, keys, or internal infrastructure details within an organization's public repositories.
```shell
# Find Organization Repos
org:"TargetCompany"

# Sensitive Information Hunting
org:"TargetCompany" "password"
org:"TargetCompany" "API_KEY"
org:"TargetCompany" "internal"
org:"TargetCompany" "AWS_ACCESS_KEY_ID"

# Configuration & Key Files
org:"TargetCompany" filename:.env
org:"TargetCompany" filename:id_rsa
org:"TargetCompany" filename:config
```
### Developer Profiling (Manual)
**Description:** Once a developer is identified via LinkedIn:
1. Find their personal GitHub profile.
2. Check **"Dotfiles"** repos (often contain aliases, paths, or local configs).
3. Check **"Issues"** they opened on other projects (reveals software versions/stacks they use).
## 3. Document Metadata Analysis
### Metadata Extraction (Manual)
**Description:** extract metadata (Author, Software Version, Paths) from public documents. 
**Tools:** `wget` (download), `exiftool` (analyze).
```shell
# 1. Download public documents (Recursive, specific extensions)
# ⚠️ OPSEC: Moderate Noise. Looks like a crawler.
wget -r -l1 -A pdf,doc,docx,xls,pptx -P docs/ https://www.target.com

# 2. Extract Usernames & Software Info
# Look for "Author", "Creator", or "Producer" to find username patterns (e.g., jsmith vs john.smith)
exiftool docs/* | grep -E "Author|Creator|Producer"
```
### Metagoofil (Automated)
**Install:** `sudo apt install metagoofil` 
**Docs:** [https://github.com/laramies/metagoofil](https://github.com/laramies/metagoofil)
```shell
# Description: Automates searching, downloading, and extracting metadata from public documents.
# Syntax: metagoofil -d <domain> -t <filetypes> -l <limit> -n <downloads> -o <output_dir>
# ⚠️ OPSEC: Moderate Noise.
metagoofil -d target.com -t pdf,doc,xls -l 20 -n 10 -o docs/ -f results.html
```
## 4. Credential & Username Discovery
### Email Pattern Discovery
**Tools:** [Hunter.io](https://hunter.io), [Phonebook.cz](https://phonebook.cz) 
**Goal:** Determine the standard email format to generate wordlists.
- `{first}.{last}@target.com` (Standard)
- `{f}{last}@target.com` (Common in older AD environments)
### Username List Generation (Bash)
**Description:** Generate custom username lists from a list of full names (`names.txt`).
```shell
# Format: john.smith
awk '{print tolower($1)"."tolower($2)}' names.txt > users_dot.txt

# Format: jsmith
awk '{print tolower(substr($1,1,1))tolower($2)}' names.txt > users_fi.txt
```
### Breach Data Search
**Tools:** [HaveIBeenPwned](https://haveibeenpwned.com), [DeHashed](https://dehashed.com)
```shell
# H8mail (Automated Breach Check)
# Install: pip3 install h8mail
# Syntax: h8mail -t <target_email>
# ⚠️ OPSEC: Passive (Queries APIs/Local DBs).
h8mail -t target@target.com
```