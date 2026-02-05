# Staff
```table-of-contents
```
## LinkedIn Enumeration
Identify High-Value Targets (SysAdmins, Developers) and technology stacks.
### Google Dorks (Passive)
```shell
# Find Employees
site:linkedin.com/in/ "Target Company"

# Find Specific Roles (High Value)
site:linkedin.com/in/ "Target Company" "System Administrator"
site:linkedin.com/in/ "Target Company" "DevOps"
site:linkedin.com/in/ "Target Company" "HR"

# Identification of Technology Stack via Job Posts
site:linkedin.com/jobs "Target Company"
site:linkedin.com/jobs "Target Company" "VPN"
site:linkedin.com/jobs "Target Company" "Firewall"
```
### Tools
```shell
# CrossLinked (Scrapes LinkedIn via Google/Bing)
# Generates valid email formats based on names found
python3 crosslinked.py -f '{first}.{last}@target.com' -t 5 target_name
```
## GitHub Recon
### GitHub Search Dorks
```shell
# Find Organization
org:"TargetCompany"

# Find Internal Info
org:"TargetCompany" "password"
org:"TargetCompany" "API_KEY"
org:"TargetCompany" filename:.env
org:"TargetCompany" filename:id_rsa
org:"TargetCompany" "internal"
```
### User Enumeration
Check public repositories of identified employees.
1. Identify a developer from LinkedIn.
2. Find their GitHub profile.
3. Check "Dotfiles" repositories (often contain aliases or paths).
4. Check "Issues" they opened on other repos (reveals software versions they use).
## Document Metadata (FOCA / Exiftool)
```shell
# 1. Download public documents (PDF, DOC, DOCX, XLS, PPT)
wget -r -l1 -A pdf,doc,docx,xls,pptx -P docs/ https://www.target.com

# 2. Extract Metadata (Look for 'Author' or 'Creator')
# This often reveals the naming convention (e.g., 'jsmith' or 'john.smith')
exiftool docs/* | grep -E "Author|Creator|Producer"

# 3. Automated Tool (Metagoofil)
metagoofil -d target.com -t pdf,doc,xls -l 20 -n 10 -o docs/ -f results.html
```
## Email Pattern & Credential Discovery
### Email Format Discovery
Use services like Hunter.io or Phonebook.cz to find the pattern.
- `{first}.{last}@target.com` (Most common)
- `{f}{last}@target.com`
- `{first}{l}@target.com`
### Breach Data Search_
```shell
# H8mail (Check local breach or APIs)
h8mail -t target@target.com

# Manual Check
# https://haveibeenpwned.com/
# https://dehashed.com/
```
### Username List Generation
```shell
# Using strict format (requires 'names.txt' list of Full Names)
# names.txt content: John Smith
awk '{print tolower($1)"."tolower($2)}' names.txt > users_dot.txt    # john.smith
awk '{print tolower(substr($1,1,1))tolower($2)}' names.txt > users_fi.txt # jsmith
```