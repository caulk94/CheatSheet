# Application Discovery & Enumeration
**Concept:** Before attacking specific applications (WordPress, Tomcat, etc.), we must identify _what_ is running on the network. 
**Goal:** Rapidly screenshot and categorize web services on large ranges (e.g., `/24`, `/16`). 
**Tools:** EyeWitness, Aquatone.
## 1. EyeWitness
**Role:** Takes a list of URLs (or an Nmap XML output) and generates an HTML report with screenshots, headers, and default credential checks.
### Installation
```shell
sudo apt install eyewitness
# Or clone: git clone https://github.com/FortyNorthSecurity/EyeWitness
```
### Execution (From Nmap XML)
**Prerequisite:** Run an Nmap scan with output (`-oX`).
```shell
# 1. Nmap Scan (Discovery)
nmap -p 80,443,8000,8080,8443 --open -oX web_discovery.xml 10.10.10.0/24

# 2. EyeWitness Execution
# --web: HTTP/HTTPS mode
# -x: Input XML file
# -d: Output directory
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

**Output Analysis:** Open `report.html` in the output directory. Look for:
- Default pages (Tomcat, IIS, Apache).
- Login portals (Citrix, VPN, CMS).
- Error pages disclosing versions.
## 2. Aquatone
**Role:** A Go-based alternative to EyeWitness. Very fast, uses headless Chrome/Chromium for rendering. Useful for piping from other tools.
### Installation
```shell
# Download binary
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
sudo mv aquatone /usr/local/bin/
```
### Execution (Pipeline)
Aquatone accepts URLs via STDIN, making it perfect for chaining with tools like `cat` or `httpx`.
```shell
# 1. Create a list of targets (URLs)
cat targets.txt | aquatone -out ./aquatone_report

# 2. Or pipe directly from Nmap grepable output (gnmap)
cat scan.gnmap | grep http | cut -d " " -f 2 | aquatone -out ./aquatone_report
```
**Output:** Generates `aquatone_report.html` grouping similar screenshots together (clustering), which helps identify mass deployments of the same application.****