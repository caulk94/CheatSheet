# osTicket Assessment
**Concept:** osTicket is an open-source support ticket system. While vulnerabilities exist (CVEs), its primary value to a Red Teamer is often as a **repository of sensitive information** (credentials in tickets, internal communication) and a pivot point for social engineering. 
**Attack Surface:** User Enumeration, Ticket History Mining, Logic Flaws (Email association).
## 1. Discovery & Fingerprinting
**Goal:** Identify osTicket instances and version information.
### Indicators
- **Cookies:** Look for the session cookie `OSTSESSID`.
- **Footer:** Often contains "Powered by osTicket".
- **URL Structure:** `/login.php`, `/kb/faq.php`.
### Enumeration
- **Version Check:** Check source code or `/setup/install.php` (if accessible).
- **CVE Check:** osTicket < 1.14.1 is vulnerable to **SSRF** (CVE-2020-24881) and authenticated **SQLi**.
## 2. Exploitation: Sensitive Data Exposure (Post-Auth)
**Goal:** Gain access to an agent or user account to mine ticket history.
### Credential Reuse (The "Dehashed" Workflow)
Helpdesk portals are often integrated with LDAP/AD, meaning credentials found in breaches might work here.
1. **Gather Targets:** Use OSINT (LinkedIn, Breaches) to find employee emails.
2. **Search Breaches:** Use tools like `Dehashed` or local dumps to find passwords.    
```shell
# Example Dehashed search
python3 dehashed.py -q inlanefreight.local -p
```
3. **Test Access:** Attempt login on the osTicket portal (`support.target.com`).
    - _Note:_ Try both `username` and `email` formats.
### Ticket Mining (The Goldmine)
Once authenticated (as a User or Agent), search closed tickets.
- **Keywords:** "Password Reset", "VPN", "Credentials", "Login", "Config", "SSH".
- **Scenario:** Support agents often paste temporary passwords directly into the ticket thread. "I've reset your VPN password to `Welcome123!`. Please change it immediately."
    - **Action:** Test this password against the VPN portal (`vpn.target.com`) or SSH.
## 3. Logic Abuse: Email Association
**Concept:** osTicket creates a threadable email address for each ticket (e.g., `940288@support.target.com`). 
**Attack:** If you can register external accounts (e.g., Slack, GitLab) using this ticket-email address:

1. **Open Ticket:** Create a ticket and note the associated email/ID.    
2. **Register External Service:** Sign up for the target's GitLab using the ticket email.
3. **Capture OTP:** The confirmation email from GitLab will be "replied" into the osTicket thread, allowing you to view the confirmation link/OTP and validate the account.