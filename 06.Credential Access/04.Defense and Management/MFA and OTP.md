# MFA and OTP
## Theory: The MFA Gap
Multi-Factor Authentication (MFA) protects the _login process_, but it rarely protects the _session_ once established.
- **The bypass strategy:** We do not try to guess the 6-digit code. We steal the **Session Cookie** or the **TOTP Secret**.
## 1. Adversary-in-the-Middle (AiTM)
### Evilginx2
**Concept:** You set up a phishing site that proxies traffic between the victim and the real service (e.g., Microsoft 365). When the user enters the MFA code, the real server grants a **Session Cookie**. Evilginx2 captures this cookie.

**Usage:**
1. **Setup Phishlet:** Configure a phishlet for the target (e.g., `outlook`, `okta`).
2. **Lure:** Send the link to the victim.
3. **Capture:**
    ```shell
    # Inside Evilginx console
    sessions
    # Look for the 'tokens' column.
    sessions <id>
    ```
4. **Impersonate:** Import the captured cookies (JSON format) into your browser using an extension like "Cookie-Editor." You are now logged in without needing the MFA code.
## 2. Token Manipulation (TOTP Secrets)
**Context:** Sometimes users save the QR code image or the "Secret Key" (a string like `JBSWY3DPEHPK3PXP`) in a text file or email to "back it up." 
**Exploit:** If you find this string, you can generate valid codes forever.
### Generating Codes (Oathtool)
```shell
# Syntax: oathtool --totp -b <SECRET_STRING>
oathtool --totp -b JBSWY3DPEHPK3PXP
# Output: 843921
```
## 3. Session Hijacking (Pass-the-Cookie)
**Context:** If you have compromised a machine, the user is likely already logged into their MFA-protected services (AWS, Slack, Github). 
**Technique:** Steal the browser cookies database.

**Locations:**
- **Chrome:** `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies`
- **Firefox:** `%APPDATA%\Mozilla\Firefox\Profiles\<random>.default\cookies.sqlite`

**Tools:**
- **Mimikatz:** `dpapi::chrome` (decrypts Chrome cookies using the user's DPAPI master key).
- **WhiteWinterWolf:** `CookieCadger`.