# LDAP
## What is LDAP?
**LDAP** is a protocol used to access and manage directory information. Think of a "directory" not just as a folder, but as a **hierarchical data store** optimized for reading data. It organizes network resources—such as users, groups, computers, and printers—into a tree-like structure.
### Key Characteristics
- **Platform-Independent:** Runs over TCP/IP and SSL, making it compatible with Windows, Linux, and macOS.
- **Standardized:** Based on the X.500 standard for directory services.
- **Centralized:** Acts as a single source of truth for authentication and asset management.
## Strengths & Weaknesses

| **Pros**                                                                     | **Cons**                                                                            |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **Efficient:** Fast queries due to lean language and non-normalized storage. | **Complex:** Difficult for many developers to configure and secure correctly.       |
| **Global Naming:** Ensures unique entries across independent directories.    | **Unencrypted by Default:** Traffic is cleartext unless wrapped in SSL/TLS (LDAPS). |
| **Flexible:** Supports custom attributes and schemas.                        | **Injection Risks:** Vulnerable to query manipulation if input isn't sanitized.     |
## LDAP vs. Active Directory (AD)
It is crucial to distinguish between the **protocol** and the **service**.
- **LDAP** is the **language/protocol** used to speak to the directory.
- **Active Directory** is the **directory service (database)** itself, created by Microsoft.

| **Feature**       | **LDAP**              | **Active Directory**          |
| ----------------- | --------------------- | ----------------------------- |
| `Type`          | Protocol              | Directory Server Application  |
| `Compatibility` | Open & Cross-platform | Proprietary (Windows-centric) |
| `Schema`        | Flexible/Customizable | Predefined (Strict)           |
| `Auth`          | Simple Bind, SASL     | Kerberos (primary), NTLM      |
## How LDAP Works: The Client-Server Model
LDAP operates on a client-server architecture. The client sends a request (encoded in ASN.1) over TCP/IP (usually port 389 or 636), and the server processes it.
### The Conversation
1. **Session Connection:** Client connects to the server.
2. **Request:** Client specifies the action (e.g., `bind` to log in, `search` to find a user).
    - **Parameters:** Includes the **Distinguished Name (DN)**, search scope, and filters.
3. **Processing:** Server looks up the directory tree.
4. **Response:** Server returns the result code (Success/Fail) and requested data (Attributes/Values).
### Practical Example: `ldapsearch`
Administrators use the `ldapsearch` tool to query the database manually.
```shell
ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
```
- `-H`: Server URL.
- `-D`: Bind DN (Who are you logging in as?).
- `-w`: Password.
- `-b`: Base DN (Where do you want to start searching?).
- `(...)`: The search filter.
## LDAP Injection
Just like SQL Injection, **LDAP Injection** occurs when an application inserts unsafe user input directly into an LDAP query. If the input is not sanitized, an attacker can manipulate the query logic.
### The Mechanism
Special characters are used to alter the query structure:
- `*` (Wildcard: matches anything)
- `|` (Logical OR)
- `&` (Logical AND)
### Attack Scenario: Authentication Bypass
Imagine a login form that constructs this query: `(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))`
**1. The Attack:** The attacker enters `*` into the username field.
**2. The Resulting Query:** `(&(objectClass=user)(sAMAccountName=*)(userPassword=dummy))`
**3. The Outcome:** Because `*` matches **any** username, the LDAP server finds the first user in the directory (often the Administrator) and logs the attacker in, ignoring the password check or validating the first half of the AND statement as true depending on the logic implementation.
## Practical Enumeration Example
In a penetration test, you might start with an **Nmap** scan to identify LDAP services.
```shell
nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229
```

**Results Analysis:**
- **Port 80 (HTTP):** A web login portal is running.
- **Port 389 (LDAP):** `OpenLDAP` is running.