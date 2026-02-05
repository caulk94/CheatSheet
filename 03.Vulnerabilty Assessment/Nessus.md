# Nessus
```table-of-contents
```
## Management & Setup
```shell
# Start the Service
sudo systemctl start nessusd.service

# Check Status
sudo systemctl status nessusd.service

# Update Plugins (Manual)
# Run this if the GUI update fails or is stuck
sudo /opt/nessus/sbin/nessuscli update --all
```
## Scanning Workflow
1. **Access:** Open `https://localhost:8834`.
2. **Policies:** Create a "Basic Network Scan" (Safe) or "Advanced Scan" (Custom).
3. **Authentication:** Add SSH/SMB credentials for a "Credentialed Scan" (Critical for accurate patch verification).
4. **Launch:** Run against the target IP range.
## Common Findings Analysis
| **Severity**   | **Description**                                              | **Action**                                              |
| ---------- | -------------------------------------------------------- | --------------------------------------------------- |
| `Critical` | Remote Code Execution, Default Creds, Exploit Available. | Exploit immediately or verify manually.             |
| `High`     | Privilege Escalation, SQL Injection, Traversal.          | Verify manually.                                    |
| `Medium`   | SMB Signing Disabled, SSL Weak Ciphers.                  | Note for reporting, usually not an immediate shell. |
| `Info`     | Service detection, Traceroute.                           | Use for further enumeration.                        |