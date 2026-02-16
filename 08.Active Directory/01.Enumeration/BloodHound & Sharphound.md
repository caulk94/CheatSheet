# BloodHound & SharpHound
**Concept:** BloodHound uses graph theory to reveal hidden relationships and attack paths in an Active Directory environment. It answers questions like: _"How can I go from my current low-privilege user to Domain Admin?"_ 
**Components:**
1. **SharpHound:** The data collector (Ingestor). Runs on the victim or via proxy.
2. **BloodHound (GUI):** The visualizer. Runs on your attacker machine.
3. **Neo4j:** The graph database backend.
## 1. Installation & Setup (Kali Linux)
**Note:** BloodHound recently updated to "BloodHound CE" (Community Edition). The installation process on Kali handles the backend setup.
### Step 1: Install
Update your package list and install BloodHound from the official Kali repository:
```shell
sudo apt update && sudo apt install -y bloodhound
```
### Step 2: Configuration
Run the setup script to initialize the Neo4j database and the BloodHound API.
```shell
sudo bloodhound-setup
```
### Troubleshooting: Postgres Collation Mismatch
**Error:** If you see `Postgres has a collation version mismatch`, the cluster version does not match the OS libraries. **Fix:** You must recreate the cluster. **Warning: This deletes existing Postgres data.**
1. **Stop PostgreSQL:** 
```shell
sudo systemctl stop postgresql
```
2. **Delete the old cluster:** (Check your version in `/etc/postgresql/`, usually 15, 16, or 17).
```shell
sudo pg_dropcluster --stop 16 main
```
3. **Create a new cluster:**
```shell
sudo pg_createcluster 16 main --start
```
4. **Re-run Setup:**
```shell
sudo bloodhound-setup
```
### Step 3: Access & Credentials
1. **Initialize Neo4j:**
    - Go to: `http://localhost:7474`
    - Default Creds: `neo4j` / `neo4j`
    - **Action:** Change password to: `neo4jneo4j` (or your preference).
    - _Note:_ Update `/etc/bhapi/bhapi.json` if you change the password later.
2. **Start BloodHound:**
```shell
bloodhound
```
3. **Login to BloodHound GUI:**
    - Go to: `http://127.0.0.1:8080`
    - Initial Creds: `admin` / `admin`
    - **Action:** It will generate a temporary password in the terminal output. Use that to log in, then change the password to something permanent (e.g., `adminAdmin1!`).
## 2. Data Collection (SharpHound)
**Goal:** Gather the data to feed into BloodHound. 
**Tool:** `SharpHound` (C# for Windows) or `BloodHound.py` (Python for Linux/Proxy).
### Method A: SharpHound.exe (From Windows)
**Context:** You have a foothold on a domain-joined Windows machine.
1. **Transfer:** Upload `SharpHound.exe` to the victim.
2. **Execute:**
```powershell
# Standard Collection (Group, LocalAdmin, Session, Trusts)
.\SharpHound.exe -c All

# Stealthier (Avoids 'Session' enumeration which touches every host)
.\SharpHound.exe -c DCOnly
```
3. **Output:** A `.zip` file (e.g., `202301011200_BloodHound.zip`). Exfiltrate this back to Kali.
### Method B: BloodHound.py (From Linux)
**Context:** You are on your Kali machine and have credentials for a domain user. You can run this through a VPN or Proxychains.
```shell
# Syntax: bloodhound-python -d <DOMAIN> -u <USER> -p <PASS> -c All -ns <DC_IP>
bloodhound-python -d inlanefreight.local -u avazquez -p Password123 -c All -ns 172.16.5.5
```
## 3. Analysis (The Attack Graph)
**Import:** Drag and drop the `.zip` file into the BloodHound GUI.
### Key Edge Types (How to Pivot)
When you see a line (Edge) connecting two nodes, here is what it means:

| **Edge Name**           | **Meaning**                                 | **Attack Action**                                   |
| ----------------------- | ------------------------------------------- | --------------------------------------------------- |
| *MemberOf*            | User A is in Group B.                       | Inherit permissions of Group B.                     |
| *AdminTo*             | User A is Local Admin on Computer B.        | RDP/WinRM to Computer B, dump LSASS, steal creds.   |
| *HasSession*          | User A is currently logged into Computer B. | Compromise Computer B -> Steal User A's token/hash. |
| *ForceChangePassword* | User A can reset User B's password.         | Reset password, login as User B.                    |
| *AddMember*           | User A can add members to Group B.          | Add yourself to Group B.                            |
| *GenericAll*          | Full Control.                               | Change password, add to group, modify attributes.   |
### Common Queries (Pre-Built)
Use the "Analysis" tab to run these standard queries:
1. **Find Principals with DLP Rights:** useful to find LAPS readers.
2. **Find Shortest Paths to Domain Admins:** The "Kill Chain."
3. **Find Shortest Paths to High Value Targets:** Shows paths to DA, Backup Admins, etc.
4. **Find Computers with Unsupported OS:** Easy targets for initial compromise (Windows 7/2008).
### Custom Cypher Queries
You can write raw Cypher queries in the bottom bar.
```cypher
// Find all users with "Admin" in the name who are not disabled
MATCH (u:User)
WHERE u.name CONTAINS "ADMIN" AND u.enabled = true
RETURN u
```
#### SQL Server Administration (The Hidden Admin)
**Concept:** SQL Servers are often linked to AD. If a user is a **SysAdmin** on a SQL instance (e.g., via the `SQLAdmin` group), they can execute OS commands on that server.

**BloodHound Query:**
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```