# SMB
```table-of-contents
```
## Discovery & Null Session
```shell
# Nmap Discovery
sudo nmap <IP> -sV -sC -p 139,445

# SMBClient - List Shares (Null Session)
# -N: No password | -L: List
smbclient -N -L //<IP>

# SMBMap - Permissions Check
# Useful to see if you have Read/Write access immediately
smbmap -H <IP> -u "null"

# CrackMapExec - Enumeration
# Checks domain, hostname, and signing status
crackmapexec smb <IP> -u '' -p '' --shares
```
## RPC Client (Manual Enum)
```shell
# Connect with Null Session
rpcclient -U "" <IP>

# --- Inside RPC Client Prompt ---
srvinfo          # Server Information
enumdomusers     # List Users
enumdomgroups    # List Groups
querydominfo     # Domain Info
netshareenumall  # List Shares
queryuser <RID>  # Get detailed info on a user (RID is hex, e.g., 0x3e8)
querygroup <RID> # Get group info
```
### RID Cycling (Bash One-Liner)
```shell
# Cycles RIDs from 500 to 1100 and cleans output
for i in $(seq 500 1100); do 
    rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""
done
```
## Automated Enumeration
```shell
# Enum4Linux-ng (Modern Python version)
# Runs standard checks + RID cycling + Share enum
./enum4linux-ng.py <IP> -A

# Impacket Samrdump
# Dumps system hives and user info via SAMR
samrdump.py <IP>
```
## Interaction & Downloading
### SMBClient (CLI Access)
```shell
# Connect to a specific share
smbclient //<IP>/<SHARE_NAME> -N

# --- Inside SMB Prompt ---
ls              # List files
get file.txt    # Download file
recurse ON      # Enable recursive mode (for directories)
prompt OFF      # Turn off confirmation for mget
mget * # Download everything
```
### Mounting (Local Access)
```shell
# Create mount point
mkdir /mnt/share

# Mount (Null Session)
mount -t cifs //<IP>/<SHARE_NAME> /mnt/share -o user=,password=

# Mount (With Credentials)
mount -t cifs //<IP>/<SHARE_NAME> /mnt/share -o user=USERNAME,password=PASSWORD,domain=DOMAIN
```
## Post-Exploitation (Local Only)
```shell
# Read Samba Configuration (Find shares/paths)
cat /etc/samba/smb.conf | grep -v "#\|;"

# Check Connection Status
smbstatus

# Check Database (secrets, etc)
pdbedit -L -v
```