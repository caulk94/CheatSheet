# OpenVAS
```table-of-contents
```
## Management (GVM)
```shell
# Initial Setup (Run once, takes a long time)
sudo gvm-setup

# Check Setup (Diagnostic)
sudo gvm-check-setup

# Start Services
sudo gvm-start

# Stop Services
sudo gvm-stop

# Update Feeds (NVT, SCAP, CERT)
sudo greenbone-feed-sync --type GVMD_DATA
sudo greenbone-feed-sync --type SCAP
sudo greenbone-feed-sync --type CERT
```
## User Management
```shell
# Create an Admin User
sudo runuser -u _gvm -- gvmd --create-user=<USER> --password=<PASSWORD> --role=Admin

# Reset Password
sudo runuser -u _gvm -- gvmd --user=<USER> --new-password=<PASSWORD>
```
## Usage Note
1. **Port:** `https://127.0.0.1:9392`
2. **Target:** Define the target hosts.
3. **Task:** Create a new task linking the target and a scan config (e.g., "Full and fast").
