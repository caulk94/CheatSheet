# OpenVAS (Greenbone Vulnerability Management)
**Role:** Open Source Vulnerability Scanner. 
**Key Insight:** Unlike Nessus, OpenVAS is completely free and uncensored. However, the initial sync (`gvm-setup`) can take **hours** to download the feed data (NVTs, SCAP, CERT). Plan accordingly.
## 1. Management & Setup (The Pain Point)
**Goal:** Initialize the database, download feeds, and start the web interface.
### Initial Setup (Run Once)
**Warning:** This process downloads gigabytes of data. Do not interrupt it.
```shell
# Setup Wizard (Database, Feeds, Users)
sudo gvm-setup

# Check Installation (Diagnostics)
# Run this if the web interface doesn't load.
sudo gvm-check-setup
```
### Service Control
**Goal:** Start/Stop the background services to save RAM (OpenVAS is heavy).
```shell
# Start Services
sudo gvm-start

# Stop Services
sudo gvm-stop

# Open Web Interface
# URL: https://127.0.0.1:9392
# Default User: admin (Password generated during setup)
```
### Feed Updates (Maintenance)
**Goal:** Keep vulnerability definitions current.
```shell
# Update Network Vulnerability Tests (NVT)
sudo greenbone-feed-sync --type NVTs

# Update SCAP & CERT Data
sudo greenbone-feed-sync --type SCAP
sudo greenbone-feed-sync --type CERT
```
## 2. User Management (CLI)
**Context:** You lost the randomly generated password from `gvm-setup`.
```shell
# Create a New Admin User
sudo runuser -u _gvm -- gvmd --create-user=admin_user --password=StrongPass123! --role=Admin

# Reset Existing User Password
sudo runuser -u _gvm -- gvmd --user=admin --new-password=NewStrongPass123!
```
## 3. Usage Workflow (Web GUI)
**Port:** `9392` (Default)
1. **Targets:**
    - Navigate to _Configuration > Targets_.
    - Create a new target (IP range, single host, or list).
    - **Credentialed Scan:** Add SSH/SMB credentials here for deeper inspection (highly recommended).
2. **Tasks (The Actual Scan):**
    - Navigate to _Scans > Tasks_.
    - Create a new task.
    - **Scan Config:** Select "Full and fast" (Standard) or "System Discovery" (Recon only).
    - **Target:** Select the target created in Step 1.
3. **Reports:**
    - Navigate to _Scans > Reports_.
    - Click on the completed scan date.
    - **Download:** Export as PDF (Executive Summary) or XML (Technical Import).