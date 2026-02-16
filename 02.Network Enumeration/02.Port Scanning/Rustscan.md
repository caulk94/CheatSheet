# Rustscan
**Install:** Download `.deb` from [GitHub Releases](https://github.com/RustScan/RustScan/releases) or `cargo install rustscan` 
**Docs:** [https://github.com/RustScan/RustScan](https://github.com/RustScan/RustScan)
## Operational Usage
**Concept:** A modern wrapper. It uses an ultra-fast port scanner (internal) to find open ports in seconds, then **automatically** pipes them into Nmap for service enumeration. 
**Format:** `rustscan -a <Target> -- <Nmap Flags>`
### 1. The "CTF Standard" (Scan + Enumerate)
**Description:** Finds open ports instantly, then runs Nmap scripts (`-sC`) and version detection (`-sV`) ONLY on those ports. 
**Syntax:** `rustscan -a <IP> -- -sC -sV`
```shell
# ⚠️ OPSEC: High Noise. The initial scan is very aggressive.
# The "--" separator is CRITICAL. Everything after it goes to Nmap.
rustscan -a 10.129.2.15 -- -sC -sV
```
### 2. Discovery Only (No Nmap)
**Description:** Just find the open ports (like Masscan) without running Nmap. 
**Syntax:** `rustscan -a <IP> --queue-size <size>`
```shell
# Just lists open ports (e.g., [80, 443, 22])
rustscan -a 10.129.2.15 --ulimit 5000
```
### 3. Tuning & Performance
**Description:** Adjusting the speed and batch size.
```shell
# -b: Batch size (default 4500) | -t: Timeout (ms)
# Useful for unstable connections where default settings miss ports.
rustscan -a 10.129.2.15 -b 1500 -t 2000 -- -sC -sV
```
### 4. Docker Usage (Alternative Install)
**Description:** If you don't want to install Rust/Cargo locally.
```shell
# ⚠️ OPSEC: Docker networking can sometimes obscure the source IP or complicate VPN routing.
docker run -it --rm --name rustscan rustscan/rustscan:alpine -a 10.129.2.15 -- -sC -sV
```