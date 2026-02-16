# Shell Spawning & Stabilization
**Context:** You have caught a reverse shell, but it's "dumb". It doesn't support interactive commands like `su`, `sudo`, or text editors (`nano`/`vim`). 
**Goal:** Spawn a TTY (Teletype) to get a fully interactive session.
## 1. Language-Based Spawning
**Technique:** Use installed interpreters to spawn a robust `/bin/bash` process.
### Python (The Gold Standard)
```shell
# Check available version
which python python3

# Python 2
python -c 'import pty; pty.spawn("/bin/bash")'

# Python 3
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
### Perl
```shell
perl -e 'exec "/bin/sh";'
```
### Ruby
```shell
ruby: exec "/bin/sh"
```
### Lua
```shell
lua: os.execute('/bin/sh')
```
## 2. Binary Abuse (GTFOBins)
**Technique:** If interpreters are restricted, abuse standard Linux utilities to break out of restricted environments.
### Script (Best Native Option)
```shell
# Records a session, effectively spawning a new shell
script /dev/null -c bash
```
### AWK
```shell
awk 'BEGIN {system("/bin/sh")}'
```
### Find
```shell
# Execute shell on current directory
find . -exec /bin/sh \; -quit
```
### Vim
```shell
# Escape from Vim to Shell
:set shell=/bin/sh
:shell

# Or from CLI
vim -c ':!/bin/sh'
```
## 3. Upgrading to Full TTY (The Magic Sequence)
**Context:** This turns a fragile Netcat connection into a full SSH-like session. You can use Tab Completion, Clear Screen, and CTRL+C safely.

**Step 1: Spawn Bash (Inside Remote Shell)**
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Step 2: Background the Shell (Inside Remote Shell)**
- Press `CTRL + Z` 
- _Result: You are back in your local Kali terminal._

**Step 3: Configure Local Terminal (Inside Local Kali)**
```shell
# Tell your terminal to pass raw input keys through
stty raw -echo; fg
```
- _Note: When you hit `fg` and Enter, it might look like nothing happened. Type `reset` and hit Enter._

**Step 4: Final Configuration (Inside Remote Shell)**
```shell
# 1. Set terminal type (fixes clear screen)
export TERM=xterm

# 2. Set Shell (fixes some output issues)
export SHELL=bash

# 3. Fix Rows/Columns (Optional - for text editors)
# Check local size with: stty size
stty rows 38 columns 116
```
