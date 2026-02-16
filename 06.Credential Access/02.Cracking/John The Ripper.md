# John the Ripper (The Swiss Army Knife)
**Role:** CPU-based Cracker & Format Converter. 
**Key Insight:** JtR's superpower is the suite of `*2john` tools. These python/perl scripts extract the "hash" from a binary file (like a PDF or SSH key) into a text format that JtR can process.
## 1. The Workflow: Convert -> Crack
To crack files, you must first extract the "hash" metadata.

**Step 1: Conversion (Extract Hash)** Find the appropriate tool (usually installed in `/usr/sbin` or `/usr/share/john/`).
```shell
# General Syntax
<tool> <protected_file> > hash.txt
```

**Step 2: Cracking (Run John)** John usually auto-detects the format from the hash file header.
```shell
# General Syntax
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
## 2. Common Conversion Tools (`*2john`)
Use `locate *2john` to find them all.

| **Target**       | **Tool**       | **Command Example**                                             |
| ---------------- | -------------- | --------------------------------------------------------------- |
| *SSH Keys*     | `ssh2john`     | `python3 /usr/share/john/ssh2john.py id_rsa > ssh.hash`         |
| *ZIP Archives* | `zip2john`     | `zip2john secret.zip > zip.hash`                                |
| *PDF Docs*     | `pdf2john`     | `pdf2john contract.pdf > pdf.hash`                              |
| *Keepass DB*   | `keepass2john` | `keepass2john database.kdbx > keepass.hash`                     |
| *Office Docs*  | `office2john`  | `python3 /usr/share/john/office2john.py Salary.docx > doc.hash` |
| *RAR Archives* | `rar2john`     | `rar2john archive.rar > rar.hash`                               |
## 3. Cracking Modes
### Wordlist Mode (Standard)
**Use Case:** The most common mode. Reads words from a dictionary file.
```shell
# Syntax: john --wordlist=<LIST> <HASH_FILE>
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```
### Single Crack Mode (Context Aware)
**Use Case:** "Smart" guessing. It uses the username, GECOS fields (Full Name), and filename to generate guesses.
- _Example:_ If the user is `admin`, it tries `admin123`, `Admin!`, etc.
```shell
# Note: Requires the hash file to be formatted correctly (user:hash)
john --single hash.txt
```
### Incremental Mode (Brute Force)
**Use Case:** When wordlists fail. It tries every character combination. **Slow.**
```shell
john --incremental hash.txt
```
## 4. Viewing Results
Like Hashcat, John stores cracked passwords in a "pot" file (`~/.john/john.pot`). It will not show the password again if you re-run the crack command.
```shell
# To see the password again, use --show
john --show ssh.hash

# Output:
# id_rsa:supersecret123
```
## 5. Practical Examples
### Cracking an SSH Private Key
**Scenario:** You found `id_rsa` in `/home/user/.ssh/`, but it asks for a passphrase.
```shell
# 1. Convert to hash format
python3 /usr/share/john/ssh2john.py id_rsa > id_rsa.hash

# 2. Crack
john --wordlist=rockyou.txt id_rsa.hash

# 3. View Password
john --show id_rsa.hash
```
### Cracking a ZIP File
**Scenario:** You found a backup `backup.zip` that is password protected.
```shell
# 1. Extract hash
zip2john backup.zip > zip.hash

# 2. Crack
john --wordlist=rockyou.txt zip.hash
```