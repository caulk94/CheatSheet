# Cracking Files & Archives
**Concept:** You have found sensitive files (SSH keys, ZIPs, DOCX), but they are encrypted. 
**Goal:** Extract the "hash" (metadata representing the password) from the file and use offline tools (John the Ripper / Hashcat) to crack it.
## 1. Hunting for Encoded Files
**Goal:** Locate potential high-value targets amidst the noise of the filesystem.
```shell
# Search for Documents & Spreadsheets
# 2>/dev/null: Hide permission errors
# grep -v: Exclude system directories (libraries, fonts)
for ext in $(echo ".xls .xlsx .csv .doc .docx .pdf .zip .rar .kdbx"); do 
    echo -e "\n[+] Searching for: $ext"
    find / -name "*$ext" 2>/dev/null | grep -v "lib\|fonts\|share\|core\|bin"
done
```
### Inspecting SSH Keys
**Context:** An SSH key starting with `-----BEGIN RSA PRIVATE KEY-----` is great, but if it has a passphrase, you can't use it yet.
```shell
# Check for encryption header
head -n 4 /home/user/.ssh/id_rsa

# Look for: "Proc-Type: 4,ENCRYPTED" or "DEK-Info: AES-128-CBC"
# If present, you must crack the passphrase.
```
## 2. Hash Extraction (The 2John Suite)
**Concept:** John the Ripper (JtR) cannot crack a `.docx` file directly. It needs a specific text format containing the hash/salt. **Tools:** Kali Linux includes a suite of python scripts (`*2john`) to convert files.

**Locate the converters:**
```shell
# Find where the scripts are stored
locate *2john*
# Common path: /usr/share/john/
```
### SSH Keys (`ssh2john`)
```shell
# 1. Convert Key to Hash
python3 /usr/share/john/ssh2john.py id_rsa > ssh.hash

# 2. Crack (John)
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```
### Office Documents (`office2john`)
**Targets:** Word, Excel, PowerPoint.
```shell
# 1. Convert Doc to Hash
python3 /usr/share/john/office2john.py Passwords.docx > doc.hash

# 2. Crack (John)
john --wordlist=rockyou.txt doc.hash
```
### PDF Documents (`pdf2john`)
**Note:** Some PDFs use older 40-bit encryption (trivial) while others use AES-256 (hard).
```shell
# 1. Convert PDF to Hash
python3 /usr/share/john/pdf2john.py Contract.pdf > pdf.hash

# 2. Crack (John)
john --wordlist=rockyou.txt pdf.hash
```
### ZIP / RAR Archives (`zip2john`)
```shell
# 1. Convert Archive to Hash
zip2john Backup.zip > zip.hash
rar2john Backup.rar > rar.hash

# 2. Crack (John)
john --wordlist=rockyou.txt zip.hash
```
## 3. BitLocker Volumes (Windows Forensics)
**Context:** You have a full disk image (`.vhd`, `.dd`) or a backup file of a BitLocker drive. 
**Goal:** Extract the Recovery Key or User Password.

**Step 1: Extract Hash (John)**
```shell
# Extract recovery hashes from the image
bitlocker2john -i Backup.vhd > bitlocker.hashes

# Filter for the User Password hash
# $bitlocker$0 is usually the user password
# $bitlocker$1 is usually the recovery key
grep "bitlocker\$0" bitlocker.hashes > target.hash
```

**Step 2: Crack (Hashcat)** **Mode:** `22100` (BitLocker)
```shell
# Crack using GPU
hashcat -m 22100 -a 0 target.hash rockyou.txt -o cracked.txt
```
## 4. OpenSSL Encrypted Archives (Manual Scripting)
**Context:** You find a file like `backup.tar.gz.enc`. Running `file` reveals it was encrypted with OpenSSL. 
**Challenge:** There is no standard "header" to extract a hash from. You must try to _decrypt_ it with every password in your list.

**Identification:**
```shell
file backup.enc
# Output: openssl enc'd data with salted password
```

**The Brute Force Loop (Bash):**
```shell
# Try every password in rockyou.txt
for pass in $(cat rockyou.txt); do 
    # Try to decrypt (-d) using AES-256-CBC (Common default)
    # -k: Password
    # | tar xz: Pipe to tar to verify if it extracts correctly
    openssl enc -aes-256-cbc -d -in backup.enc -k $pass 2>/dev/null | tar xz

    # Check exit code ($?) of the pipe
    if [ $? -eq 0 ]; then
        echo "[+] Success! Password is: $pass"
        break
    fi
done
```