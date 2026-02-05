# Cracking Files & Archives
```table-of-contents
```
## Hunting for Encoded Files
```shell
# Search for spreadsheets, documents, PDFs, and presentations
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
### SSH Keys
```shell
# Find Private Keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

# Check header for encryption
cat /home/user/.ssh/id_rsa
# Output example: DEK-Info: AES-128-CBC... (Requires cracking)
```
## Hash Extraction (The *2John Suite*)
**Locate available scripts:**
```shell
locate *2john*
```
### SSH Keys
```shell
# Extract hash
python3 /usr/share/john/ssh2john.py SSH.private > ssh.hash

# Crack
john --wordlist=rockyou.txt ssh.hash
```
### Office Documents (Word/Excel/PowerPoint)
```shell
# Extract hash
python3 /usr/share/john/office2john.py Protected.docx > doc.hash

# Crack
john --wordlist=rockyou.txt doc.hash
```
### PDF Documents
```shell
# Extract hash
python3 /usr/share/john/pdf2john.py Protected.pdf > pdf.hash

# Crack
john --wordlist=rockyou.txt pdf.hash
```
### ZIP Archives
```shell
# Extract hash
zip2john Archive.zip > zip.hash

# Crack
john --wordlist=rockyou.txt zip.hash
```
## BitLocker Volumes
**Step 1: Extract Hash**
```shell
# Extract hashes from the VHD or image file
bitlocker2john -i Backup.vhd > backup.hashes

# Filter for the User Password hash (usually $bitlocker$0)
grep "bitlocker\$0" backup.hashes > target.hash
```

**Step 2: Crack with Hashcat** Use Mode **22100** for BitLocker.
```shell
# Syntax: hashcat -m 22100 <hash_file> <wordlist>
hashcat -m 22100 target.hash rockyou.txt -o cracked.txt
```
## OpenSSL Encrypted Archives
**Identification:**
```shell
file Archive.gzip
# Output: openssl enc'd data with salted password
```

**Brute Force Loop:** This loop iterates through a wordlist, attempting to decrypt the file. If `tar` succeeds (exit code 0), the password is correct.
```sh
for i in $(cat rockyou.txt); do 
    openssl enc -aes-256-cbc -d -in Archive.gzip -k $i 2>/dev/null | tar xz
    
    # Check if a file was successfully extracted
    if [ $? -eq 0 ]; then
        echo "Success! Password is: $i"
        break
    fi
done
```