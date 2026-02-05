# John The Ripper
```table-of-contents
```
## Cracking Modes
### Single Crack Mode
```shell
john --format=<hash_type> <hash_or_hash_file>
```
### Wordlist Mode
```shell
john --wordlist=<wordlist_file> --rules <hash_file>
```
### Incremental Mode
```shell
john --incremental <hash_file>
```
## Cracking Protected Files
To crack files (like SSH keys, PDFs, Zip archives), JTR requires the file to be converted into a hash format that it can understand. This is a two-step process:
1. **Extract the hash** using a specific `*2john` tool. 
2. **Crack the hash** using `john`.
### General Workflow
```shell
# Step 1: Convert file to hash
<tool> <file_to_crack> > file.hash

# Step 2: Crack the hash
john --wordlist=<wordlist.txt> file.hash
```
### Example: Cracking a PDF
```shell
# Convert PDF to hash
pdf2john server_doc.pdf > server_doc.hash

# Crack the hash
john server_doc.hash
```
### Common Conversion Tools
These tools are usually located in `/usr/sbin/`, `/usr/bin/`, or `/usr/share/john/`. You can find them using `locate *2john*`.

| **Tool**                    | **Description**                                       |
| ----------------------- | ------------------------------------------------- |
| `pdf2john`              | Converts PDF documents                            |
| `ssh2john`              | Converts SSH private keys (id_rsa, etc.)          |
| `mscash2john`           | Converts MS Cash hashes                           |
| `keychain2john`         | Converts macOS keychain files                     |
| `rar2john`              | Converts RAR archives                             |
| `pfx2john`              | Converts PKCS#12 files (.pfx, .p12)               |
| `truecrypt_volume2john` | Converts TrueCrypt volumes                        |
| `keepass2john`          | Converts KeePass databases (.kdbx)                |
| `vncpcap2john`          | Converts VNC PCAP capture files                   |
| `putty2john`            | Converts PuTTY private keys (.ppk)                |
| `zip2john`              | Converts ZIP archives                             |
| `hccap2john`            | Converts WPA/WPA2 handshake captures              |
| `office2john`           | Converts MS Office documents (.docx, .xlsx, etc.) |
| `wpa2john`              | Converts WPA/WPA2 handshakes                      |