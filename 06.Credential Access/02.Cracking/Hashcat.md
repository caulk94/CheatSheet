# Hashcat (GPU Cracking)
**Role:** The World's Fastest Password Cracker. 
**Requirement:** Works best with a dedicated GPU (NVIDIA/AMD). Running on a VM without GPU passthrough will be slow (CPU mode).
## 1. Basic Syntax
```shell
# Syntax: hashcat -m <HASH_TYPE> -a <ATTACK_MODE> <HASH_FILE> <WORDLIST>

# Example (Cracking NTLM with RockYou):
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

| **Flag**     | **Description**                                                                        |
| -------- | ---------------------------------------------------------------------------------- |
| `-m`     | **Hash Type.** The numeric identifier for the algorithm (e.g., 1000 = NTLM).       |
| `-a`     | **Attack Mode.** How to generate candidates (0 = Dictionary, 3 = Mask/Brute).      |
| `-o`     | **Output File.** Where to save cracked passwords.                                  |
| `--show` | **Show Cracked.** Display passwords already cracked in the `hashcat.potfile`.      |
| `-O`     | **Optimized.** Enable optimized kernels (Faster, but limits password length > 32). |
| `-w 3`   | **Workload.** High performance profile (Uses more GPU power).                      |
## 2. Common Hash Modes (`-m`)
**Identify your hash type first!** Use tools like `hashid` or `name-that-hash` if you are unsure.

| **Category**  | **Hash Name**             | **Mode ID (`-m`)** | **Source**                           |
| --------- | --------------------- | -------------- | -------------------------------- |
| *Windows* | *NTLM*                | `1000`         | SAM / NTDS.dit                   |
|           | *NetNTLMv2*           | `5600`         | Responder / SMB Relay            |
|           | *Kerberos 5 (TGS)*    | `13100`        | Kerberoasting                    |
|           | *Kerberos 5 (AS-REP)* | `18200`        | AS-REP Roasting                  |
| *Linux*   | *SHA-512 (Unix)*      | `1800`         | `/etc/shadow` (Modern)           |
|           | *MD5 (Unix)*          | `500`          | `/etc/shadow` (Legacy)           |
|           | *bcrypt*              | `3200`         | Web Apps / Linux                 |
| *Web*     | *MD5*                 | `0`            | Databases (Old)                  |
|           | *SHA-256*             | `1400`         | Databases                        |
| *WiFi*    | *WPA/WPA2*            | `22000`        | Captured Handshake (PMKID/EAPOL) |
| *Docs*    | *MS Office 2013*      | `9600`         | Word/Excel                       |
|           | *PDF (1.7 Level 8)*   | `10700`        | PDF Documents                    |
| *Archive* | *7-Zip*               | `11600`        | .7z Archives                     |
|           | *WinZip*              | `13600`        | .zip Archives                    |
|           | *RAR5*                | `13000`        | .rar Archives                    |
| *Crypto*  | *Bitcoin Wallet*      | `11300`        | wallet.dat                       |
## 3. Attack Modes (`-a`)
### Mode 0: Dictionary Attack (Straight)
**Use Case:** Trying a list of real words.
```shell
# Standard RockYou run
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
```
### Mode 0 + Rules (Best Practice)
**Use Case:** Dictionary words are mutated (e.g., `password` -> `P@ssw0rd1!`). **Rules Location:** `/usr/share/hashcat/rules/`
```shell
# Use the 'best64' rule engine (Fast & Effective)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Use 'OneRuleToRuleThemAll' (Thorough - takes longer)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```
### Mode 3: Mask Attack (Brute Force)
**Use Case:** The password is short or follows a strict pattern (e.g., "Summer2023"). **Syntax:** `?l` (lower), `?u` (upper), `?d` (digit), `?s` (special), `?a` (all).
```shell
# Brute force 7 lower-case characters
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?l?l?l

# Pattern: "Summer" + 4 digits (Summer2023)
hashcat -m 1000 -a 3 hashes.txt Summer?d?d?d?d

# Pattern: Upper + Lower + Lower + Lower + Digit + Digit + Special (Pass12!)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?d?d?s
```
## 4. Viewing Results
**Context:** Hashcat stores cracked hashes in a "potfile" (`~/.hashcat/hashcat.potfile`) so it doesn't crack them twice.
```shell
# Display results from the potfile
# You MUST run the exact same command you used to crack, but append --show
hashcat -m 1000 hashes.txt --show

# Output format:
# 8846F7EAEE8FB117AD06BDD830B7586C:Password123
```
## 5. Practical Examples
### Cracking Windows NTLM (SAM)
```shell
# Fast dictionary attack with rules
hashcat -m 1000 -a 0 -w 3 ntlm.txt rockyou.txt -r rules/best64.rule
```
### Cracking Linux SHA-512 (Shadow)
```shell
# Slow hash! Use GPU optimization (-O) if possible
hashcat -m 1800 -a 0 -O shadow.txt rockyou.txt
```
### Cracking Kerberoast Ticket (TGS)
```shell
# Use mode 13100
hashcat -m 13100 -a 0 krb5_tgs.txt rockyou.txt
```
### Cracking WiFi (WPA2)
**Note:** The capture file (`.cap`) must be converted to hashcat format (`.hc22000`) first. Use `hcxpcapngtool` for this.
```shell
# Crack WiFi
hashcat -m 22000 -a 0 wifi.hc22000 rockyou.txt
```