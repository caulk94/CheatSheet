# Online Hash Crackers (OSINT)
**Concept:** Instead of calculating the hash yourself (Brute Force), you check if someone else has already cracked it (Lookup). 
> [!Warning] OPSEC Alert
> Never upload sensitive client data, PII, or active banking credentials to these sites. Once you search for a hash, it is logged and added to their public database.
## 1. The "Big Three" (Free Databases)
These are the first stops for standard hashes like MD5, SHA1, and NTLM.

|Service|Best For|URL|Notes|
|---|---|---|---|
|**CrackStation**|**MD5, SHA1**|`crackstation.net`|The gold standard. Uses massive pre-computed rainbow tables (190GB+). Instant results.|
|**Hashes.com**|**NTLM, SHA256**|`hashes.com`|Community-driven. You can upload lists and wait for others to crack them (Escrow). Excellent for NTLM.|
|**CMD5**|**MD5, MySQL**|`cmd5.org`|Very old, massive database. Often finds obscure MD5s that CrackStation misses. Captcha heavy.|
## 2. Specialized & Paid Services
Use these when the free rainbow tables fail.

|Service|Focus|URL|Notes|
|---|---|---|---|
|**OnlineHashCrack**|**WPA2, Office**|`onlinehashcrack.com`|Cloud-based cracking for WPA handshakes and Office docs. Paid/Freemium.|
|**GPTHash**|**NTLM**|`gpthash.com`|Specifically optimized for Windows NTLM hashes.|
|**HashKiller**|**General**|`hashkiller.io`|(Currently active/inactive varies). Historically very strong forum-based cracking.|
## 3. Encoding vs. Encryption (CyberChef)
**Crucial Distinction:** Sometimes a string isn't hashed, it's just **encoded** (Base64, Hex, Rot13). You don't "crack" encoding; you decode it.
**Tool:** **CyberChef** (The "Cyber Swiss Army Knife").
- **URL:** `gchq.github.io/CyberChef/`
- **Usage:** Paste the string in "Input". Drag "Magic" from the left pane to the recipe. It usually auto-detects the encoding.
## 4. Google Hacking (Dorks)
Sometimes the hash itself is indexed by Google because it appeared in a pastebin or forum.
```txt
site:pastebin.com "5f4dcc3b5aa765d61d8327deb882cf99"
"5f4dcc3b5aa765d61d8327deb882cf99" password
hash 5f4dcc3b5aa765d61d8327deb882cf99
```