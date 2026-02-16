# Password Mutation & Custom Wordlists
**Concept:** People are predictable. They capitalize the first letter, replace 'a' with '@', and append the current year. 
**Goal:** Instead of bruteforcing every character (which takes centuries), we generate a **Targeted Wordlist** based on the company's website, and then **Mutate** it using standard rules.
## 1. Targeted Wordlist Generation (CeWL)
**Tool:** `CeWL` (Custom Word List generator). 
**Role:** Spiders a target URL and scrapes every word to create a custom dictionary. This captures specific jargon, project names, and employee names that `rockyou.txt` will miss.
```shell
# Basic Usage
cewl https://www.inlanefreight.com -w wordlist.txt

# Advanced Usage
# -d 4: Depth (How many links deep to crawl)
# -m 6: Min word length (Ignore "the", "and", etc.)
# --lowercase: Normalize everything to lowercase
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane_base.txt
```
## 2. Rule-Based Mutation (Hashcat)
**Concept:** Hashcat has a "rule engine" that can take a list of words (like `inlane_base.txt` or `rockyou.txt`) and modify them on the fly.
### Common Rule Syntax
Rules are simple commands that tell Hashcat how to manipulate the string.

| **Function** | **Code** | **Input**        | **Output** |
| ------------ | -------- | ---------------- | ---------- |
| *Nothing*    | `:`      | password         | password   |
| *Lowercase*  | `l`      | Password         | password   |
| *Uppercase*  | `u`      | password         | PASSWORD   |
| *Capitalize* | `c`      | password         | Password   |
| *Append*     | `$`      | password (`$!`)  | password!  |
| *Prepend*    | `^`      | password (`^!`)  | !password  |
| *Substitute* | `s`      | password (`sa@`) | p@ssword   |
| *Reverse*    | `r`      | password         | drowssap   |
### Using Standard Rules (The Easy Way)
Kali Linux comes with optimized rule files in `/usr/share/hashcat/rules/`.
- **`best64.rule`**: The 64 most common mutations. **Start here.**
- **`rockyou-30000.rule`**: Comprehensive.
- **`OneRuleToRuleThemAll.rule`**: Extremely thorough (takes longer).

```shell
# List available rules
ls /usr/share/hashcat/rules/
```
## 3. Creating Custom Rules
**Scenario:** You notice the company uses the year `2023` in many passwords. You want to create a specific rule to append `2023` to every word.

**Create the File (`custom.rule`):**
```shell
:           # 1. Do nothing (Keep original)
c           # 2. Capitalize first letter
$2 $0 $2 $3 # 3. Append '2023'
c $2 $0 $2 $3 # 4. Capitalize AND Append '2023'
sa@         # 5. Swap 'a' for '@'
```
## 4. Generating the Mutated List
**Workflow:**
1. **Input:** Your base wordlist (`inlane_base.txt`).
2. **Action:** Apply rules (`custom.rule` or `best64.rule`).
3. **Output:** Save to a new file (`mutated.txt`) to use with other tools (like Hydra or John).

```shell
# Syntax: hashcat --force <INPUT> -r <RULES> --stdout | sort -u > <OUTPUT>

# Example: Applying best64 to our CeWL list
hashcat --force inlane_base.txt -r /usr/share/hashcat/rules/best64.rule --stdout | sort -u > inlane_mutated.txt
```