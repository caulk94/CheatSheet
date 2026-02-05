# Password Mutation & Custom Wordlists
```table-of-contents
```
## Credential Stuffing
[DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
## Rule-Based Mutation with Hashcat
### Common Rule Syntax
[Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

| **Function** | **Description**                                 | **Example Input**    | **Example Output** |
| -------- | ------------------------------------------- | ---------------- | -------------- |
| `:`      | Do nothing                                  | password         | password       |
| `l`      | Lowercase all letters                       | Password         | password       |
| `u`      | Uppercase all letters                       | password         | PASSWORD       |
| `c`      | Capitalize first letter, lowercase the rest | password         | Password       |
| `sXY`    | Substitute all instances of X with Y        | password (`sa@`) | p@ssword       |
| `$!`     | Append an exclamation mark                  | password         | password!      |
### Creating a Custom Rule File
```python title:custom.rule
:           # Original word
c           # Capitalize
so0         # Substitute 'o' with '0'
c so0       # Capitalize AND Substitute 'o' with '0'
sa@         # Substitute 'a' with '@'
$!          # Append '!'
$! c        # Append '!' AND Capitalize
```
### Generating the List
```shell
# Syntax: hashcat --force <input_list> -r <rule_file> --stdout | sort -u > <output_list>

caulk@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```
### Using Standard Rules
Hashcat comes with optimized rule files located in `/usr/share/hashcat/rules/`.
- **`best64.rule`**: Highly recommended for quick wins. It contains the 64 most common password mutations.
- **`rockyou-30000.rule`**: A comprehensive set derived from the RockYou breach.
```shell
# List available rules
ls /usr/share/hashcat/rules/
```
## Targeted Wordlist Generation (CeWL)
### CeWL Usage
```shell
# Basic Usage
cewl <url> -w <output_file>

# Advanced Example
# -d 4: Depth of spidering (4 links deep)
# -m 6: Minimum word length (6 characters)
# --lowercase: Convert found words to lowercase
# -w: Output file
caulk@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```
### Workflow Integration
1. **Spider** the target site with `CeWL` to create `base.list`.
2. **Mutate** `base.list` using `Hashcat` with `best64.rule`.
3. **Crack** using the resulting `mutated.list`.