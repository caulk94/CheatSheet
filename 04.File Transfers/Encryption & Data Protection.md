# Encryption & Data Protection
## Linux Encryption (OpenSSL)
**Concept:** Use ubiquitous OpenSSL to encrypt exfiltrated data or tools before transfer.
### 1. File Encryption (AES-256)
**Description:** Encrypts a file using AES-256-CBC with Salt and PBKDF2 (Password-Based Key Derivation Function 2) for resilience against brute-force. **Syntax:** `openssl enc -aes256 -iter 100000 -pbkdf2 -in <INPUT_FILE> -out <OUTPUT_FILE> -k <PASSWORD>`
- `-aes256`: The encryption cipher.
- `-iter 100000`: Adds computational cost to slow down cracking attempts.
- `-pbkdf2`: Uses a modern key derivation function (better than default).
- `-k`: (Optional) Provide password inline (Caution: visible in history). If omitted, it prompts interactively.

```shell
# Encrypt a sensitive file
# ⚠️ OPSEC: Using -k in CLI leaves the password in ~/.bash_history. Prefer interactive mode.
openssl enc -aes256 -iter 100000 -pbkdf2 -in <SENSITIVE_FILE> -out <ENCRYPTED_FILE> -k <STRONG_PASSWORD>

# Example
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/shadow -out shadow.enc
```
### 2. File Decryption
**Description:** Restore the original file. **Syntax:** `openssl enc -d -aes256 -iter 100000 -pbkdf2 -in <ENCRYPTED_FILE> -out <RESTORED_FILE> -k <PASSWORD>`
```shell
# Decrypt the file
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in <ENCRYPTED_FILE> -out <OUTPUT_FILE> -k <STRONG_PASSWORD>
```
### 3. Base64 Encoding (Text Transfer)
**Description:** If you need to copy-paste the encrypted binary data via a terminal shell, encode it to Base64 first.
```shell
# Encrypt and Encode to Base64 (Single Line)
openssl enc -aes256 -iter 100000 -pbkdf2 -in <INPUT_FILE> -k <PASSWORD> | base64 -w 0 > <OUTPUT_B64_FILE>

# Decode and Decrypt
cat <OUTPUT_B64_FILE> | base64 -d | openssl enc -d -aes256 -iter 100000 -pbkdf2 -k <PASSWORD> -out <RESTORED_FILE>
```
## Windows Encryption (PowerShell)
**Concept:** Windows lacks a native "openssl" equivalent for file encryption. We must define a helper function using .NET classes.
### 1. The Script (Invoke-AESEncryption)
**Action:** Copy-paste this function into your PowerShell session or save it as `Invoke-AESEncryption.ps1`.
```powershell
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
        # IV generation logic would go here for robust security.
        # This script uses specific padding/mode suitable for simple transfer tasks.

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) { Write-Error "File not found!"; break }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) { Write-Error "File not found!"; break }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    return "File decrypted to $outPath"
                }
            }
        }
    }
    End {
        $shaManaged.Dispose(); $aesManaged.Dispose()
    }
}
```
### 2. Usage Examples
#### Encrypt a File
**Syntax:** `Invoke-AESEncryption -Mode Encrypt -Key <PASSWORD> -Path <FILE_PATH>`
```powershell
# Encrypts the file and appends .aes extension
Invoke-AESEncryption -Mode Encrypt -Key "Sup3rS3cur3Key!" -Path .\<SENSITIVE_DATA.docx>
```
#### Decrypt a File
**Syntax:** `Invoke-AESEncryption -Mode Decrypt -Key <PASSWORD> -Path <ENCRYPTED_FILE>`
```powershell
# Decrypts the file and removes .aes extension
Invoke-AESEncryption -Mode Decrypt -Key "Sup3rS3cur3Key!" -Path .\<SENSITIVE_DATA.docx.aes>
```
#### Encrypt Text String (For Copy-Paste)
**Syntax:** `Invoke-AESEncryption -Mode Encrypt -Key <PASSWORD> -Text "<STRING>"`
```powershell
# Returns a Base64 string of the encrypted text
Invoke-AESEncryption -Mode Encrypt -Key "MyKey123" -Text "<ADMIN_PASSWORD>"
```