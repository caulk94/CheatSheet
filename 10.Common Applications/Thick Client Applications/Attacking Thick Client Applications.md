# Attacking Thick Client Applications
## 1. Information Gathering & Static Analysis
Thick clients often contain hardcoded secrets, connection strings, or vulnerable logic within the binary.
- **Tools:**
    - **CFF Explorer / Detect It Easy:** Identify file types, packers, and protections.
    - **Strings:** Extract ASCII and Unicode strings to find URLs, credentials, or API keys.
    - **Decompilers:**
        - **.NET:** `dnSpy` (Code viewing, editing, debugging).
        - **Java:** `JD-GUI`, `JADX` (Decompile JAR/APK files).
        - **Native:** `Ghidra`, `IDA Pro` (Disassembly and decompilation).
- **Process Monitoring:**
    - Use `ProcMon` (Windows) to observe file system, registry, and network activity.
    - _Example:_ Identifying temporary files created by an executable that might contain decoded secrets or configuration data.
## 2. Network Traffic Analysis
Thick clients communicate with backend servers, often using HTTP/HTTPS or custom protocols.
- **Proxying Traffic:**
    - **Burp Suite:** Configure the thick client to use Burp as a proxy (may require installing the Burp CA certificate in the OS trust store).
    - **Echo/Hosts Modification:** If the client doesn't respect system proxy settings, modify `C:\Windows\System32\drivers\etc\hosts` to point the target domain to your attacking machine (running a listener or proxy).
- **Packet Capture:** Use `Wireshark` or `TCPView` to analyze non-HTTP traffic or identify destination ports and protocols.
## 3. Client-Side Attacks & Modification
Since the client resides on the attacker's machine, it can be manipulated to bypass controls.
- **Patching/Recompilation:**
    - **Java:** Decompile (`JD-GUI`), modify source code (e.g., bypass path traversal filters or change connection ports), recompile (`javac`), and repackage (`jar -cmf`).
        - _Bypass Signing:_ Remove `META-INF` signature files (`.RSA`, `.SF`) and hashes from `MANIFEST.MF` to run modified JARs.
    - **.NET:** Use `dnSpy` to edit methods (IL instructions) and save the modified module.
- **Memory Manipulation:**
    - Use debuggers (`x64dbg`) or instrumentation tools (`Frida`) to hook functions, inspect memory for decrypted secrets, or bypass authentication checks at runtime.
## 4. Server-Side Attacks via Thick Client
The thick client is just an interface; the backend is often vulnerable to standard web attacks.
- **SQL Injection:**
    - Identify input fields sent to the database.
    - _Mechanism:_ Thick clients might perform client-side hashing but fail to sanitize inputs used in backend queries.
    - _Exploitation:_ Use `UNION SELECT` injections to forge user objects if the application constructs sessions based on query results.
- **Path Traversal:**
    - If the client requests files from the server, intercept the request or modify the client logic to request arbitrary paths (e.g., `../../../../etc/passwd` or config files).
- **Command Injection:** Check for inputs passed to system shells on the server.
## 5. Scenario: Exploiting Java Thick Client
1. **Recon:** Identify the client connects to a wrong port/host.
2. **Traffic Manipulation:** Update `hosts` file to redirect traffic to the attacker; modify client config (`beans.xml`) to correct ports.
3. **Decompilation:** Extract `jar`, decompile with `JD-GUI` to understand logic (e.g., `showFiles` method).
4. **Path Traversal:** Modify the client code to send `..` instead of the hardcoded folder, rebuild the jar, and access sensitive server files (`fatty-server.jar`).
5. **SQL Injection:** Analyze server code (`FattyDbSession.class`). Identify `UNION` based SQLi in the login function. Modify client to send a matching plaintext password and inject a forged admin user via the username field.