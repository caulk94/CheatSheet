# ELF & DLL Examination
## ELF Executable Examination
If you encounter a Linux binary that interacts with a service (e.g., a database checker), it likely contains a connection string. If the source code is unavailable, we can use **GDB (GNU Debugger)** with **PEDA** to inspect the memory during execution.
### Identifying the Connection String
Running the binary may show it attempting to connect to a service. By disassembling the `main` function in GDB, we can look for calls to network or database functions.
1. **Load the binary:** `gdb ./octopus_checker` 
2. **Disassemble the main function:** `disas main`
3. **Find the API call:** Look for calls like `SQLDriverConnect` or `connect`.
4. **Set a breakpoint:** Set a breakpoint at the address of the connection call.
5. **Inspect registers:** Once the breakpoint is hit, examine the registers (typically `RDX` or `RSI` in x64) to see the string passed to the function.
```ini
# Example GDB output showing a revealed connection string
RDX: 0x7fffffffda70 ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=username;PWD=password;")
```
## DLL File Examination
On Windows systems, `.dll` (Dynamic Link Library) files often house shared logic for connecting to internal APIs or databases. Many modern DLLs are **.NET assemblies**, which do not compile to machine code but rather to **Intermediate Language (CIL)**. This makes them easy to decompile back into readable source code.
### Decompiling with dnSpy
If a file metadata check suggests the file is a .NET assembly, you can use **dnSpy** to reverse-engineer it.
1. **Open the DLL:** Drag and drop the `.dll` file into dnSpy.
2. **Navigate the Tree:** Look through the namespaces and classes. Logic for database connections is often found in classes named `Controller`, `Database`, or `Config`.
3. **Identify Credentials:** Inspect methods that initialize connections. You may find hardcoded SQL connection strings, hardcoded API keys, or logic that points to other internal services.
### OPSEC Warning
- **Execution:** Running unknown binaries to debug them should always be done in a **sandboxed environment**. Malicious or poorly coded binaries can crash systems or trigger alerts.
- **Metadata:** Tools like `strings` or `exiftool` should be used first for passive analysis before resorting to active debugging.