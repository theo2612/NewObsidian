# Attack Chain - theFrizz

## Complete Attack Path (ROOT)
```
Web Enumeration → Gibbon-LMS v25.0.00 Discovery →
Unauthenticated RCE Exploit (gibbonlms_cmd_shell.py) →
Basic Command Shell → Reverse Shell Upgrade (PowerShell Base64) →
Stable Interactive Shell → config.php Enumeration →
Database Credentials (MrGibbonsDB) → MySQL gibbonperson Query →
f.frizzle Hash + Salt Extraction → Hashcat Mode 1420 Cracking →
Domain User Credentials (f.frizzle) → Kerberos SSH Access →
Hidden File Enumeration → Recycle Bin Discovery →
wapt-backup-sunday.7z Extraction → waptserver.ini Password (Base64) →
m.schoolbus Credentials → SSH as m.schoolbus →
BloodHound Analysis → WriteGPLink Permission Discovery →
Manual GPO Creation (theo-rev2) → Link to Domain (DC=frizz,DC=htb) →
SharpGPOAbuse Scheduled Task → PowerShell Reverse Shell Payload →
GPO Propagation (gpupdate /force) → Reverse Shell as NT AUTHORITY\SYSTEM →
Root Flag: 35a0ed09f6d1e66eb5906ade78c5ae8a
```

## Branch Points

### After Web Enumeration
- **Option A:** Test default credentials on Gibbon login
- **Option B:** Search for Gibbon v25 CVEs ✓ **CHOSEN**
- **Option C:** Directory fuzzing for other apps
- **Why B:** Pre-auth exploits are highest value, fastest path to foothold

### After Basic RCE Shell
- **Option A:** Use unstable command shell for enumeration
- **Option B:** Upgrade to reverse shell for stability ✓ **CHOSEN**
- **Option C:** Upload netcat/tools for better shell
- **Why B:** Reverse shell provides interactivity needed for MySQL queries without upload requirements

### After Reverse Shell
- **Option A:** Upload enumeration scripts (winPEAS, etc.)
- **Option B:** Use built-in commands for enumeration ✓ **CHOSEN**
- **Option C:** Immediately try to escalate privileges
- **Why B:** Built-in commands avoid AV detection, sufficient for finding config files

### After Database Credentials
- **Option A:** Enumerate all database tables systematically
- **Option B:** Target user tables (gibbonperson) ✓ **CHOSEN**
- **Option C:** Look for other databases
- **Why B:** User credentials are highest value for lateral movement/privilege escalation

### After f.frizzle Password Cracked
- **Option A:** Test against Gibbon login
- **Option B:** Test against Windows services (SMB, WinRM, SSH) **NEXT STEP**
- **Option C:** Enumerate LDAP with credentials
- **Why B:** Domain user credentials likely grant access to Windows services, potential for shell access

## Privilege Escalation Method: GPO Abuse via WriteGPLink

**Permissions:**
- m.schoolbus is member of **Group Policy Creator Owners**
- m.schoolbus has **WriteGPLink** permission over DC=frizz,DC=htb

**Attack Steps:**
1. Created GPO manually: `New-GPO -name "theo-rev2"`
2. Linked to domain root: `New-GPLink -Name "theo-rev2" -target "DC=frizz,DC=htb"`
3. Used SharpGPOAbuse to inject malicious scheduled task:
   - Task executes PowerShell reverse shell payload (base64 encoded)
   - Payload connects back to 10.10.14.89:6969
   - Task runs as NT AUTHORITY\SYSTEM on DC
4. Forced GPO refresh: `gpupdate /force`
5. GPO propagated to DC, scheduled task executed
6. Received reverse shell as SYSTEM
7. Retrieved root flag from C:\Users\Administrator\Desktop\root.txt

**Why This Works:**
- WriteGPLink allows linking GPOs to OUs (including domain root)
- GPOs linked to domain root apply to ALL computers, including DCs
- Scheduled tasks in GPOs execute as SYSTEM
- Immediate execution via scheduled task (no reboot required)

## Tools Used
- **Reconnaissance:** nmap, curl
- **Exploitation:** gibbonlms_cmd_shell.py (GitHub)
- **Shell Upgrade:** revshells.com (PowerShell #3 Base64), nc listener
- **Credential Extraction:** type (PowerShell), mysql.exe
- **Password Cracking:** hashcat mode 1420 (SHA256 + salt)
- **Wordlist:** rockyou.txt

## Key Decisions
1. **Prioritized web over AD enumeration** - Apache + PHP on DC is unusual, high attack surface
2. **CVE research before brute force** - Version identified (v25.0.00), searched exploitdb
3. **Shell upgrade for stability** - Basic shell functional but reverse shell needed for MySQL operations
4. **Targeted gibbonperson table** - User credentials > other data for progression
5. **Email as domain username** - f.frizzle@frizz.htb → likely valid domain account

## Credentials Obtained
See `loot/credentials.md` for full credential tracking.
