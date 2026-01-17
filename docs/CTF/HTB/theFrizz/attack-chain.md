# Attack Chain - theFrizz

## Current Path
```
Web Enumeration → Gibbon-LMS v25.0.00 Discovery →
Unauthenticated RCE Exploit (gibbonlms_cmd_shell.py) →
Basic Command Shell → Reverse Shell Upgrade (PowerShell Base64) →
Stable Interactive Shell → config.php Enumeration →
Database Credentials (MrGibbonsDB) → MySQL gibbonperson Query →
f.frizzle Hash + Salt Extraction → Hashcat Mode 1420 Cracking →
Domain User Credentials: f.frizzle@frizz.htb / Jenni_Luvs_Magic23
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

## Next Steps (Current Position)

- [ ] Test f.frizzle credentials against SMB (nxc smb)
- [ ] Test f.frizzle credentials against WinRM (nxc winrm → evil-winrm if successful)
- [ ] Test f.frizzle credentials against SSH
- [ ] Enumerate SMB shares with valid credentials
- [ ] Locate and retrieve user.txt flag
- [ ] Enumerate Active Directory for privilege escalation paths (BloodHound)

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
