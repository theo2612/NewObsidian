# Attack Chain - Puppy

## Complete Attack Path (PWNED - Both Flags)
```
Initial creds (levi.james) → SMB enum → BloodHound collection →
HR has GenericWrite on Developers → bloodyAD add member →
levi.james in Developers → Access DEV share →
Found recovery.kdbx (KDBX4) → Compiled bleeding-jumbo john →
Cracked master password (liverpool) → Extracted 5 credentials →
ant.edwards (Senior Devs, GenericAll over adam.silver) →
bloodyAD set password adam.silver → Password123! →
STATUS_ACCOUNT_DISABLED → bloodyAD msldap enableuser →
evil-winrm as adam.silver → USER FLAG →

Privilege Escalation:
Enumeration (no ACLs, no Windows privs) → Found C:\Backups\ →
site-backup-2024-12-30.zip → nms-auth-config.xml.bak →
steph.cooper / ChefSteph2025! → evil-winrm as steph.cooper →
DPAPI enumeration (credential blobs + master keys found) →
dpapi.py decrypt master key with password →
dpapi.py decrypt credential blob with master key →
steph.cooper_adm / FivethChipOnItsWay2025! →
evil-winrm as steph.cooper_adm (Domain Admin) →
ROOT FLAG → DCSync dump all hashes → COMPLETE
```

## Branch Points

### After BloodHound Analysis
**Chose:** Use GenericWrite (HR → Developers) to add levi.james to Developers
**Alternative 1:** Could have searched for GPO control first
**Alternative 2:** Could have attempted password spraying before ACL abuse

### After Finding KeePass Database
**Chose:** Compile bleeding-jumbo john for KDBX 4.0 support
**Result:** Successfully cracked master password `liverpool`, extracted 5 credentials
**Alternative 1 (not needed):** Try password guessing with kpcli import
**Alternative 2 (not needed):** Extract and analyze KeePass MSI for embedded creds
**Alternative 3 (for future):** CVE-2023-32784 memory dump after getting shell

### After Extracting KeePass Credentials
**Chose:** Test credentials in order: adam.silver, ant.edwards first (BloodHound priority)
**Result:** Both accounts disabled despite valid passwords, but ant.edwards has SMB access
**Alternative 1 (skipped):** Test remaining credentials (jamie.williams, Steve Tucker, Samuel Blake)
**Alternative 2 (not needed):** Password spray all 5 passwords against all domain users

### After Finding Disabled Accounts
**Chose:** Use ant.edwards's GenericAll over adam.silver to reset password and enable account
**Result:** Successfully changed password and enabled account
**Attempts before success:**
1. Attempted targetedKerberoast.py (failed - Kerberos issues)
2. Attempted net rpc password change (failed - syntax/permission issues)
3. Used bloodyAD set password (SUCCESS)
4. Discovered STATUS_ACCOUNT_DISABLED after password change
5. Used bloodyAD msldap enableuser (SUCCESS)
6. evil-winrm login successful, user flag captured

### After Getting WinRM Shell
**Current task:** Privilege escalation to Administrator/SYSTEM
**Options to explore:**
- Check BloodHound for adam.silver's outbound ACL permissions
- Enumerate local privileges (SeBackupPrivilege, SeImpersonatePrivilege, etc.)
- Search for sensitive files, scripts, credentials on system
- Check for vulnerable services, scheduled tasks, or misconfigurations

### After adam.silver Shows Disabled
**Current decision point:** Need alternative path to WinRM or Senior Devs
**Option 1:** Check Developers control over GPOs (GPO abuse)
**Option 2:** Password spray KingofAkron2025! against all users (reuse)
**Option 3:** Analyze KeePass MSI file for credentials
**Option 4:** Check Developers control over computers (RBCD attack)
**Option 5:** Investigate NFS/iSCSI services for exposed data

### After Privilege Escalation Enumeration (Failed Attempts)
**Attempts that yielded nothing:**
1. BloodHound ACL - adam.silver/steph.cooper have no outbound control
2. whoami /priv - no dangerous Windows privileges (no SeBackup, SeImpersonate, etc.)
3. PowerShell history - empty (newly enabled accounts)
4. User files enumeration - no interesting documents or scripts
5. Recycle Bin - empty
6. Scheduled tasks - access denied to enumerate
7. NFS exports (port 2049) - showmount returned no exports
8. SYSVOL GPO scripts - not writable (access denied)
9. Password spraying KeePass passwords - all failed against steph.cooper_adm
10. AS-REP roasting - no vulnerable accounts found
11. Registry autologon credentials - none saved
12. Windows Credential Manager (cmdkey /list) - empty

**Chose:** Enumerate root directories on C:\
**Result:** Found C:\Backups\ directory with site-backup-2024-12-30.zip

### After Finding Backup File
**Chose:** Download and analyze backup ZIP for credentials
**Result:** Found nms-auth-config.xml.bak with steph.cooper credentials
**Alternative 1:** Could have continued with other enumeration (would have wasted time)
**Why backup files matter:** Old config files often contain credentials for testing/development

### After Getting steph.cooper Credentials
**Chose:** Check for DPAPI credential files
**Reasoning:**
  - Standard user with no privileges = DPAPI scenario
  - Found another user account = check for saved admin credentials
**Result:** Found DPAPI master keys and credential blobs in AppData

**Alternative 1:** Could have checked BloodHound first (would have found no ACLs)
**Alternative 2:** Could have tried password variations for steph.cooper_adm (would have failed)

### DPAPI Decryption Decision
**Chose:** Manual decryption with dpapi.py (educational approach)
**Steps:**
1. Downloaded DPAPI master key files and credential blobs
2. Used dpapi.py to decrypt master key with steph.cooper's password
3. Used decrypted master key to decrypt credential blob
4. Successfully extracted steph.cooper_adm / FivethChipOnItsWay2025!

**Alternative 1:** SharpDPAPI on Windows (faster, but less understanding of process)
**Alternative 2:** pypykatz (similar to dpapi.py but different syntax)
**Result:** SUCCESS - obtained Domain Admin password

## Key Lessons & Decision Points

### When to Think DPAPI?
✅ Indicators that DPAPI should be checked:
- Standard domain user with no ACL paths
- No dangerous Windows privileges
- Found one user's credentials → check their DPAPI for other accounts
- Administrative account exists (_adm suffix) but password unknown
- cmdkey /list shows saved credentials (though was empty in our case)

### Backup Files as Attack Vector
- Always enumerate C:\ root directories (C:\Backups, C:\Temp, C:\inetpub, etc.)
- Backup files often contain:
  - Old/test credentials still valid
  - Configuration files with hardcoded passwords
  - Database connection strings
  - API keys and service account credentials

### Administrative Account Naming Patterns
- steph.cooper = regular user
- steph.cooper_adm = administrative account
- Common patterns: _adm, -admin, .admin, _da suffixes
- DPAPI from regular account → saved password for admin account

## Completed Steps
- [x] Captured user flag as adam.silver
- [x] Captured root flag as steph.cooper_adm
- [x] DCSync dump of all domain user hashes
- [x] Documented DPAPI privilege escalation technique
- [x] Updated methodology with DPAPI enumeration
