# Attack Chain - Puppy

## Current Path
```
Initial creds (levi.james) → SMB enum → BloodHound collection →
HR has GenericWrite on Developers → bloodyAD add member →
levi.james now in Developers → Access DEV share →
Found recovery.kdbx (KDBX4, blocked) → Found KeePass MSI →
Identified path: Senior Devs → GenericAll → adam.silver (DISABLED) → WinRM

BLOCKED: No control over Senior Devs, adam.silver appears disabled
```

## Branch Points

### After BloodHound Analysis
**Chose:** Use GenericWrite (HR → Developers) to add levi.james to Developers
**Alternative 1:** Could have searched for GPO control first
**Alternative 2:** Could have attempted password spraying before ACL abuse

### After Finding KeePass Database
**Chose:** Attempt keepass2john extraction (failed - KDBX4 unsupported)
**Alternative 1:** Try password guessing with kpcli import
**Alternative 2:** Extract and analyze KeePass MSI for embedded creds
**Alternative 3:** Note for later: CVE-2023-32784 memory dump after getting shell

### After adam.silver Shows Disabled
**Current decision point:** Need alternative path to WinRM or Senior Devs
**Option 1:** Check Developers control over GPOs (GPO abuse)
**Option 2:** Password spray KingofAkron2025! against all users (reuse)
**Option 3:** Analyze KeePass MSI file for credentials
**Option 4:** Check Developers control over computers (RBCD attack)
**Option 5:** Investigate NFS/iSCSI services for exposed data

## Next Steps
- [ ] BloodHound: Check if Developers has control over any GPOs
- [ ] Password spray KingofAkron2025! against domain users
- [ ] Extract and analyze KeePassXC-2.7.9-Win64.msi
- [ ] Check for Developers control over computer objects
- [ ] Investigate NFS exports (showmount, but was hanging)
- [ ] Once shell obtained: CVE-2023-32784 KeePass memory dump for master password
