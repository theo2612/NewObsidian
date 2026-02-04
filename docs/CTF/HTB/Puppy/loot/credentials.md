# Credentials - Puppy

| User             | Password/Hash           | Type      | Source                                                 | Access Granted                       | Tested |
| ---------------- | ----------------------- | --------- | ------------------------------------------------------ | ------------------------------------ | ------ |
| levi.james       | KingofAkron2025!        | Plaintext | HTB provided                                           | SMB, LDAP (no WinRM)                 | ✓      |
| adam.silver      | HJKL2025!               | Plaintext | KeePass (recovery.kdbx)                                | Account disabled (original password) | ✓      |
| adam.silver      | Password123!            | Plaintext | bloodyAD password reset                                | SMB, WinRM (after account enable)    | ✓      |
| ant.edwards      | Antman2025!             | Plaintext | KeePass (recovery.kdbx)                                | SMB (account disabled for WinRM)     | ✓      |
| jamie.williams   | JamieLove2025!          | Plaintext | KeePass (recovery.kdbx)                                | Unknown (likely disabled)            | ✗      |
| Steve Tucker     | Steve2025!              | Plaintext | KeePass (recovery.kdbx)                                | Unknown (not tested)                 | ✗      |
| Samuel Blake     | ILY2025!                | Plaintext | KeePass (recovery.kdbx)                                | Unknown (not tested)                 | ✗      |
| steph.cooper     | ChefSteph2025!          | Plaintext | site-backup-2024-12-30.zip (nms-auth-config.xml.bak)   | SMB, WinRM (standard user)           | ✓      |
| steph.cooper_adm | FivethChipOnItsWay2025! | Plaintext | DPAPI credential decrypt (from steph.cooper's AppData) | WinRM (Pwn3d!) Domain Admin          | ✓      |

## Notes
- levi.james added to Developers group via bloodyAD (GenericWrite from HR group)
- recovery.kdbx master password cracked: `liverpool` (using compiled bleeding-jumbo john)
- All 5 credentials extracted from KeePass database
- **adam.silver (HJKL2025!):** Original password from KeePass, account was disabled
- **ant.edwards (Antman2025!):** Valid SMB access, account disabled for WinRM, has GenericAll over adam.silver
- Used ant.edwards to reset adam.silver password via bloodyAD: `Password123!`
- Used ant.edwards to enable adam.silver account via bloodyAD msldap enableuser
- **adam.silver (Password123!):** Successfully logged in via WinRM, user flag captured
- jamie.williams, Steve Tucker, Samuel Blake not tested (no longer needed after getting shell)
- No Kerberoastable accounts found (no SPNs set)
- Attempted targetedKerberoast and net rpc password change - both failed
- bloodyAD LDAP-based approach successful for both password reset and account enable
