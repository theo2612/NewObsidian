# Credentials - theFrizz

| User | Password/Hash | Type | Source | Access Granted | Tested |
|------|---------------|------|--------|----------------|--------|
| MrGibbonsDB | MisterGibbs!Parrot!?1 | Plaintext | Gibbon config.php (RCE shell) | MySQL database | ✓ |
| f.frizzle@frizz.htb | Jenni_Luvs_Magic23 | Plaintext | MySQL gibbon.gibbonperson (cracked SHA256+salt) | SSH (Kerberos), SMB, LDAP | ✓ |

## Cracked Hashes
- **f.frizzle hash:** `067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03`
- **Salt:** `/aACFhikmNopqrRTVz2489`
- **Hash Mode:** hashcat -m 1420 (SHA256 + salt)
- **Wordlist:** rockyou.txt
- **Cracked Password:** Jenni_Luvs_Magic23

| m.schoolbus@frizz.htb | !suBcig@MehTed!R | Plaintext | wapt-backup-sunday.7z (waptserver.ini, base64 decoded) | SSH (Kerberos), SMB, LDAP | ✓ |

## Final Status
- ✓ User flag obtained via f.frizzle SSH access
- ✓ Root flag obtained via GPO abuse → SYSTEM reverse shell

## Notes
- Database credentials found in `/xampp/htdocs/Gibbon-LMS/config.php` via RCE shell
- f.frizzle is Fiona Frizzle (Ms. Frizzle) - primary user in Gibbon LMS
- m.schoolbus password found in deleted WAPT backup archive (C:\$RECYCLE.BIN)
  - File: wapt-backup-sunday.7z → waptserver.ini → wapt_password (base64 encoded)
  - Base64: `IXN1QmNpZ0BNZWhUZWQhUgo=` → Decoded: `!suBcig@MehTed!R`
- m.schoolbus is member of **Group Policy Creator Owners** and has **WriteGPLink** over Domain Controllers OU
- Privilege escalation via manual GPO creation + SharpGPOAbuse scheduled task → SYSTEM shell
