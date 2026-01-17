# Credentials - theFrizz

| User | Password/Hash | Type | Source | Access Granted | Tested |
|------|---------------|------|--------|----------------|--------|
| MrGibbonsDB | MisterGibbs!Parrot!?1 | Plaintext | Gibbon config.php (RCE shell) | MySQL database | ✓ |
| f.frizzle@frizz.htb | Jenni_Luvs_Magic23 | Plaintext | MySQL gibbon.gibbonperson (cracked SHA256+salt) | Domain user | Pending |

## Cracked Hashes
- **f.frizzle hash:** `067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03`
- **Salt:** `/aACFhikmNopqrRTVz2489`
- **Hash Mode:** hashcat -m 1420 (SHA256 + salt)
- **Wordlist:** rockyou.txt
- **Cracked Password:** Jenni_Luvs_Magic23

## Notes
- Database credentials found in `/xampp/htdocs/Gibbon-LMS/config.php` via RCE shell
- f.frizzle is Fiona Frizzle (Ms. Frizzle) - primary user in Gibbon LMS
- Need to test f.frizzle against: SMB, WinRM (port 5985/5986), SSH (port 22), LDAP
