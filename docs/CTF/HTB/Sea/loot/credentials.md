# Credentials - Sea

| User | Password/Hash | Type | Source | Access Granted | Tested |
|------|---------------|------|--------|----------------|--------|
| WonderCMS admin | $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q | Bcrypt | database.json | CMS admin panel | ✓ |
| amay | mychemicalromance | Plaintext (cracked) | hashcat -m 3200 | SSH | ✓ |

## Notes
- bcrypt hash found in /var/www/sea/data/files/database.json (WonderCMS flat-file store)
- Password `mychemicalromance` cracked from bcrypt hash, reused for SSH as amay
