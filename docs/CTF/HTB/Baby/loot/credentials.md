# Credentials - Baby

| User | Password/Hash | Type | Source | Access Granted | Tested |
|------|---------------|------|--------|----------------|--------|
| Caroline.Robinson | BabyStart123! (initial) | Plaintext | LDAP description (Teresa.Bell) | STATUS_PASSWORD_MUST_CHANGE | ✓ |
| Caroline.Robinson | Yourmoms123! (changed) | Plaintext | Changed via nxc smbpasswd | WinRM (it group) | ✓ |
| Administrator (local) | 8d992faed38128ae85e95fa35868bb43 | NT Hash | pypykatz SAM dump | Local admin (not domain) | ✓ |
| Administrator (domain) | ee4457ae59f1e3fbd764e33d9cef123d | NT Hash | secretsdump.py ntds.dit | Domain Admin — WinRM (Pwn3d!) | ✓ |
| krbtgt | 6da4842e8c24b99ad21a92d620893884 | NT Hash | secretsdump.py ntds.dit | Kerberos key distribution | - |
| BABYDC$ | 3d538eabff6633b62dbaa5fb5ade3b4d | NT Hash | secretsdump.py ntds.dit | Machine account | - |

## All Domain User Hashes (from ntds.dit)

| User | NT Hash |
|------|---------|
| Jacqueline.Barnett | 20b8853f7aa61297bfbc5ed2ab34aed8 |
| Ashley.Webb | 02e8841e1a2c6c0fa1f0becac4161f89 |
| Hugh.George | f0082574cc663783afdbc8f35b6da3a1 |
| Leonard.Dyer | b3b2f9c6640566d13bf25ac448f560d2 |
| Ian.Walker | 0e440fd30bebc2c524eaaed6b17bcd5c |
| Connor.Wilkinson | e125345993f6258861fb184f1a8522c9 |
| Joseph.Hughes | 31f12d52063773769e2ea5723e78f17f |
| Kerry.Wilson | 181154d0dbea8cc061731803e601d1e4 |
| Teresa.Bell | 7735283d187b758f45c0565e22dc20d8 |
| Caroline.Robinson | 3c387bd06399c49ac18d935208e2ef67 |

## Notes
- LDAP description on Teresa.Bell: "Set initial password to BabyStart123!"
- All users changed initial password EXCEPT Caroline.Robinson (STATUS_PASSWORD_MUST_CHANGE)
- Box was broken initially — required HTB machine reset to get clean state
- Changed Caroline's password to Yourmoms123! via nxc smb change-password module
- Caroline.Robinson is in `it` group → `Remote Management Users` → WinRM access
- SAM hash (8d992faed38128ae85e95fa35868bb43) is LOCAL admin, not domain admin
- Domain admin hash (ee4457ae59f1e3fbd764e33d9cef123d) extracted from ntds.dit via Backup Operators privesc
