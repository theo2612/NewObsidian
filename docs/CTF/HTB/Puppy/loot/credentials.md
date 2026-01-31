# Credentials - Puppy

| User | Password/Hash | Type | Source | Access Granted | Tested |
|------|---------------|------|--------|----------------|--------|
| levi.james | KingofAkron2025! | Plaintext | HTB provided | SMB, LDAP (no WinRM) | ✓ |
| adam.silver | ? | Unknown | Target user | Remote Management Users (DISABLED) | ✗ |
| ant.edwards | ? | Unknown | Senior Devs member | Unknown | ✗ |
| jamie.williams | ? | Unknown | Senior Devs member | Unknown | ✗ |

## Notes
- levi.james added to Developers group via bloodyAD (GenericWrite from HR group)
- adam.silver shows KDC_ERR_CLIENT_REVOKED (account disabled/locked) - blocks AS-REP roasting and auth
- recovery.kdbx found in DEV share but KDBX4 format (keepass2john doesn't support)
- No Kerberoastable accounts found (no SPNs set)
- ant.edwards and jamie.williams not AS-REP roastable
- Password spray with KingofAkron2025! not yet attempted against other users
