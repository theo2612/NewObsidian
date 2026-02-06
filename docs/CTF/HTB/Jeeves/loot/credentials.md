# Credentials - Jeeves

| User | Password/Hash | Type | Source | Access Granted | Tested |
|------|---------------|------|--------|----------------|--------|
| kohsuke | N/A (no auth) | Jenkins unauthenticated | Jenkins Script Console | RCE as jeeves\kohsuke | Yes - works |
| administrator | S1TjAtJHKsugh9oC4VZl | Plaintext (DC Recovery PW) | CEH.kdbx KeePass DB | TBD | Not yet |
| administrator | aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 | NTLM hash (Backup stuff) | CEH.kdbx KeePass DB | Pass-the-hash → SYSTEM | Yes - ROOTED |
| bob | lCEUnYPjNfIuPZSzOySA | Plaintext (Keys to the kingdom) | CEH.kdbx KeePass DB | TBD | Not yet |
| admin | ??? | Plaintext (It's a secret) | CEH.kdbx → localhost:8180/secret.jsp | TBD | Not yet |
| hackerman123 | ??? | Plaintext (EC-Council) | CEH.kdbx | N/A (external site) | N/A |

## Notes

- Jenkins at `/askjeeves/` requires NO authentication
- Script Console at `/askjeeves/script` gives direct Groovy code execution
- SMB guest/anonymous access is blocked despite nmap showing `account_used: guest`
- CEH.kdbx found in `C:\Users\kohsuke\Documents\` - cracked with john + rockyou.txt
- NTLM hash in "Backup stuff" entry is likely Administrator hash for pass-the-hash
