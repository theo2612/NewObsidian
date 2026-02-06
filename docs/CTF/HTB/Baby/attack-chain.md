# Attack Chain - Baby

## Current Path
```
Nmap scan → Identified AD DC (baby.vl) → /etc/hosts config →
[Next: SMB/LDAP null session enumeration]
```

## Branch Points
- **Null Session Path:** If SMB/LDAP allow anonymous access → enumerate users → AS-REP roasting
- **RID Cycling Path:** If null sessions fail → brute-force SIDs with guest account
- **Credential Spray Path:** If we get user list but no hashes → password spray with common passwords

## Next Steps
- [ ] Add baby.vl to /etc/hosts
- [ ] Test SMB null sessions for shares/users/groups/policy
- [ ] Test LDAP anonymous bind for user enumeration
- [ ] Try RID cycling if both above fail
