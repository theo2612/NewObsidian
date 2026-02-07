# Attack Chain - Baby

## Current Path
```
Nmap scan → Identified AD DC (baby.vl) → /etc/hosts config →
SMB null auth (accepted but restricted) → LDAP anonymous bind (SUCCESS - 8 users) →
[Next: LDAP description check / AS-REP roasting]
```

## Branch Points
- **After nmap:** Pure AD DC, no web services → SMB/LDAP enumeration
- **SMB null session:** Auth accepted but no data returned (shares/users/groups/policy all empty)
- **LDAP anonymous bind:** Got 8 users — now pursuing credential discovery

## Next Steps
- [x] Add baby.vl to /etc/hosts
- [x] Test SMB null sessions — auth OK but restricted
- [x] LDAP anonymous bind — 8 users found, saved to loot/users.txt
- [ ] Check LDAP description fields for passwords
- [ ] AS-REP roasting against user list
- [ ] Full LDAP dump for additional recon
