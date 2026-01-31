# Credentials - Certified

## Active Credentials

| User            | Password/Hash                    | Type    | Source                                     | Access Granted            | Tested |
| --------------- | -------------------------------- | ------- | ------------------------------------------ | ------------------------- | ------ |
| judith.mader    | judith09                         | Plaintext | Assumed breach (box starting creds)      | SMB, LDAP, BloodHound     | ✓      |
| management_svc  | a091c1832bcdd4677c28b5a6a1295584 | NT Hash | Shadow Credentials (certipy shadow auto) | SMB, WinRM (Pwn3d!)       | ✓      |

## Target Accounts

| User            | Status         | Notes |
| --------------- | -------------- | ----- |
| ca_operator     | Disabled user  | "operator ca" is a DISABLED user account (userAccountControl: 66048), NOT a group |
| Administrator   | No creds yet   | Domain Admin - ultimate target |
| Domain Admins   | No creds yet   | High-value group for privilege escalation |

## Groups of Interest

| Group                      | Members           | Notes |
| -------------------------- | ----------------- | ----- |
| Management                 | 2 (management_svc, judith.mader) | judith.mader successfully added after ACL abuse |
| Remote Management Users    | management_svc, others? | WinRM access granted |
| Account Operators          | Unknown           | Has GenericAll on Management group (per BloodHound) |

## Attack Chain Summary

```
judith.mader (assumed breach)
  ↓ [WriteOwner on Management]
impacket-owneredit (take ownership)
  ↓ [Owner of Management]
impacket-dacledit (grant WriteMembers)
  ↓ [WriteMembers on Management]
net rpc group addmem (add judith to Management)
  ↓ [Member of Management]
Management → Write permissions on management_svc
  ↓ [Write on msDS-KeyCredentialLink]
certipy shadow auto (Shadow Credentials attack)
  ↓ [NT hash extracted]
management_svc: a091c1832bcdd4677c28b5a6a1295584
  ↓ [Pass-the-Hash]
evil-winrm -H (WinRM shell access)
  ↓ [User flag captured]
**FOOTHOLD ACHIEVED**
```

## Access Summary

**judith.mader:**
- **SMB:** READ ONLY on NETLOGON, SYSVOL, IPC$
- **LDAP:** Can query domain objects, enumerate groups and users
- **WinRM:** NOT accessible (not in Remote Management Users)
- **Kerberos:** Valid domain user (can request TGTs/TGS tickets)
- **ADCS:** Can enumerate; cannot enroll in CertifiedAuthentication (ca_operator account disabled)
- **BloodHound:** Successful collection completed
- **Group Membership:** Domain Users, Users, **Management** (after exploitation)

**management_svc:**
- **SMB:** Authenticated access (verified with nxc)
- **WinRM:** FULL ACCESS (member of Remote Management Users) ✓
- **Kerberos:** Valid domain user, NT hash available
- **Group Membership:** Management, Remote Management Users
- **User Flag:** ✓ Captured (62929513fad79d1416b71f041d940571)

## ACL Permissions Exploited

1. **judith.mader → WriteOwner → Management (group)**
   - Exploited with: `impacket-owneredit`
   - Result: judith.mader became owner of Management group

2. **Owner of Management → ModifyDACL → Management**
   - Exploited with: `impacket-dacledit` (granted WriteMembers)
   - Result: judith.mader can add/remove Management members

3. **WriteMembers on Management → AddMember**
   - Exploited with: `net rpc group addmem`
   - Result: judith.mader added to Management group

4. **Management group → Write → management_svc (msDS-KeyCredentialLink)**
   - Exploited with: `certipy shadow auto`
   - Result: Extracted management_svc NT hash (Shadow Credentials attack)

## Tools Used

- **impacket-owneredit** - Change object ownership (ACL abuse)
- **impacket-dacledit** - Modify DACL permissions (grant rights)
- **net rpc group** - Add/remove group members via Samba RPC
- **certipy shadow** - Shadow Credentials attack (extract NT hash)
- **evil-winrm** - WinRM client for interactive shell (pass-the-hash)
- **nxc smb** - Verify credentials and access levels
- **ldapsearch** - Verify group memberships and object attributes

## Next Steps for Credential Access

**PRIORITY 1: Enumerate from management_svc WinRM shell**
- [ ] Check `whoami /all` for groups and privileges
- [ ] Look for SeImpersonatePrivilege (PrintSpoofer → SYSTEM)
- [ ] Check replication permissions (DCSync potential)
- [ ] Run BloodHound query: Shortest Path from management_svc to Domain Admins

**PRIORITY 2: Kerberoasting with management_svc**
- [ ] `impacket-GetUserSPNs certified.htb/management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -request`
- [ ] management_svc may see different SPNs than judith.mader
- [ ] Crack any hashes obtained for additional credentials

**PRIORITY 3: Check ca_operator permissions**
- [ ] Does management_svc have permissions to enable ca_operator account?
- [ ] If yes: enable → reset password → enroll in CertifiedAuthentication template

**PRIORITY 4: Search for credentials in management_svc context**
- [ ] PowerShell history: `Get-Content (Get-PSReadlineOption).HistorySavePath`
- [ ] Registry passwords: `reg query HKLM /f password /t REG_SZ /s`
- [ ] Files: `Get-ChildItem -Recurse | Select-String -Pattern "password"`

## Lessons Learned

- **"operator ca" naming was misleading** - appeared to be a group in certipy output, actually a disabled user
- **bloodyAD failed, Impacket succeeded** - same attack, different tools; persistence pays off
- **Shadow Credentials is powerful and stealthy** - non-destructive hash extraction
- **systemd-timesyncd interferes with Kerberos** - must stop/disable for lab environments
- **Pass-the-Hash works seamlessly** - no need for plaintext passwords once hash is obtained
- **ACL abuse chains work even when individual steps fail** - troubleshoot tool issues, not attack logic
