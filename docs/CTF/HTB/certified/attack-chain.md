# Attack Chain - Certified

## Current Path

```
Assumed Breach (judith.mader) → SMB/SYSVOL Enumeration (empty GPOs) →
ADCS Confirmed (cert pipe) → certipy Enumeration (CertifiedAuthentication template) →
BloodHound Collection → WriteOwner on Management Discovered →
LDAP Queries ("operator ca" is disabled USER, not group) →
impacket-owneredit (took ownership of Management) →
impacket-dacledit (granted WriteMembers) →
net rpc group addmem (added judith to Management) →
certipy shadow auto (Shadow Credentials on management_svc) →
NT Hash Extracted (a091c1832bcdd4677c28b5a6a1295584) →
evil-winrm Pass-the-Hash → WinRM Shell as management_svc →
User Flag Captured (62929513fad79d1416b71f041d940571) →
[PRIVILEGE ESCALATION IN PROGRESS]
```

---

## Complete Attack Chain (Step-by-Step)

### Phase 1: Initial Reconnaissance ✓
1. Nmap port scan (18 open ports discovered)
2. Service enumeration (Windows DC, certified.htb domain)
3. DNS/hosts configuration (`/etc/hosts`)
4. Time synchronization prep (noted +7 hour skew)

### Phase 2: Initial Access (Assumed Breach) ✓
1. Received credentials: judith.mader : judith09
2. Verified SMB access (NETLOGON, SYSVOL, IPC$ readable)
3. Discovered "cert" named pipe (ADCS presence confirmed)
4. SYSVOL enumeration (empty GPOs, no credentials)

### Phase 3: ADCS Enumeration ✓
1. Ran `certipy find` to enumerate certificate templates
2. Found custom "CertifiedAuthentication" template (1000-year validity!)
3. Identified "operator ca" with enrollment rights
4. ESC2/ESC3 flags (informational only, not exploitable)

### Phase 4: BloodHound Collection ✓
1. Initial attempt failed (DNS timeout with UDP)
2. Added `--dns-tcp` flag to fix
3. Successfully collected AD data
4. **CRITICAL DISCOVERY:** judith.mader → WriteOwner → Management (group)

### Phase 5: LDAP Investigation ✓
1. Queried "operator ca" object
2. **KEY FINDING:** "operator ca" is a DISABLED USER (ca_operator), NOT a group!
3. userAccountControl: 66048 (disabled + password never expires)
4. Eliminated certificate enrollment path (can't auth as disabled user)
5. Confirmed management_svc in Remote Management Users (WinRM potential)

### Phase 6: ACL Abuse - WriteOwner Exploitation ✓
1. **Attempt 1:** bloodyAD commands failed (tool/environment issues)
2. **Pivot:** Switched to Impacket suite
3. **Step 1:** `impacket-owneredit` - took ownership of Management group
4. **Step 2:** `impacket-dacledit` - granted WriteMembers permission to judith.mader
5. **Step 3:** `net rpc group addmem` - added judith.mader to Management group
6. **Verification:** Confirmed judith.mader now in Management (ldapsearch)

### Phase 7: Time Synchronization Challenge ✓
1. Attempted Kerberoasting - failed with clock skew error
2. Attempted certipy shadow - failed with clock skew error
3. **Problem:** systemd-timesyncd kept resetting time
4. **Solution:**
   - `sudo systemctl stop systemd-timesyncd`
   - `sudo systemctl disable systemd-timesyncd`
   - `sudo ntpdate -s 10.129.231.186`
5. Time sync maintained, Kerberos attacks now functional

### Phase 8: Shadow Credentials Attack ✓
1. **Hypothesis:** Management group → Write permissions → management_svc user
2. Ran `certipy shadow auto -u judith.mader -account management_svc`
3. **Attack steps (automated by certipy):**
   - Generated certificate and private key
   - Created Key Credential from public key
   - Added Key Credential to management_svc's `msDS-KeyCredentialLink` attribute
   - Authenticated as management_svc using PKINIT (Kerberos with certificate)
   - Requested TGT and extracted NT hash from PAC
4. **SUCCESS:** Extracted NT hash: a091c1832bcdd4677c28b5a6a1295584
5. Saved credential cache: management_svc.ccache

### Phase 9: Verification and WinRM Access ✓
1. Verified hash with `nxc smb DC01.certified.htb -u management_svc -H [hash]`
2. SMB authentication successful
3. **Foothold:** `evil-winrm -i 10.129.231.186 -u management_svc -H [hash]`
4. Interactive PowerShell session established
5. **User Flag:** `C:\Users\management_svc\Desktop\user.txt`
6. **Flag:** 62929513fad79d1416b71f041d940571

---

## Branch Points & Decisions

### After SMB Enumeration
- **Choice:** SYSVOL credential hunting OR ADCS enumeration
- **Chose:** SYSVOL first
- **Result:** Dead end (empty GPOs)
- **Lesson:** In ADCS-focused boxes, prioritize certificate enumeration first

### After certipy Enumeration
- **Choice:** Try to join "operator ca" OR find alternative paths
- **Chose:** BloodHound collection to find ACL abuse paths
- **Result:** Found WriteOwner on Management group
- **Lesson:** When direct exploitation fails, enumerate lateral paths

### After WriteOwner Discovery
- **Choice:** bloodyAD OR Impacket tools
- **Chose:** bloodyAD first (standard tooling)
- **Result:** bloodyAD failed, pivoted to Impacket
- **Lesson:** Tool failures don't invalidate attack path; try alternatives

### After LDAP Discovery (ca_operator disabled)
- **Choice:** Try to enable ca_operator OR find alternative privilege escalation
- **Chose:** Focus on management_svc (WinRM potential)
- **Result:** Shadow Credentials attack successful
- **Lesson:** Disabled accounts may be red herrings; focus on accessible targets

### After Management Group Membership
- **Choice:** Password reset (destructive) OR Shadow Credentials (stealthy)
- **Chose:** Shadow Credentials
- **Result:** NT hash extracted without alerting
- **Lesson:** Non-destructive attacks preferred for OPSEC and forensics

### After Time Sync Failures
- **Choice:** Manual time adjustments OR disable time sync service
- **Chose:** Disable systemd-timesyncd permanently
- **Result:** Kerberos attacks worked consistently
- **Lesson:** Time sync daemons interfere with Kerberos in lab environments

---

## Progress Checklist

### Reconnaissance ✓ (Complete)
- [x] Nmap port scan (18 open ports)
- [x] Service enumeration (Windows DC, certified.htb domain)
- [x] Clock skew identification (+7 hours)
- [x] ADCS presence confirmed (cert named pipe)

### Initial Enumeration ✓ (Complete)
- [x] SMB share enumeration (NETLOGON, SYSVOL, IPC$ accessible)
- [x] SYSVOL exploration (empty GPOs, no credentials)
- [x] ADCS enumeration with certipy (CertifiedAuthentication template, "operator ca")
- [x] BloodHound collection (WriteOwner on Management)
- [x] LDAP queries ("operator ca" is disabled user, management_svc groups)
- [ ] LDAP full user enumeration (not yet needed)
- [ ] Kerberoasting from judith.mader (failed - no SPNs found)
- [ ] AS-REP roasting (not yet attempted)

### ACL Abuse / Privilege Escalation ✓ (Complete)
- [x] Discovered "operator ca" is disabled USER, not group
- [x] Exploited WriteOwner on Management group (impacket-owneredit)
- [x] Granted WriteMembers permission (impacket-dacledit)
- [x] Added judith.mader to Management group (net rpc)
- [x] Verified Management → Write permissions → management_svc
- [x] Executed Shadow Credentials attack (certipy shadow auto)
- [x] Extracted management_svc NT hash
- [x] Verified hash with SMB authentication (nxc)

### Foothold ✓ (Complete)
- [x] Fixed time synchronization (disabled systemd-timesyncd)
- [x] WinRM shell access as management_svc (evil-winrm pass-the-hash)
- [x] User flag captured: 62929513fad79d1416b71f041d940571

### Privilege Escalation to Domain Admin (IN PROGRESS)
- [ ] Enumerate management_svc privileges (`whoami /all`, `whoami /priv`)
- [ ] Check for SeImpersonatePrivilege (PrintSpoofer → SYSTEM)
- [ ] BloodHound: Shortest path from management_svc to Domain Admins
- [ ] Check replication permissions (DCSync potential)
- [ ] Kerberoasting with management_svc credentials
- [ ] Search for Administrator credentials in files/registry
- [ ] Check ca_operator enable/reset permissions
- [ ] ADCS exploitation from management_svc context
- [ ] Root flag capture

---

## Key Findings

### ADCS Infrastructure
- **CA:** certified-DC01-CA (100-year validity)
- **Custom Template:** CertifiedAuthentication
  - 1000-year validity (highly unusual - lab artifact or persistence)
  - Enrollment rights: ca_operator (disabled user), Domain Admins, Enterprise Admins
  - EKU: Client Authentication, Server Authentication
- **"operator ca" / ca_operator:** DISABLED user account (NOT a group!)
  - userAccountControl: 66048 (ACCOUNTDISABLE + DONT_EXPIRE_PASSWORD)
  - Cannot authenticate as disabled account
  - Likely red herring or requires enable/reset from privileged context

### ACL Abuse Path
- **judith.mader → WriteOwner → Management (group)**
  - Exploited with impacket-owneredit (bloodyAD failed)
  - Took ownership of Management group
  - As owner, granted WriteMembers permission
  - Added self to Management group

### management_svc Context
- **Member of:** Management, Remote Management Users
- **WinRM Access:** Yes (pass-the-hash with NT hash)
- **NT Hash:** a091c1832bcdd4677c28b5a6a1295584 (extracted via Shadow Credentials)
- **User Flag:** 62929513fad79d1416b71f041d940571

### BloodHound Relationships
- Account Operators → GenericAll → Management
- judith.mader → WriteOwner → Management
- Management → Members: management_svc, judith.mader (after exploitation)
- Management → Member Of: (0 groups)
- Management → Write permissions → management_svc (msDS-KeyCredentialLink)

---

## Attack Techniques Used

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Valid Accounts | T1078 | Assumed breach with judith.mader credentials |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | SMB enumeration, SYSVOL access |
| Remote Services: Windows Remote Management | T1021.006 | WinRM shell access as management_svc |
| Domain Trust Discovery | T1482 | BloodHound domain enumeration |
| Account Manipulation | T1098 | Modified Management group DACL, added member |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Shadow Credentials (forged certificate for Kerberos auth) |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | evil-winrm with NT hash |
| Modify Authentication Process | T1556 | Added Key Credential to management_svc (msDS-KeyCredentialLink abuse) |

### Tools & Techniques
1. **nmap** - Port scanning, service enumeration
2. **smbmap / impacket-smbclient** - SMB share enumeration
3. **certipy find** - ADCS enumeration (CAs, templates, vulnerabilities)
4. **bloodhound-python** - AD enumeration, ACL discovery
5. **ldapsearch** - LDAP queries, object verification
6. **impacket-owneredit** - ACL abuse (change object owner)
7. **impacket-dacledit** - ACL abuse (modify permissions)
8. **net rpc group** - Samba RPC group management
9. **certipy shadow** - Shadow Credentials attack (Key Credential abuse)
10. **nxc** - Credential verification, SMB checks
11. **evil-winrm** - WinRM shell (pass-the-hash)
12. **systemctl** - Disable time sync services
13. **ntpdate** - Manual time synchronization

---

## Next Steps (Priority Order)

**IMMEDIATE (when resuming from WinRM shell):**

1. **Basic enumeration as management_svc**
   ```powershell
   whoami /all
   whoami /groups
   whoami /priv
   net user management_svc /domain
   ```
   - Look for: SeImpersonatePrivilege, privileged group memberships
   - Check replication rights (DCSync potential)

2. **BloodHound: Shortest path to Domain Admins**
   - Search for management_svc user node
   - Run query: Shortest Path from management_svc to Domain Admins
   - Check "Outbound Object Control"

3. **Check for SeImpersonatePrivilege**
   - If present: Use PrintSpoofer, RoguePotato, or JuicyPotato
   - On DC, SYSTEM = Domain Admin equivalent
   - Immediate privilege escalation

4. **Kerberoasting with management_svc**
   ```bash
   sudo ntpdate -s 10.129.231.186
   impacket-GetUserSPNs certified.htb/management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -request
   ```
   - May see different SPNs than judith.mader
   - Crack hashes for additional credentials

5. **Search for credentials in management_svc context**
   ```powershell
   Get-Content (Get-PSReadlineOption).HistorySavePath  # PowerShell history
   cmdkey /list  # Saved credentials
   reg query HKLM /f password /t REG_SZ /s  # Registry passwords
   Get-ChildItem -Recurse | Select-String -Pattern "password"  # File search
   ```

6. **Check DCSync permissions**
   ```powershell
   Get-Acl "AD:DC=certified,DC=htb" | Select -ExpandProperty Access | Where-Object {$_.IdentityReference -like "*management*"}
   ```
   - If DS-Replication-Get-Changes: `impacket-secretsdump` → dump all hashes

7. **Check ca_operator enable/reset permissions**
   ```powershell
   Get-Acl "AD:CN=operator ca,CN=Users,DC=certified,DC=htb" | Select -ExpandProperty Access
   Enable-ADAccount -Identity ca_operator  # If permissions exist
   Set-ADAccountPassword -Identity ca_operator -Reset  # Reset password
   ```
   - If successful: enroll in CertifiedAuthentication template

---

## Evidence Collected

- `nmap/certifiedNmapOpenPorts.txt` - Port discovery scan
- `nmap/certifiedNmapServicesVersions.txt` - Service enumeration
- `evidence/smbmapJudithMader.txt` - SMB share enumeration
- `loot/certipyOutput.txt` - ADCS enumeration (templates, CA, permissions)
- `logs/operator-ca-members.txt` - "operator ca" group members (empty - was USER account)
- `logs/management_svc-groups.txt` - management_svc group memberships
- `logs/all-groups.txt` - All domain groups
- `evidence/management_svc MemberOf Management` - BloodHound screenshot (WriteOwner path)
- BloodHound JSON files (imported to GUI)
- `management_svc.ccache` - Kerberos TGT from Shadow Credentials attack
- User flag: 62929513fad79d1416b71f041d940571

---

## Lessons Learned

### Reconnaissance
- Machine names hint at attack vectors ("Certified" = ADCS)
- Named pipes in IPC$ reveal services (`cert` = ADCS)
- Always verify object types with LDAP (group vs user confusion)

### Tool Usage
- When bloodyAD fails, try Impacket equivalents
- Tool failures don't invalidate attack logic
- net rpc works when LDAP modifications fail

### ACL Abuse
- WriteOwner → Owner → WriteMembers is valid chain
- Don't always need GenericAll if specific rights suffice
- Verify ACL changes with LDAP queries

### Kerberos
- systemd-timesyncd interferes with manual time adjustments
- Must stop/disable time sync services for lab Kerberos attacks
- Clock skew must be within ±5 minutes

### Shadow Credentials
- Non-destructive alternative to password reset
- Extracts NT hash via msDS-KeyCredentialLink abuse
- Requires Write permission on attribute (GenericWrite, GenericAll, WriteProperty)
- Works on Domain Functional Level 2016+
- Leaves minimal forensic footprint

### Pass-the-Hash
- NT hash alone sufficient (no password needed)
- evil-winrm, nxc, all Impacket tools support pass-the-hash
- Hash format: 32 hex characters (NTLM)
