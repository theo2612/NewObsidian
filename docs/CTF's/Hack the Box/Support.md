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
	- armando:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
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

