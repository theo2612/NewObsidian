- nmap ports
	- reveals 80 http, 139 smb, 445 smb
```bash
nmap -p- -T4 -vvv 10.10.221.31

PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack
```

- nmap services and versions
```bash
──(kali㉿kali)-[~/thm/yearFox]
└─$ sudo nmap -p 80,139,445 -sU -T4 -vvv -Pn 10.10.74.16 -oN nmapFoxVersionScripts.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-24 14:41 EDT
Initiating Parallel DNS resolution of 1 host. at 14:41
Completed Parallel DNS resolution of 1 host. at 14:41, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating UDP Scan at 14:41
Scanning 10.10.74.16 [3 ports]
Completed UDP Scan at 14:41, 2.07s elapsed (3 total ports)
Nmap scan report for 10.10.74.16
Host is up, received user-set.
Scanned at 2024-03-24 14:41:42 EDT for 2s

PORT    STATE         SERVICE      REASON
80/udp  open|filtered http         no-response
139/udp open|filtered netbios-ssn  no-response
445/udp open|filtered microsoft-ds no-response

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.18 seconds
           Raw packets sent: 6 (196B) | Rcvd: 0 (0B)
```

- list smb shares with smbclient reveals
	- sharenames yotf-Fox's stuff and IPC$-IPC service yotf server Samba and Ubuntu
	- workgroup YEAROFTHEFOX
```bash
┌──(kali㉿kali)-[~/thm/yearFox]
└─$ smbclient -L \\test.local -I 10.10.221.31 -N

        Sharename       Type      Comment
        ---------       ----      -------
        yotf            Disk      Fox's Stuff -- keep out!
        IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        YEAROFTHEFOX         YEAR-OF-THE-FOX
```
`-L` : This option is used to list shares on the specified server. It's followed by the server name or IP address.
`\\test.local`: This specifies the server you want to connect to. The `\\` indicates the beginning of the server name, and `test.local` is the NetBIOS name or Fully Qualified Domain Name (FQDN) of the server. It's important to note that if you're using an IP address instead of a hostname, you should omit the `\\`.
`-I 10.10.221.31`: This option specifies the IP address of the target server. It's used to explicitly set the server's IP address instead of relying on name resolution. This can be useful if DNS isn't configured properly or if you want to bypass DNS altogether.
`-N`: This flag specifies "no password" authentication. It means you're attempting to connect without providing a password. This is typically used for anonymous access or if you're sure that the server doesn't require a password.

- Logging into the smb client IPC$ public share 
```bash
┌──(kali㉿kali)-[~/thm/yearFox]
└─$ smbclient //10.10.221.31/IPC$ -W YEAROFTHEFOX

Password for [YEAROFTHEFOX\kali]:
Try "help" to get a list of possible commands.
smb: \> 
```

- navigate to ip address in browser
	- generates a pop up login 
	
- Linux4enum reveals
	- users - fox, rascal, ?nobody?
	- 	  
	- smb shares yotf and IPC$ on workgroup YEAROFTHEFOX
	- Password Policy Info 
		- Minimum password length: 5
		- password complexity: Disabled - simple password possibility
		- Account lockout threshold: none - Brute force susceptible

- Running hydra knowing user rascal
```bash
hydra -l rascal -P /usr/share/wordlists/rockyou.txt -v -f 10.10.221.31 http-head /
```




