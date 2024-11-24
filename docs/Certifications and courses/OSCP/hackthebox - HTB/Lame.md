### nmap for open ports
- 21 ftp vsftpd2.3.4
- 22 openssh 4.7p1
- 139 samba smbd 3.x - 4.x
- 445 samba smbd 3.0.20-debian
- 3632 distccd v1 
### nmap for services and versions running on open ports
- 21 ftp vsftpd2.3.4
- 22 openssh 4.7p1
- 139 samba smbd 3.x - 4.x
- 445 samba smbd 3.0.20-debian
- 3632 distccd v1 
### search for exploits, RCEs, etc on service's versions running on those open ports
- 21 ftp
	- searchsploit has rce for vsftpd 2.3.4 but does not work
	- ran 2 exploits from github and neither worked
		- https://github.com/ahervias77/vsftpd-2.3.4-exploit
		- https://github.com/Hellsender01/vsftpd_2.3.4_Exploit
		- while vsftpd is exploitable this box is not vulnerable to it
- 139 samba smbd 3.x - 4.x
	- 
