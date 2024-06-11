```bash
nmap -sC -sV <IP>

```
reveals the following open ports-
port 21 ftp - version 220 uftpd (2.10)
port 22 ssh - version OpenSSH 7.6pl Ubuntu 4ubuntu0.6

FTP access - There is a misconfiguration in FTP where you can login using 'admin' and no password.
Using this We can see we have access to a single folder '/'

using directory traversal we find that we can access the admin folder

create ssh-kegen and upload to <IP> 





