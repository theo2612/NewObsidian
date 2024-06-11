[Linux PrivEsc](https://tryhackme.com/room/linprivesc)

login with credentials provided -- karen/Password1
```bash
ssh karen@ip.ip.ip.ip
```

stabilize shell - Use Python to spawn a better-featured bash shell
```bash 
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
The export TERM=xterm command sets the terminal emulator to xterm
```bash
export TERM=xterm
```

**hostname** - returns the hostname of the target machine
```bash
karen@wade7363:/$ hostname
wade7363
```

**uname** -a -returns system info giving additional detail about the kernel used by the system
```bash
karen@wade7363:/$ uname -a
Linux wade7363 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

**/proc/version** provides information about the target system processes
```bash
karen@wade7363:/$ cat /proc/version
Linux version 3.13.0-24-generic (buildd@panlong) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014
```

**/etc/issue** also can provide information about the target system processes
```bash
karen@wade7363:/$ cat /etc/issue
Ubuntu 14.04 LTS \n \l
```

**ps**/Process Status shows the running processes on a Linux system
* PID: The process ID (unique to the process)
* TTY: Terminal type used by the user
* Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)
* CMD: The command or executable running (will NOT display any command line parameter)
```bash
karen@wade7363:/$ ps
  PID TTY          TIME CMD
 1816 pts/6    00:00:00 bash
 2027 pts/6    00:00:00 ps
 ```

**ps -A** displays all running processes
 ```bash
karen@wade7363:/$ ps -A
  PID TTY          TIME CMD
    1 ?        00:00:01 init
    2 ?        00:00:00 kthreadd
    3 ?        00:00:00 ksoftirqd/0
    5 ?        00:00:00 kworker/0:0H
    6 ?        00:00:00 kworker/u30:0
    7 ?        00:00:00 rcu_sched ....
	1642 pts/4    00:00:00 sh
 	1815 pts/4    00:00:00 python3
 	1816 pts/6    00:00:00 bash
 	2029 pts/6    00:00:00 ps
```

**ps axjf** displays process tree
```bash
karen@wade7363:/$ ps axjf
 PPID   PID  PGID   SID TTY      TPGID STAT   UID   TIME COMMAND
    0     2     0     0 ?           -1 S        0   0:00 [kthreadd]
    2     3     0     0 ?           -1 S        0   0:00  \_ [ksoftirqd/0]
    2     5     0     0 ?           -1 S<       0   0:00  \_ [kworker/0:0H]...
	1  1505  1282  1282 ?           -1 Sl     112   0:00 /usr/lib/x86_64-linux-gnu/notify-osd
    1  1517   391   391 ?           -1 Sl     113   0:00 /usr/lib/colord/colord
    1  1591  1591  1591 ?           -1 Ss       0   0:00 /usr/sbin/cupsd -f
```

**ps aux** displays processes for all users (a), user who launched the process (u), and processes that are not attached to the terminal.
```bash
karen@wade7363:/$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.3  33760  3056 ?        Ss   09:59   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    09:59   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    09:59   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   09:59   0:00 [kworker/0:0H]....
karen     1815  0.0  0.6  42660  6324 pts/4    S+   10:13   0:00 python3 -c import pty;pty.spawn("/bin/bash")
karen     1816  0.0  0.2  25256  2128 pts/6    Ss   10:13   0:00 /bin/bash
karen     2046  0.0  0.1  22644  1304 pts/6    R+   10:55   0:00 ps aux
```

**env** will display environmental variables
PATH variable may have a compiler/scripting lang like Python that could be used to run code on the target system or leveraged for privilage escalation
```bash
karen@wade7363:/$ env
XDG_SESSION_ID=1
SHELL=/bin/sh
TERM=xterm
SSH_CLIENT=10.6.14.44 55068 22
SSH_TTY=/dev/pts/4
USER=karen
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
MAIL=/var/mail/karen
QT_QPA_PLATFORMTHEME=appmenu-qt5
PWD=/
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/karen
LOGNAME=karen
SSH_CONNECTION=10.6.14.44 55068 10.10.107.204 22
XDG_RUNTIME_DIR=/run/user/1001
_=/usr/bin/env
```

**sudo -l** displays all commands users on the system can run using sudo

**ls** lists files in the current directory. The **-la** parameter shows all files

**id** provides a general overview of the users privilage level group memberships. Can also be used to view same info about other users
```bash
karen@wade7363:/home$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)
karen@wade7363:/home$ id lightdm
uid=112(lightdm) gid=118(lightdm) groups=118(lightdm)
```

**/etc/passwd** file that shows users on the system 
```bash
karen@wade7363:/home$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
...
lightdm:x:112:118:Light Display Manager:/var/lib/lightdm:/bin/false
colord:x:113:121:colord colour management daemon,,,:/var/lib/colord:/bin/false
hplip:x:114:7:HPLIP system user,,,:/var/run/hplip:/bin/false
pulse:x:115:122:PulseAudio daemon,,,:/var/run/pulse:/bin/false
matt:x:1000:1000:matt,,,:/home/matt:/bin/bash
karen:x:1001:1001::/home/karen:
sshd:x:116:65534::/var/run/sshd:/usr/sbin/nologin
```
**cat /etc/passwd | cut -d ":" -f 1** will return a trimmed version of the users in etc/passwd. This will return all users, some of which are system or service users that would not be very useful
```bash
karen@wade7363:/home$ cat /etc/passwd | cut -d ":" -f 1
root
daemon
bin
sys
sync
games
...
lightdm
colord
hplip
pulse
matt
karen
sshd
```

grep for “home” as real users will most likely have their folders under the “home” directory. 
```bash
karen@wade7363:/home$ cat /etc/passwd | grep home
syslog:x:101:104::/home/syslog:/bin/false
usbmux:x:103:46:usbmux daemon,,,:/home/usbmux:/bin/false
saned:x:108:115::/home/saned:/bin/false
matt:x:1000:1000:matt,,,:/home/matt:/bin/bash
karen:x:1001:1001::/home/karen:
```
**history** will display a list of previously used commands. potentially could have username/passwords
```bash
karen@wade7363:/home$ history
    1  whoami
    2  export TERM=xterm
    3  stty rows 38 columns 116
    4  ls 
    5  hostname
    6  uname -a
    7  /proc/version
    8  /etc/issue
```
**ifconfig** command will show info about the network interfaces of the system. Attacking machines can reach eth0 but cannot directly access any others
```bash
karen@wade7363:/home$ ifconfig
eth0      Link encap:Ethernet  HWaddr 02:15:bc:e8:c2:bd  
          inet addr:10.10.107.204  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::15:bcff:fee8:c2bd/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:2415 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1802 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:189310 (189.3 KB)  TX bytes:295682 (295.6 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:110 errors:0 dropped:0 overruns:0 frame:0
          TX packets:110 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:8137 (8.1 KB)  TX bytes:8137 (8.1 KB)
```
**ip route** can be used to see which network routes exist
```bash
karen@wade7363:/home$ ip route
default via 10.10.0.1 dev eth0 
10.10.0.0/16 dev eth0  proto kernel  scope link  src 10.10.107.204 
169.254.0.0/16 dev eth0  scope link  metric 1000 
```
**netstat** can be used to gather information on existing connections
**netstat -a** shows all listening ports and established connections
```bash
karen@wade7363:/home$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 *:ssh                   *:*                     LISTEN     
tcp        0      0 localhost:ipp           *:*                     LISTEN     
tcp        0    316 ip-10-10-107-204.eu:ssh ip-10-6-14-44.eu-:55068 ESTABLISHED
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
tcp6       0      0 ip6-localhost:ipp       [::]:*                  LISTEN     
tcp6       1      0 ip6-localhost:53621     ip6-localhost:ipp       CLOSE_WAIT 
```
**netstat -at** can be used to list TCP protocols
```bash
karen@wade7363:/home$ netstat -at
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 *:ssh                   *:*                     LISTEN     
tcp        0      0 localhost:ipp           *:*                     LISTEN     
tcp        0    316 ip-10-10-107-204.eu:ssh ip-10-6-14-44.eu-:55068 ESTABLISHED
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
tcp6       0      0 ip6-localhost:ipp       [::]:*                  LISTEN     
tcp6       1      0 ip6-localhost:53621     ip6-localhost:ipp       CLOSE_WAIT 
```
**netstat -au** can be used to list UDP protocol
```bash
karen@wade7363:/home$ netstat -au
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
udp        0      0 *:bootpc                *:*                                
udp        0      0 *:41562                 *:*                                
udp        0      0 *:ipp                   *:*                                
udp        0      0 *:mdns                  *:*                                
udp        0      0 *:29459                 *:*                                
udp6       0      0 [::]:56913              [::]:*                             
udp6       0      0 [::]:47817              [::]:*                             
udp6       0      0 [::]:mdns               [::]:*

```
**netstat -l** lists ports in "listening mode". These ports are open and ready to accept incoming connections. use **t** to list only ports that are listening using the TCP protocol.
```bash
karen@wade7363:/home$ netstat -l
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 *:ssh                   *:*                     LISTEN     
tcp        0      0 localhost:ipp           *:*                     LISTEN     
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
tcp6       0      0 ip6-localhost:ipp       [::]:*                  LISTEN     
udp        0      0 *:bootpc                *:*                                
udp        0      0 *:41562                 *:*                                
udp        0      0 *:ipp                   *:*                                
udp        0      0 *:mdns                  *:*                                
udp        0      0 *:29459                 *:*                                
udp6       0      0 [::]:56913              [::]:*                             
udp6       0      0 [::]:47817              [::]:*                             
udp6       0      0 [::]:mdns               [::]:*                             
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     STREAM     LISTENING     9892     /tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     9891     @/tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     10651    @/tmp/dbus-VFJvmMD7VA
unix  2      [ ACC ]     STREAM     LISTENING     11324    /run/user/112/pulse/native
unix  2      [ ACC ]     STREAM     LISTENING     9767     /var/lib/amazon/ssm/ipc/termination
unix  2      [ ACC ]     STREAM     LISTENING     9551     /var/run/acpid.socket
unix  2      [ ACC ]     SEQPACKET  LISTENING     7504     /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     7112     @/com/ubuntu/upstart
unix  2      [ ACC ]     STREAM     LISTENING     10853    @/com/ubuntu/upstart-session/112/1334
unix  2      [ ACC ]     STREAM     LISTENING     11669    /var/run/cups/cups.sock
unix  2      [ ACC ]     STREAM     LISTENING     9766     /var/lib/amazon/ssm/ipc/health
unix  2      [ ACC ]     STREAM     LISTENING     10601    @/tmp/dbus-DtPKdpMKT1
unix  2      [ ACC ]     STREAM     LISTENING     7844     /var/run/avahi-daemon/socket
unix  2      [ ACC ]     STREAM     LISTENING     7873     /var/run/sdp
unix  2      [ ACC ]     STREAM     LISTENING     7623     /var/run/dbus/system_bus_socket
karen@wade7363:/home$ netstat -lt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 *:ssh                   *:*                     LISTEN     
tcp        0      0 localhost:ipp           *:*                     LISTEN     
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
tcp6       0      0 ip6-localhost:ipp       [::]:*                  LISTEN
```
**netstat -s** lists network statistics by protocol. Can also be used with the **-t** or **-u** to limit output to TCP or UDP
```bash
karen@wade7363:/home$ netstat -s
Ip:
    2645 total packets received
    0 forwarded
    0 incoming packets discarded
    2643 incoming packets delivered
    1873 requests sent out
Icmp:
    0 ICMP messages received
    0 input ICMP message failed.
    ICMP input histogram:
    0 ICMP messages sent
    0 ICMP messages failed
    ICMP output histogram:
Tcp:
    104 active connections openings
    4 passive connection openings
    44 failed connection attempts
    0 connection resets received
    1 connections established
    2635 segments received
    1812 segments send out
    64 segments retransmited
    0 bad segments received.
    49 resets sent
Udp:
    73 packets received
    0 packets to unknown port received.
    0 packet receive errors
    108 packets sent
UdpLite:
TcpExt:
    14 TCP sockets finished time wait in fast timer
    21 delayed acks sent
    1 packets directly queued to recvmsg prequeue.
    192 packet headers predicted
    176 acknowledgments not containing data payload received
    1135 predicted acknowledgments
    12 other TCP timeouts
    TCPRcvCoalesce: 2
IpExt:
    InNoRoutes: 2
    InMcastPkts: 30
    OutMcastPkts: 32
    InOctets: 211654
    OutOctets: 318423
    InMcastOctets: 3979
    OutMcastOctets: 4059
    InNoECTPkts: 2647
```
**netstat -tp** lists connections with the service name and PID info
```bash
karen@wade7363:/home$ netstat -tp
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 ip-10-10-107-204.eu:ssh ip-10-6-14-44.eu-:55068 ESTABLISHED -               
tcp6       1      0 ip6-localhost:53621     ip6-localhost:ipp       CLOSE_WAIT  -
```
**-l** can be used with **netstat -ltp** to list listening ports
```bash
karen@wade7363:/$ netstat -ltp
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 *:ssh                   *:*                     LISTEN      -               
tcp        0      0 localhost:ipp           *:*                     LISTEN      -               
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN      -               
tcp6       0      0 ip6-localhost:ipp       [::]:*                  LISTEN
```
**netstat -i** shows interface statistics. note which interfaces are more active than others
```bash
karen@wade7363:/$ netstat -i
Kernel Interface table
Iface   MTU Met   RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg
eth0       9001 0      3132      0      0 0          2585      0      0      0 BMRU
lo        65536 0       102      0      0 0           102      0      0      0 LRU

```
**netstat -ano** 
* -a: Display all sockets
* -n: Do not resolve names
* -o: Display timers
```bash
karen@wade7363:/$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 10.10.63.50:22          10.6.14.44:47930        ESTABLISHED keepalive (4845.83/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 ::1:631                 :::*                    LISTEN      off (0.00/0/0)
tcp6       1      0 ::1:53616               ::1:631                 CLOSE_WAIT  off (0.00/0/0)
udp        0      0 0.0.0.0:52234           0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:68              0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:631             0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:46734           0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           off (0.00/0/0)
udp6       0      0 :::44059                :::*                                off (0.00/0/0)
udp6       0      0 :::8231                 :::*                                off (0.00/0/0)
udp6       0      0 :::5353                 :::*                                off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     STREAM     LISTENING     10031    /tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     10030    @/tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     11333    /run/user/112/pulse/native

```
**find** command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size. **find** command tends to generate errors and makes the output hard to read. 
Use **find** command with **-type f 2>/dev/null** to redirect errors to “/dev/null” and have a cleaner output.
* find . -name flag1.txt: find the file named “flag1.txt” in the current directory
* find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
* find / -type d -name config: find the directory named config under “/”
* find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
* find / -perm a=x: find executable files
* find /home -user frank: find all files for user “frank” under “/home”
* find / -mtime 10: find files that were modified in the last 10 days
* find / -atime 10: find files that were accessed in the last 10 day
* find / -cmin -60: find files changed within the last hour (60 minutes)
* find / -amin -60: find files accesses within the last hour (60 minutes)
* find / -size 50M: find files with a 50 MB size*
**Folders and files that can be written to or executed from:** 3 different find commands below dealing with perms because of multiple ways to set perms
* find / -writable -type d 2>/dev/null : Find world-writeable folders
* find / -perm -222 -type d 2>/dev/null: Find world-writeable folders
* find / -perm -o w -type d 2>/dev/null: Find world-writeable folders
* find / -perm -o x -type d 2>/dev/null : Find world-executable folders
**Find world-executable folders**
* find / -name perl*
* find / -name python*
* find / -name gcc*
**Find specific file permissions** 
Below is a short example used to find files that have the SUID bit set. The SUID bit allows the file to run with the privilege level of the account that owns it, rather than the account which runs it. This allows for an interesting privilege escalation path. 
Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user. 
```bash
find / -perm -u=s -type f 2>/dev/null 
```

What vulnerability seems to affect the kernal of the target system (3.13.0) Ubuntu?
```bash
searchsploit 3.13
---------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                          |  Path
---------------------------------------------------------------------------------------- ---------------------------------
AjentiCP 1.2.23.13 - Cross-Site Scripting                                               | php/webapps/45691.txt
Apple Mac OSX xnu 1228.3.13 - 'macfsstat' Local Kernel Memory Leak/Denial of Service    | osx/dos/8263.c
Apple Mac OSX xnu 1228.3.13 - 'Profil' Kernel Memory Leak/Denial of Service (PoC)       | osx/dos/8264.c
Apple Mac OSX xnu 1228.3.13 - 'zip-notify' Remote Kernel Overflow (PoC)                 | osx/dos/8262.c
Apple Mac OSX xnu 1228.3.13 - IPv6-ipcomp Remote kernel Denial of Service (PoC)         | multiple/dos/5191.c
Atlassian JIRA 3.13.5 - File Download Security Bypass                                   | multiple/remote/35898.php
Bludit 3.13.1 - 'username' Cross Site Scripting (XSS)                                   | php/webapps/50529.txt
Chevereto 3.13.4 Core - Remote Code Execution                                           | php/webapps/47903.py
Deluge Web UI 1.3.13 - Cross-Site Request Forgery                                       | json/webapps/41541.html
GetSimple CMS 3.3.13 - Cross-Site Scripting                                             | php/webapps/44408.txt
id Software Solaris Quake II 3.13/3.14 / QuakeWorld 2.0/2.1 / Quake 1.9/3.13/3.14 - Com | linux/remote/19079.c
Linux Kernel 3.13 - SGID Privilege Escalation                                           | linux/local/33824.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privile | linux/local/37292.c

searchsploit -x 37292
/*
# Exploit Title: ofs.c - overlayfs local root in ubuntu
# Date: 2015-06-15
# Exploit Author: rebel
# Version: Ubuntu 12.04, 14.04, 14.10, 15.04 (Kernels before 2015-06-15)
# Tested on: Ubuntu 12.04, 14.04, 14.10, 15.04
# CVE : CVE-2015-1328     (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-1328.html)
```

**Automated Enumeration Tools**
* LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
* LinEnum: https://github.com/rebootuser/LinEnum
* LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
* Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
* Linux Priv Checker: https://github.com/linted/linuxprivchecker *






 

 











