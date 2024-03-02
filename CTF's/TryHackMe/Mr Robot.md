- scan ip address for open ports
	- 22/tcp closed ssh conn-refused
	- 80/tcp open http syn-ack
	- 443/tcp open https syn-ack

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- -T5 -vvv 10.10.74.16                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-02 12:03 EST
Initiating Ping Scan at 12:03
Scanning 10.10.74.16 [2 ports]
Completed Ping Scan at 12:03, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:03
Completed Parallel DNS resolution of 1 host. at 12:03, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:03
Scanning 10.10.74.16 [65535 ports]
Discovered open port 443/tcp on 10.10.74.16
Discovered open port 80/tcp on 10.10.74.16
Connect Scan Timing: About 8.21% done; ETC: 12:09 (0:05:46 remaining)
Connect Scan Timing: About 21.78% done; ETC: 12:07 (0:03:39 remaining)
Connect Scan Timing: About 35.52% done; ETC: 12:07 (0:02:45 remaining)
Connect Scan Timing: About 48.23% done; ETC: 12:07 (0:02:26 remaining)
Connect Scan Timing: About 63.98% done; ETC: 12:07 (0:01:33 remaining)
Connect Scan Timing: About 79.17% done; ETC: 12:07 (0:00:52 remaining)
Completed Connect Scan at 12:07, 266.99s elapsed (65535 total ports)
Nmap scan report for 10.10.74.16
Host is up, received syn-ack (0.22s latency).
Scanned at 2024-03-02 12:03:10 EST for 267s
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE  SERVICE REASON
22/tcp  closed ssh     conn-refused
80/tcp  open   http    syn-ack
443/tcp open   https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 267.28 seconds
```