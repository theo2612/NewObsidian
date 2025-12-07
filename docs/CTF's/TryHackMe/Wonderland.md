[[nmap]] to view open ports reveals 22 [[ssh]] and 80 [[http]]
```bash
┌──(kali㉿kali)-[~/thm/wonderland]
└─$ cat nmapPortScan.txt 
^[[3~Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-15 06:11 EDT
Initiating Ping Scan at 06:11
Scanning 10.10.40.54 [2 ports]
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Ping Scan Timing: About 100.00% done; ETC: 06:11 (0:00:00 remaining)
Completed Ping Scan at 06:11, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:11
Completed Parallel DNS resolution of 1 host. at 06:11, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 06:11
Scanning 10.10.40.54 [65535 ports]
Discovered open port 22/tcp on 10.10.40.54
Discovered open port 80/tcp on 10.10.40.54
Warning: 10.10.40.54 giving up on port because retransmission cap hit (2).
Connect Scan Timing: About 4.77% done; ETC: 06:22 (0:10:19 remaining)
Stats: 0:00:44 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 6.14% done; ETC: 06:23 (0:11:12 remaining)
Connect Scan Timing: About 23.20% done; ETC: 06:25 (0:10:32 remaining)
Stats: 0:03:51 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 27.39% done; ETC: 06:25 (0:10:12 remaining)
Connect Scan Timing: About 32.73% done; ETC: 06:25 (0:09:27 remaining)
Connect Scan Timing: About 37.65% done; ETC: 06:25 (0:08:42 remaining)
Connect Scan Timing: About 42.24% done; ETC: 06:25 (0:08:00 remaining)
Connect Scan Timing: About 47.94% done; ETC: 06:25 (0:07:17 remaining)
Connect Scan Timing: About 52.66% done; ETC: 06:25 (0:06:34 remaining)
Connect Scan Timing: About 58.36% done; ETC: 06:25 (0:05:51 remaining)
Connect Scan Timing: About 63.30% done; ETC: 06:25 (0:05:06 remaining)
Connect Scan Timing: About 68.28% done; ETC: 06:25 (0:04:19 remaining)
Connect Scan Timing: About 73.21% done; ETC: 06:25 (0:03:35 remaining)
Connect Scan Timing: About 78.61% done; ETC: 06:25 (0:02:51 remaining)
Connect Scan Timing: About 83.76% done; ETC: 06:24 (0:02:08 remaining)
Connect Scan Timing: About 89.00% done; ETC: 06:24 (0:01:26 remaining)
Connect Scan Timing: About 94.23% done; ETC: 06:24 (0:00:45 remaining)
Completed Connect Scan at 06:25, 805.08s elapsed (65535 total ports)
Nmap scan report for 10.10.40.54
Host is up, received syn-ack (0.24s latency).
Scanned at 2024-03-15 06:11:39 EDT for 805s
Not shown: 65472 closed tcp ports (conn-refused)
PORT      STATE    SERVICE       REASON
22/tcp    open     ssh           syn-ack
80/tcp    open     http          syn-ack
1384/tcp  filtered os-licman     no-response
3710/tcp  filtered portgate-auth no-response
3764/tcp  filtered mni-prot-rout no-response
5915/tcp  filtered unknown       no-response
6436/tcp  filtered unknown       no-response
6626/tcp  filtered wago-service  no-response
6814/tcp  filtered unknown       no-response
9997/tcp  filtered palace-6      no-response
11666/tcp filtered unknown       no-response
14647/tcp filtered unknown       no-response
14654/tcp filtered unknown       no-response
15239/tcp filtered unknown       no-response
17240/tcp filtered unknown       no-response
17247/tcp filtered unknown       no-response
17385/tcp filtered unknown       no-response
17557/tcp filtered unknown       no-response
19545/tcp filtered unknown       no-response
21897/tcp filtered unknown       no-response
23555/tcp filtered unknown       no-response
23931/tcp filtered unknown       no-response
24158/tcp filtered unknown       no-response
24641/tcp filtered unknown       no-response
24790/tcp filtered unknown       no-response
26005/tcp filtered unknown       no-response
26683/tcp filtered unknown       no-response
27712/tcp filtered unknown       no-response
28553/tcp filtered unknown       no-response
28968/tcp filtered unknown       no-response
29749/tcp filtered unknown       no-response
29901/tcp filtered unknown       no-response
30141/tcp filtered unknown       no-response
30768/tcp filtered unknown       no-response
31307/tcp filtered unknown       no-response
32314/tcp filtered unknown       no-response
34261/tcp filtered unknown       no-response
34667/tcp filtered unknown       no-response
36870/tcp filtered unknown       no-response
37125/tcp filtered unknown       no-response
37530/tcp filtered unknown       no-response
39296/tcp filtered unknown       no-response
40205/tcp filtered unknown       no-response
42069/tcp filtered unknown       no-response
44732/tcp filtered unknown       no-response
45602/tcp filtered unknown       no-response
46197/tcp filtered unknown       no-response
46297/tcp filtered unknown       no-response
48019/tcp filtered unknown       no-response
48656/tcp filtered unknown       no-response
48953/tcp filtered unknown       no-response
50033/tcp filtered unknown       no-response
50308/tcp filtered unknown       no-response
53084/tcp filtered unknown       no-response
53767/tcp filtered unknown       no-response
53831/tcp filtered unknown       no-response
57197/tcp filtered unknown       no-response
57488/tcp filtered unknown       no-response
59274/tcp filtered unknown       no-response
61990/tcp filtered unknown       no-response
62110/tcp filtered unknown       no-response
63249/tcp filtered unknown       no-response
64446/tcp filtered unknown       no-response

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 805.38 seconds
```

Navigating to 80 reveals the white rabbit from alice in wonderland
![[Pasted image 20240315083858.png]]

using ffuf to enumerate subdirectories 
```bash
ffuf -u http://10.10.40.54/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -recursion

```
reveals
- img
	- alice_door.jpg
	- alice_door.png
	- white_rabbit_1.jpg
- r
	- following the white rabbit by spelling out the rest of the word /r/a/b/b/i/t
- poem
	- the poem called 'the jabberwockey'

- viewing page source of [[http]]://ip.ip.ip.ip/r/a/b/b/i/t reveals 
	- username:password
	- alice:








"execute this file as the rabbit user". The file they imports your cutsom [random.py]([[https]]://random.py) which says "Open up a bash terminal as this user"