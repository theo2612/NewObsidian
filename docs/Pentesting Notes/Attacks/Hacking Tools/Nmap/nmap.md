65535 ports on any network enabled computer  
1024 well known ports
# TCP Connect Scan -sT
- We are interested in learning whether the TCP port is open, not establishing a TCP connection. Hence the connection is torn as soon as its state is confirmed by sending a RST/ACK. 
- TCP connect scan works by completing the TCP 3-way handshake. In standard TCP connection establishment, the client sends a TCP packet with SYN flag set, and the server responds with SYN/ACK if the port is open; finally, the client completes the 3-way handshake by sending an ACK.

# Syn scan -sS  
- Unprivileged users are limited to connect scan. However, the default scan mode is SYN scan, and it requires a privileged (root or sudoer) user to run it. SYN scan does not need to complete the TCP 3-way handshake; instead, it tears down the connection once it receives a response from the server. Because we didn’t establish a TCP connection, this decreases the chances of the scan being logged. 

# UDP scan -sU  
- UDP is a connectionless protocol so it does not require any handshake for connection establishment. No guarantee that a service listening on a UDP port would respond to our packets. 
- But if a UDP packet is sent to a closed port, and ICMP port unreachable error (type 3, code 3) is returned

# OS scan -O
* Operating System Scan

# version of services -sV  
* Services version scan

# Verbosity Scan -v
* increase verbosity -v
* verbosity level 2 -vv

# Save nmap results in 3 major formats 
* -oA
* save nmap results in normal format -oN
* save results in grepable format -oG  

# Aggressive scans 
* activate aggressive mode -A  
* set timing template to level 5 -T5  

# Specify ports
* only scan port 80 -p 80  
* scan ports 1000-1500 -p 1000-1500  
* scan all ports -p-  

# Scripts
activate a script from nmap scripting library --script  
activate all of the scripts in the "vuln" category --script=vuln


| Port Scan Type |	Example Command|
| ---|---|
| TCP Connect Scan |nmap -sT MACHINE_IP |
| TCP SYN Scan | sudo nmap -sS MACHINE_IP |
| UDP Scan |sudo nmap -sU MACHINE_IP |

These scan types should get you started discovering running TCP and UDP services on a target host.
| Option | Purpose |
| --- | --- |
| -p- | all ports |
| -p1-1023 |scan ports 1 to 1023 |
| -F | 100 most common ports |
| -r |	scan ports in consecutive order |
| -T<0-5> |	-T0 being the slowest and T5 the fastest |
| --max-rate 50 |	rate <= 50 packets/sec |
| --min-rate 15 |	rate >= 15 packets/sec |
| --min-parallelism 100  |	at least 100 probes in parallel |

![[NMAP_Class.pdf]]