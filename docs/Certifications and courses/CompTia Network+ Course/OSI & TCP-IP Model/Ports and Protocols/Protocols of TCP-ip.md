File Transfer Protocol - FTP  
Operates on TCP Ports 20 21  
Not secure!  
Standard network protocol used for transferring computer files  
Built on client-server architecture  
Can be encrypted/secured through SSL/TLS or SSH  
FTP - TCP Connection oriention  
TFTP - UDP connectionless  
  
Secure Shell - SSH  
Operates on TCP port 22  
SCP and S/FTP both use SSH and also use port 22  
Two major versions - SSH-1 & SSH-2  
Graphical Network Protocol  
Used over unsecure networks  
Includes remote command line login & execution  
Uses a Client-Server Architecture  
  
Telnet  
Operates on TCP port 23  
Not Secure! - Transmits in plain text  
Stands for Teletype Network  
Used on the Internet of on a Local Area Network  
One of the first internet standards  
Used to establish a connection to TCP  
  
Simple Mail Transfer Protocol - SMTP  
Operates on TCP port 25 (there are othe commonly used ports now)  
Operates at the Application Layer  
Communication protocol for email transmission  
Widely used today in email servers and other message transfer agents  
Used to send and receive emails and uses TCP  
Used to send email fom mail server to mail server - UP or Side to side  
“Send Mail To People”  
  
Terminal Access Controlller, Access Contol System - TACACS+  
Operates on TCP port 49  
Separates the authentication, authorization and accounting functions  
Supports authorization of router commands on a per user or per group basis  
Uses TCP and encrypts the entire body of the packet  
  
Domain Name(ing) Service - DNS  
Operates at Port53  
A naming system used by computers and services connected to the internet  
Hierarchical and decentralized in structure  
Associated domain names assigned to participating computers and services  
Servers as the Phone Book for the internet by translating human friendly hostnames and IP addresses.  
  
Dynamic Host Configuration Protocol - DHCP  
Operates on TCP port 67 68  
A network management protocol used on IP networks  
DHCP servers assign IP address and other network configuration parameters  
Allows computers to request IP addresses  
Without DHCP, IP addresses for network devices need to be manually assigned.  
DORA - Discover, Offer, Request, Acknowledge  
  
Trivial File Transfer Protocol - TFTP  
Operates on Port 69  
Simple FTP that allows clients to file(s) from a remote host  
Primarily used in early stages of compter booting in a LAN  
TFTP - UDP connectionless  
FTP - TCP Connection oriention  
  
Hypertext Transfer Protocol - HTTP  
Operates at Port 80  
Operates on the Application Layer  
Not Secure!  
An Application Protocol  
Used for distributed, collaborative, hypermedia infomation systems  
Foundation of communication for the World Wide Web  
Designed to permit network elements to improve or enable communications between clients and servers  
  
Post office protocol - POP  
Uses port 110  
Used when a client system downloads mail from the mail server  
Currently (2021) using version POP3  
  
Network Time Protocol - NTP  
Operates Port 123  
Used to synchronize network systems  
Managing, securing, planning and debugging require accurate timing  
Kerberos, particularily, require time synchronization  
  
Internet Mail Application Protocol - IMAP  
Operates at Port 143  
Used to download email from mail server  
  
Simple Network Management Protocol - SNMP  
Operates at Port 161  
Agent - network devices contain SNMP agents  
Central Manager - A manager or management system responsible to communicate with the SNMP agent implemented network devices  
Management Information Base (MIB) - Every SNMP agent maintains an information database describing the managed device parameters. The SNMP manager uses this database to request the agent for specific information and further translates the information as needed for the Network Management System (NMS).  
Only version 3 uses encryption to secure information  
  
Lightweight Directory Access Protocol - LDAP  
Uses Port 389 or 636 (secure LDAP)  
Hierarchical Structure used for Directory Services  
Database format/structure for Active directory or other directory services  
LDAP think Domain Controller/Windows or Authentication Server  
LDAP is the protocol that allows the hierachical stucture of organizations/servers  
  
Hypertext Transfer Protocol Secure - HTTPS  
Uses Port 443  
Uses SSL and TLS (1.2 and 1.3 currently) protocols to provide secure transmission of information across the internet  
  
Remote Authentication Dial-In User Services - RADIUS  
Uses 1812 and 1813 and operates at the Application layer  
Provides Central Authentication for remote devices like dial-up, VPN and Wi-Fi clients  
Similar to TACACS+ - Radius alllows a centralized location to confiugure policies an rules  
RADIUS only encrypts a piece of data, which includes the authentication information (password)  
Supplicant - device that initiates the connection. The remote device that wants to connect to the local area network.  
Supplicant has to connect to an Authenticator  
Wi-Fi coinrnetc to access point  
dial up connects to a remote access server  
VPN connects to a VPN server  
The polices and decsions are made on the Authenticator/VPN server, Remote access point.  
similar Protocol DIAMETER  
  
Remote Desktop Protocol - RDP  
Uses port 3389  
Provides a user with a graphical interface to connect to another computer over a network connection  
Dangerous if unfettered from outside the network  
  
Realtime Transfer Protocol (RTP)  
Uses port 5004, 5005  
handles real time traffic, like audio and video, of the internet  
RTP must be used with UDP  
supports MPEG and MJPEG  
helps in media mixing, sequencing and time-stamping  
Voice over Internet Protocol - VoIP  
Video Teleconferencing over the internets  
Internet Audio and Video Steaming

![image](https://i.imgur.com/VsA4P4S.png)