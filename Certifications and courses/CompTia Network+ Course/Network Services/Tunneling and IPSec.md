Tunneling - A function of VPN's - Tunnel encapulates one protcol within another creating a virtual network  
Provides encapsulation and can also provide securtiy services such as encryption and authentication  
Allows for routing non routable protocols and IP addresses  
![[1 2.png]]
  
PPTP - Point to Point Tunneling Protocol - Port 1723  
Based on PPP (uses MPPE for encryption and PAP, CHAP or EAP for Authentication)  
Lead by Microsoft protocol for a tunneling VPN  
Only works accross IP networks  
Remote user connects to ISP, gets an Internet Address  
Establishes VPN connection to work VPN server, get's internal IP address  
Sends private IP packets encrtypted within other IP packets  
L2TP - Layer 2 Tunneling Protocol - Port 1701  
Cisco designed L2F to break free of dependence on IP networks, but kept it proprietary  
L2TP was a combination of L2F and PPTP  
Designed to be implemented in software solutions  
THERE IS NO SECURITY with L2TP. It MUST use IPSec to secure  
IPSEC - Internet protocol Security  
Provides the framework for services such as encryption, authentication, integrity (Any of all of these services may be provided)  
Provides encapsulation, not encryption  
What is encapsulated can be protected through the protocols within IPSec  
Tunnel Mode - Whole packet is encapsulated  
Transport Mode - Only the payload is encapsulated - Less security in Tranport mode  
for use internally  
Sub-protocols  
AH - Authentication Header  
Provides integrity, authenicity and non-repudiation through the use of an ICV(Integrity Check Value). The ICV is run on the entire packet (header, data, trailer) except for particular fields in the header that are dynamic (like TTL, etc). NO CONFIDENTIALITY  
ESP - Encapsulating Security Payload  
Provides authenticity and integrity through a MAC (no non-repudiation since a MAC is symmetric). The main service provided is ENCRYPTION. ICV is run on payload only  
IKE - Internet key exchange  
No Security Services. Just management of secure connection.  
Oakley - uses Diffie Hellman to agree upon a key  
ISAKMP - Internet Security Association and Key Management Protocol Manages Keys, Security Associations (SA's) and Security Paramater Index (SPI)