Dial Up  
PPP - Point to Point Protocol allows layer2 framing for endpoint to endpoint WAN connextion  
PPPoE encapsulates PPP frames inside Ethernet frames which can support multiple users in a LAN  
  
Authentication Protocols for Remote Access  
PAP Password Authentication Protocol - clear text - NO GOOD  
CHAP Challenge Handshake Authentication Protocol - Client responds to a Challenge from the server. The only way the client can answer correctly is if the correct password had been entered.  
EAP Extensible Authentication Protocol - Extends capabilities beyond passwords. ex. smartcards, biometrics, token devices)  
  
  
Tunneling - A function of VPN's - Tunnel encapulates one protcol within another creating a virtual network  
Provides encapsulation and can also provide securtiy services such as encryption and authentication  
Allows for routing non routable protocols and IP addresses  
![[1.png]]
  
PPTP - Point to Point Tunneling Protocol  
Based on PPP (uses MPPE for encryption and PAP, CHAP or EAP for Authentication)  
Lead by Microsoft protocol for a tunneling VPN  
Only works accross IP networks  
Remote user connects to ISP, gets an Internet Address  
Establishes VPN connection to work VPN server, get's internal IP address  
Sends private IP packets encrtypted within other IP packets  
L2TP - Layer 2 Tunneling Protocol  
Cisco designed L2F to break free of dependence on IP networks, but kept it proprietary  
L2TP was a combination of L2F and PPTP  
Designed to be implemented in software solutions  
THERE IS NO SECURITY with L2TP. It MUST use IPSec to secure  
IPSEC  
Provides the framework for services such as encryption, authentication, integrity (Any of all of these services may be provided)  
Provides encapsulation, not encryption  
What is encapsulated can be protected through the protocols within IPSec  
Tunnel Mode - Whole packet is encapsulated  
Transport Mode - Only the payload is encapsulated  
  
  
GRE  
  
SSL  
  
  
PPTP  
PAP  
CHAP  
EAP  
MPPE  
GRE  
L2TP  
IPSEC  
IPSEC