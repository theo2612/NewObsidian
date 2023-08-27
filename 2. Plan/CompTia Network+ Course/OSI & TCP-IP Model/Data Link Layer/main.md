**Data Link - Layer 2**  
Provides point to point connectivity within our network  
Responsible for framing, error detection and physical addressing  
Ex - packets to a switch,  
PDU/Protocol Data Unit - frame- Segment of data with beginning and end  
  
The Data Link layer is composed of two sublayers:  
1. Logical Link Control (LLC) lower sublayer - Provides a standard interface regardless of what MAC sublayer is used  
2. Media Access Control (MAC) upper sublayer.  
1) 802.3 - Ethernet  
1- CSMA/CD - Carrier Sense Multiple Access with Collision Detection  
2- COLLISIONS  
3) 802.5 - Token Ring  
1- Proprietary IBM  
2- 2 24 bit control frame on the network. Moving form host to host. If a system wanted to communicate, it would capture the token, then put it's message out there. there was only one token and you couldn't transmitt with out it. So No collisions in a token passing environment.  
3- NO COLLISIONS  
5) 802.11 -Wireless  
1- CSMA/CA - Carrier Sense Multiple Access with Collision Avoidance  
2- multiple system can sense that at the same time but they send an intent message “Hey I'm getting ready to send, is that cool with everyone?”, if there are no other host replying that they are sending too, the device transmits its information.  
3- NO COLLISIONS  
6) 802.12 - Polling  
1- Not really used  
  
Components/protocols relevant to the Data Link layer include driver details, MAC filtering, and ARP tables.  
MAC addressing and Media access - which system gets to communicate and when  
  
A MAC address is a 48bit address expressed in a 12 digit hexadecimal number, which is a physical address of the network components.  
First 6 characters (24bits) are the OUI (Orginzational Unique Identifier)  
Last 3 characters ( are sequential hex values assigned to each individual network chip)  
EUI-64 (Extended Unique Identifier) - IPv6 global unicast  
Critcal for a host receiving data  
  
ARP- Address Resolution Protocol  
Broadcasts “hey is anyone xxx.xxx.xxx.xxx?”  
and waits for a response from a MAC address - "That me Here is my IP xxx.xxx.xxx.xxx"  
This address is then stored in ARP cache  
  
Devices  
Multi-layer switches operate at Data-link layer 2 and Network layer 3 layers  
Hub operate at this level - pass info to everyone on network  
Bridges operate at this level - point to point  
Switches operate at this level and maps to MAC address
