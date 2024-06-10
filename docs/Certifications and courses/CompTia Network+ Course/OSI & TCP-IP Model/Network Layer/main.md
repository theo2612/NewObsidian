**Network layer-** **Layer 3**  
   
IP addressing / Routing  
PDU/Protocol Data Unit - Packets, Segment of data.  
examine components of the Network layer of the OSI model. These components include the IP address, subnet mask, and default gateway for a device. Configuration details of the IPv4 and IPv6 protocols are a part of the Network layer.  
IP addresses are logical addresses mapped to a physical component  
Routers work at this level - Sometimes called layer 3 switch - Moves data across networks  
Responsible for routing and IP addressing  
Multi-layer switches operate at Data-link layer 2 and Network layer 3 layers  
  
Protocols - currenty most protocols that start with I operate at level 3 (Except for IMAP)- ICMP, IGRP, IGMP, IPSec  
If involving IP addressing it will typically be network  
  
IP - Internet Protocol - IPv4 IPv6  
Provides logical network and host addressing  
Most routers today use IP for routing data through the network  
IPConfig for Windows / IFConfig for linux  
  
ICMP - Internet Control Messaging Protocol  
Responsible for echoing utillities like Ping, Tracert, traceroute  
Ping is used to test basic physical connectivity for local and remote hosts  
If a ping fails perhaps use Tracert / Traceroute to see the hops to diagnose the problem  
where the ping fails  
Tracert for Windows, Traceroute for Linux - Chases hops through routers  
Ping a local computer on my network - If I can reach it, great!  
Then I'll ping a remorte computer - One on the other side of the router / If I can't raeach that remote host I'll use Tracert/Traceroute so I can see the message leave from me  
Goes to Router 1, Goes to Router 2, Then It doesn't look like it will pass router 3
