Troubleshooting  
Driver  
Ethernet settings  
Network and Sharing Center  
Change adapter settings  
Network Connections  
Right click Ethernet - Properties - Configure  
Driver  
Driver Details - Make  
 the LLC sublayer is implemented in the driver of the interface. The LLC takes care of the error-free transfer of data frames from one node to the other.  
   
 cmd  
-Viewing the MAC address of machine  
>ipconfig /all  
   
Ethernet adapter Ethernet  
Physical Address = MAC address of machine  
   
-There are several protocols that function at the Data Link layer. One of these is the Address Resolution Protocol (ARP). This protocol determines the MAC address that corresponds to the appropriate IP address.  
   
>arp -a  
 - shows arp table with corresponding MAC addresses