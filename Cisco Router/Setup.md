Write python script to automatically configure router  
  
Check which port the serial cable is plugged into = USB Serial Port  
Device Manager or Win+R, devmgmt.msc, Ports, (COM3)  
 ![[1b98c16e6d26d9d60381e301dbcdc46b.png]]
  
wipe startup config  
>do erase startup-config  
  
restart  
>do reload  
  
>Would you like to enter the intitial configuration dialog- NO  
  
view version  
#do show version  
  
enable privlaged exec mode  
>enable  
  
open global settings  
>configure terminal  
(configure)#  
  
assign hostname  
#hostname (name) (HackBot1337)  
  
show summary of interfaces  
#do show ip interface brief  
  
show interface types  
#interface ?  
  
interface FastEthernet 0/1 = LAN  
  
setup interface FastEthernet 0/1  
#interface FastEthernet 0/1  
#ip address 192.168.1.1 255.255.255.0  
  
bring up FastEthernet port 0/1  
#interface FastEthernet 0/1  
#ip nat inside  
#no shutdown  
  
FastEthenet 0/0 = WAN  
  
setup interface FastEthernet 0/0  
#ip address dhcp  
  
set default gateway  
#ip default-gateway 192.168.0.1  
  
save start up configuration  
#copy running configuration / copy run config  
  
Disable on screen error commands  
#no logging console  
Enable on screen error commands  
#logging console