Network Attached Storage - NAS  
Network Appliance that provides file level storage  
Files are accessed through network protocols such as  
[[SMB]] - Server Message Blocks  
NFS - Network Filing System  
![[1.png]]
  
Storage Area Network - SAN  
Storage Architectures  
Components-  
Host Layer  
Fabric Layer  
Storage Layer  
![[2.png]]
  
How do you connect to the Storage Area Network - SAN?  
Fibre Channel over Ethernet (FCoE)  
Fibre Channel fabric is a switched network topology that interconnects FC devices (Usually servers of storage devices) using FC switches, usually to create a SAN.  
A FC switch is a Layer 3 network switch that is compatible with the FC protocol, forwards FC traffic and provides FC services to the components of the FC fabric  
Switches called FCoE forwarders (FCF's) perform a subset of FC switch functions. A FCF is a Layer3 network switch that is compatible with the FC protocol and forwards FC traffic but does not provide network services;  
 ![[3.png]]
  
Internet Small Computer Systems Interface - (iSCSI)  
Works across existing infrastructure as an extension to the SCSI bus  
Logical Unit number: is a virtual address pointing to a storage address which tells the system which drive/volume to send and read from  
![[4.png]]
  
InfiniBand  
InfiniBand is a networking communications standard used in high-performance computing featuring throughput and low latency  
It is used for data interconnect both internally and between computers  
InfiniBand can also be used as either a direct or switched connection between servers and storage systems, such as SAN's  
  
Jumbo Frames  
Increase performance to SAN's as more data can be sent in less time  
![[5.png]]