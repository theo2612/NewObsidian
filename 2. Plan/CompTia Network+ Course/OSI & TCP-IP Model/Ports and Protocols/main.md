TCP/IP is a protocol suite with lots of different protocols tthat make up the suite.  
Each one of those protocols has a port number assigned to them.  
A port number is a software identifier, that when the traffic gets to your system knows which application or service is needed in order to process the traffic.  
  
Purpose of Ports  
Theres an endpoint for communication.  
Not a physical port to plug into  
A Conceptual entryway into the system  
  
If one system is going to connect to another via the network, they would have a conceptual port number  
  
Port Information - memorize 2^10 (1024) & 2^16 (65,536)  
Well known ports - focus on memorizing certain ports/protocols  
0 - 1023  
The use of well known ports allows client applications to determine corresponding server application processes  
Registered Ports  
1024 - 49151 - Focus on this range  
Registered with IANA, these port numbers are used by vendors for their own proprietary services  
Dynamic Ports  
49152 - 65535  
Focus - Source ports are pulled from this range  
Dynamic or private ports that cannot be registered with IANA. This range is used for private or customized services  
These ports are sometimes called “ephemeral” ports and frequently use for source ports  
Temporary ports used to indicate a connection  
Often used as a source port number - usually over 49152  
Often used in Network address translation
