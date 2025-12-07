![image]([[https]]://www.practice-labs.com/authenticated/images/N10-008/image-m0-c-2.jpg?v=54) 
![[2 1.png]]
All  
People  
Seem  
To  
Need  
Data  
Processing  
  
1. **Physical**: Ensures the physical communication between the devices and converts an electrical pulse to binary. It defines the specific standard to which the physical components must comply to. The most commonly used protocols include the following, IEEE.802.11, IEEE.802.3 and several others.  
2. **Data link**: The Data link layer provides communication between directly connected devices. It also provides error handling for the OSI model's physical layer. It consists of two sub-layers, Media Access Control (MAC) and the Logical Link Control (LLC) layers. Most switches operate on the Data link layer or Layer 2 for communication, but there are exceptions where switches can also work on Layer 3 and are referred to as a Layer 3 switch where routing capabilities are required.  
3. **Network**: Routers function on the Network layer. This layer is responsible for forwarding packets to specific routes on the network. This layer analyses the packets received and determines if it has reached its destination and then passes it to the Transport layer. If it is not the final destination, it will pass it to the Data link layer until it reaches its final destination. The Network layer is also responsible for updating routing tables.  
4. **Transport**: The Transport layer’s function is to deliver data across network connections. The most commonly used protocols are TCP (Transmission Control Protocol) and UDP (User Datagram Protocol). Different protocols will have different functionalities when transporting data across the network. For example, error checking is done using the TCP protocol.  
5. **Session**: The OSI model's Session layer manages the flow and sequence of different network connections. This ensures the possibility for dynamic concurrent connections.  
6. **Presentation**: The simplest part of the OSI model is the Presentation layer, as it handles the processing and converting of the data, for example, encryption and decryption, to facilitate the support for the Application layer.  
7. **Application**: The final layer in the OSI model, the Application layer, provides network services to the application. These services include protocols that integrate into the application; for example, the [[HTTP]] protocol is used to deliver data to a web browser to display a user's web page.  
  
  
![[3 1.png]]
  
[[[https]]://sites.google.com/site/osimodellayers/layer-3---network]([[https]]://sites.google.com/site/osimodellayers/layer-3---network)  
[[[https]]://community.cisco.com/t5/image/serverpage/image-id/34062i95AA8ACC6BD9290D/]([[https]]://community.cisco.com/t5/image/serverpage/image-id/34062i95AA8ACC6BD9290D/)  
  
OSI TCP/IP - Comes from DoD (Department of Defense)  
1 Physical Please Network Never  
2 Data Link Do Network  
3 Network Not Internet Ingest  
4 Transport Throw Transport Toxic  
5 Session Sausage Application Apples  
6 Presentation Pizza Application  
7 Application Away Application  
  

![image]([[https]]://i.imgur.com/aeXulzE.png)

  
   
[[[http]]://www.gocertify.com/quizzes/osi/]([[http]]://www.gocertify.com/quizzes/osi/)  
  
**Physical Layer- Layer 1**  
What we can touch, measure and see  
Uses logical addresses to route data  
   
PDU/Protocol Data Unit - Bit / 1, 0  
This layer converts packets from the data link layer into electrical signals  
Cables  
NIC - Network Interface Card  
   
Ethernet settings  
Network and Sharing Center  
Change adapter settings  
Network Connections  
Right click Ethernet - Properties - Configure  
Details  
Property - Hardware IDs  
Is Connected  
If true - Physical connection looks good  
  
**Data Link - Layer 2**  
Provides point to point connectivity within our network  
Ex - packets to a switch,  
   
PDU/Protocol Data Unit - frame- Segment of data with beginning and end  
The Data Link layer is composed of two sublayers: the Logical Link Control (LLC) lower sublayer and the Media Access Control (MAC) upper sublayer. Components/protocols relevant to the Data Link layer include driver details, MAC filtering, and ARP tables.  
Responsible for framing, error detection and physical addressing  
A MAC address is a 12 digit hexadecimal number, which is a physical address of the network components.  
Switches operate at this level and maps to MAC address  
EUI-64 (Extended Unique Identifier) - IPv6 global unicast  
Multi-layer switches operate at Data-link layer 2 and Network layer 3 layers  
Hub operate at this level - pass info to everyone on network  
Bridges operate at this level - point to point  
   
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
   
**Network layer-**  
 IP addressing / Routing  
PDU/Protocol Data Unit - Packets, Segment of data.  
examine components of the Network layer of the OSI model. These components include the IP address, subnet mask, and default gateway for a device. Configuration details of the IPv4 and IPv6 protocols are a part of the Network layer.  
IP addresses are logical addresses mapped to a physical component  
Routers work at this level - Sometimes called layer 3 switch - Moves data across networks  
Responsible for routing and IP addressing  
Multi-layer switches operate at Data-link layer 2 and Network layer 3 layers  
   
   
 ipconfig /all  
View IPv4 address - The IPv4 address is a private IP address and can only be used on internal networks (not on the Internet)  
Subnet Mask -   indicates that the range of IP addresses in the same subnet are from  
Default gateway -  
   
Change Network layer addresses  
Right click internet on task bar  
Open Network and Internet settings  
Ethernet settings  
Network and Sharing Center  
Change adapter settings  
Click Ethernet 2 link  
Properties  
Select Internet Protocol Version 4 (TCP/IPv4)  
Properties  
Here you can change IP address, Subnet mask, Default gateway  
   
--check ipconfig /all for changes  
   
**Transport layer-**  
TCP/UCP for management and sending of our data  
Flow control take place at this level  
   
Error detection and recovery take place at this layer  
   
PDU/Protocol Data Unit - Segment or Datagram  
Protocols operating at the Transport layer include netstat and UDP  
   
Netstat - This command lists the TCP sessions currently running on the device.  
   
Cmd  
>netstat  
View all TCP sessions currently running on the device  
   
 create a new TCP session navigate to  
[[[https]]://www.[[comptia]].org]([[https]]://www.[[comptia]].org)  
   
>netstat  
Make note of new TCP sessions running  
Under foreign address - Intranet [[HTTP]]  
   
>netstat -p udp  
View all the services using UDP - DHCP, [[DNS]], [[SNMP]]  
  
**Session Layer-**  
Provides connection management. Handshake, initiation, maintaining, who talks when  
This layer establishes, maintains, and terminates communications between applications located on different devices  
The session layer provides mechanism to open, close and manage communication session between end-user applications. Communication sessions consist of requests and responses between applications.  
NFS/Network File system  
   
**Presentation Layer-**  
Formats data so it can be sent over a network, standardized or encrypted, or when received are formatting it so we can read it/put on computer and understand it  
Protocols - referring to presenting file types to the user , audio, visual, text etc  
   
The presentation layer is responsible for formatting and delivering information to the application for further processing or display. It relieves the application layer of concern regarding syntactical differences in data representation within the end-user systems.  
Encryption device operates at this level - Formats data  
   
Examples of these layers functioning within the [[Windows]] environment include the use of NetBIOS names for the Session layer and character code translation such as from ASCII to EDCDIC and back.  
   
For the most part these functionalities cannot be directly viewed within a [[Windows]] environment as most [[Windows]] network components are structured around the TCP/IP model and as such, these layers are included within the Application layer.  
   
**Application Layer-**  
Different protocols that manage how applications are allowed to send and receive over the network.  
They manage how data is able to create sessions and use resources  
Allows our application  communicate with our network  
[[HTTP]], POP#3 [[SMTP]]  
   
Ethernet  
[[Windows]] Firewall link  
Advanced settings  
[[Windows]] defender firewall with advanced security  
Right pane - inbound rules  
Middle pane- These are network-aware applications that service the user applications utilized by the person operating the device.  
Core Networking - Dynamic Host Configuration Protocol (DHCP-In)  
Remote Desktop - User Mode  
[[SNMP]]  
Cast to Device streaming server ([[HTTP]]-Streaming-In)  
   
Task manager  
More details  
Processes pane  
[[Windows]] processes  
Service host process -  
that this process is running for the [[DNS]] Client, Network Location Awareness, as well as the Hyper-V Remote Desktop Virtualization Service. All these are network applications and services that require this process to run.  
   
This process runs just below the network-aware applications such as web browsers, email clients, Remote Desktop clients, and other such software packages. This is the Application layer of the OSI model in action.  
  
   
[[TryHackMe]] - OSI model review  
The OSI (Open Systems Interconnection) Model is a standardised model which we use to demonstrate the theory behind computer networking. In practice, it's actually the more compact TCP/IP model that real-world networking is based off; however the OSI model, in many ways, is easier to get an initial understanding from.  
  
The OSI model consists of seven layers:  
  
Table showing the OSI layers: Application, Presentation, Session, Transport, Network, Data Link, Physical  
  
There are many mnemonics floating around to help you learn the layers of the OSI model -- search around until you find one that you like.  
  
I personally favour: Anxious Pale Shakespeare Treated Nervous Drunks Patiently  
  
Let's briefly take a look at each of these in turn:  
  
Layer 7 -- Application:  
  
The application layer of the OSI model essentially provides networking options to programs running on a computer. It works almost exclusively with applications, providing an interface for them to use in order to transmit data. When data is given to the application layer, it is passed down into the presentation layer.  
  
Layer 6 -- Presentation:  
  
The presentation layer receives data from the application layer. This data tends to be in a format that the application understands, but it's not necessarily in a standardised format that could be understood by the application layer in the receiving computer. The presentation layer translates the data into a standardised format, as well as handling any encryption, compression or other transformations to the data. With this complete, the data is passed down to the session layer.  
  
Layer 5 -- Session:  
  
When the session layer receives the correctly formatted data from the presentation layer, it looks to see if it can set up a connection with the other computer across the network. If it can't then it sends back an error and the process goes no further. If a session can be established then it's the job of the session layer to maintain it, as well as co-operate with the session layer of the remote computer in order to synchronise communications. The session layer is particularly important as the session that it creates is unique to the communication in question. This is what allows you to make multiple requests to different endpoints simultaneously without all the data getting mixed up (think about opening two tabs in a web browser at the same time)! When the session layer has successfully logged a connection between the host and remote computer the data is passed down to Layer 4: the transport Layer.  
  
Layer 4 -- Transport:  
  
The transport layer is a very interesting layer that serves numerous important functions. Its first purpose is to choose the protocol over which the data is to be transmitted. The two most common protocols in the transport layer are TCP (Transmission Control Protocol) and UDP (User Datagram Protocol); with TCP the transmission is connection-based which means that a connection between the computers is established and maintained for the duration of the request. This allows for a reliable transmission, as the connection can be used to ensure that the packets all get to the right place. A TCP connection allows the two computers to remain in constant communication to ensure that the data is sent at an acceptable speed, and that any lost data is re-sent. With UDP, the opposite is true; packets of data are essentially thrown at the receiving computer -- if it can't keep up then that's its problem (this is why a video transmission over something like Skype can be pixelated if the connection is bad). What this means is that TCP would usually be chosen for situations where accuracy is favoured over speed (e.g. file transfer, or loading a webpage), and UDP would be used in situations where speed is more important (e.g. video streaming).  
  
With a protocol selected, the transport layer then divides the transmission up into bite-sized pieces (over TCP these are called segments, over UDP they're called datagrams), which makes it easier to transmit the message successfully.  
  
Layer 3 -- Network:  
  
The network layer is responsible for locating the destination of your request. For example, the Internet is a huge network; when you want to request information from a webpage, it's the network layer that takes the IP address for the page and figures out the best route to take. At this stage we're working with what is referred to as Logical addressing (i.e. IP addresses) which are still software controlled. Logical addresses are used to provide order to networks, categorising them and allowing us to properly sort them. Currently the most common form of logical addressing is the IPV4 format, which you'll likely already be familiar with (i.e 192.168.1.1 is a common address for a home router).  
  
Layer 2 -- Data Link:  
  
The data link layer focuses on the physical addressing of the transmission. It receives a packet from the network layer (that includes the IP address for the remote computer) and adds in the physical (MAC) address of the receiving endpoint. Inside every network enabled computer is a Network Interface Card (NIC) which comes with a unique MAC (Media Access Control) address to identify it.  
  
MAC addresses are set by the manufacturer and literally burnt into the card; they can't be changed -- although they can be spoofed. When information is sent across a network, it's actually the physical address that is used to identify where exactly to send the information.  
  
Additionally, it's also the job of the data link layer to present the data in a format suitable for transmission.  
  
The data link layer also serves an important function when it receives data, as it checks the received information to make sure that it hasn't been corrupted during transmission, which could well happen when the data is transmitted by layer 1: the physical layer.  
  
Layer 1 -- Physical:  
  
The physical layer is right down to the hardware of the computer. This is where the electrical pulses that make up data transfer over a network are sent and received. It's the job of the physical layer to convert the binary data of the transmission into signals and transmit them across the network, as well as receiving incoming signals and converting them back into binary data.