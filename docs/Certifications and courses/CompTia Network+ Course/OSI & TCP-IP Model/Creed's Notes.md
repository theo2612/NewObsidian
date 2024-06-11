Here is a simplified example of what the OSI Layers look like and what each layer does. All the layers are essential for us to be able to go on the internet. Each layer has a purpose that allows us to do our daily tasks.  
  
The diagram on the left is a good example of the OSI 7 Layer System. The diagram also has some examples for each layer and how each layer works. With the help of the diagram we can get a basic understanding of the OSI 7 Layer System.  
  
Layer 1 — Physical  
  
The first layer of the Open System Interconnection Model covers all physical aspects of the network. This includes the wiring/cabling of the system, the bit stream and the hardware. The specific services in which this layer provides includes:  
  
Signal converting for physical transmission (encoding and decoding physical signals)  
  
Bit by bit transmission  
  
Line coding  
  
Synchronisation of bits  
  
Transmission mode control  
  
Collision detection  
  
Carrier sensing  
  
The physical layer must encode a signal into an analogue signal to be transmitted. Depending on the mode of transmission (wired or wireless), the signal will be converted to either electrical pulses, light, or electromagnetic waves.  
[9:33 AM]  
Layer 2 — Data Link  
  
Secondly, the Data Link layer handles the links and transfer of data in/out the physical network. The bits of data sent from the physical layer are encoded, decoded, organised and checks for problems. Depending on which way the data is travelling (sent or receiving), the data will either be encoded to be sent to physical or decoded being sent from physical.  
  
This layer breaks down into 2 more sub layers:  
  
Logical Link Control  
  
Media Access Control  
  
Media access control oversees permissions for the data, granting or denying access to devices.  
  
Logical Link Control maintains the data flow among services including the preparation of data for transport, identifying protocols of the network layer and “framing” of data. Synchronisation of data and error checking are also handed by this layer.  
  
Packets of data from the Network layer are framed, giving them a header and trailer. The header includes the destination address, and type of data.  
[9:33 AM]  
Layer 3 — Network  
  
Seen as the backbone of the entire system, the network layer’s purpose is to provide data routing paths for packets of data to be transferred. It manages the best logical path for data transfer between nodes.  
  
Some of the communication protocols of this layer include:  
  
IP (Internet protocol) (v4/v6)  
  
IPX (Internetwork Packet Change)  
  
ICMP (Internet Control Message Protocol)  
  
IPSec (Internet Protocol Security)  
  
Network layer protocols exist in every host or router. The router examines the header fields of all the IP packets that pass through it.  
[9:33 AM]  
Layer 4 — Transport  
  
The transport layer provides the transport of the data between users. This is an important layer of the OSI System as it controls the reliability of the data that is send through the flow control.  
  
The transport layer is also responsible for managing error correction, providing the end user’s quality and reliability. This layer allows the host to send and receive correct data, packets or messages over a network, and is the network component that allows multiplexing.  
  
The transport layers work transparently within the above layers to deliver and receive error-free data. The sender pauses application messages into segments and sends them to the network layer. The inviting part reassembles segments in messages and transmits them to the application level.  
  
The transport layer may offer some or all the following services:  
  
Same Delivery Order: Ensures that packets are always delivered in strict sequence. Although the network layer is responsible, the transport layer can fix any discrepancies in sequence caused by packet drops or device interruption.  
  
Data Integrity: Using checksums, the data integrity across all the delivery layers can be ensured.  
  
Flow Control: Devices at each end of a network connection often have no way of knowing each other’s capabilities in terms of data throughput and can therefore send data faster than the receiving device is able to buffer or process it.  
  
Traffic Control: Digital communications networks are subject to bandwidth and processing speed restrictions, which can mean a huge amount of potential for data congestion on the network. This network congestion can affect almost every part of a network. The transport layer can identify the symptoms of overloaded nodes and reduced flow rates.  
[9:33 AM]  
Layer 5 — Session  
  
In the Open Systems Interconnection (OSI) model, the session layer is the fifth layer, which controls the connections between multiple computers. The session layer tracks the dialog’s between computers, which are also called sessions. This layer establishes, controls and ends the sessions between local and remote applications.  
  
The session layer manages a session by initiating the opening and closing of sessions between end-user application processes. This layer also controls single or multiple connections for each end-user application, and directly communicates with both the presentation and the transport layers. The services offered by the session layer are generally implemented in application environments using Remote Procedure Calls (RPCs). Sessions are most implemented on Web browsers using protocols such as the Zone Information Protocol, the AppleTalk Protocol and the Session Control Protocol.  
  
These protocols also manage session restoration through checkpointing and recovery.  
  
The session layer supports full-duplex and half-duplex operations and creates procedures for checkpointing, adjournment, restart and termination. The session layer is also responsible for synchronising information from different sources. For example, sessions are implemented in live television programs in which the audio and video streams emerging from two different sources are merged. This avoids overlapping and silent broadcast time.  
[9:33 AM]  
Layer 6 — Presentation  
  
The Presentation layer takes care of the encryption, presentation and working out the right file formats needed. This is the Translation Layer that we need to get the data from the internet.  
  
Residing at Layer 6 of the Open Systems Interconnection (OSI) communications model, the presentation layer ensures that the communications that pass through it are in the appropriate form for the recipient application. In other words, it presents the data in a readable format from an application layer perspective.  
  
For example, a presentation layer program could format a file transfer request in binary code to ensure a successful file transfer. Because binary is the most rudimentary of computing languages, it ensures that the receiving device will be able to decipher and translate it into a format the application layer understands and is expecting. The application layer passes data meant for transport to another device in a certain format. The presentation layer then prepares this data in the most appropriate format the receiving application can understand.  
  
Common formats include ASCII and extended binary-coded decimal interchange code (EBCDIC) for text, it can also be called Extended ASCII.; JPEG, GIF and TIFF for images; and MPEG, MP4 and QuickTime for video.  
  
Encryption and decryption of data communications are also commonly performed at the presentation layer. Here, encryption methods and keys are exchanged between the two communicating devices. Thus, only the sender and receiver can properly encode and decode data, so it returns to a readable format.  
[9:34 AM]  
Layer 7 — Application  
  
The Seventh Layer also known as the Application layer and it handles the end user processes. This layer takes care of the communication, identification, connectivity and privacy between the two services.  
  
Positioned at Layer 4 of the Open Systems Interconnection (OSI) communications model, the transport layer ensures the reliable arrival of messages across a network and provides error-checking mechanisms and data flow controls.  
  
The transport layer takes application messages and transmits those message segments into Layer 3, the networking layer. Once the receiving side has the segments, they are reassembled into messages and passed on to Layer 7, the application layer.  
  
The functions of the transport layer are:  
  
Connection mode and connection less mode transmissions. For connection mode transmissions, a transmission may be sent or arrive in the form of packets that need to be reconstructed into a complete message at the other end. Connection mode transmissions also require acknowledgement from the receiving device as an assurance.  
  
The Transmission Control Protocol (TCP) is the most common form of connection-oriented transmission today. The connections are identified and tracked using port numbers that range between 0 and 65,535. One useful benefit of TCP is that it uses a positive acknowledgement with re-transmission technique where the receiving device must respond back to the sender that it indeed received the data it was sent.  
  
The User Data Protocol (UDP) is an example of a connection-less-oriented protocol. Similar to TCP, UDP uses port numbers between 0 and 65,535 for identification and tracking of data transmission streams. But unlike TCP, which requires acknowledgement from the receiving device, UDP provides no guarantee mechanism. Because of this, UDP is ideal for real-time, streaming data transmissions, like voice and video conferencing.  
  
Same order delivery. This makes sure packets are delivered in a specific sequence. Each packet is given a number and the receiver reorders the packets.  
  
Data integrity. There are various ways packets might be lost or corrupted. Packets may also be delivered in the wrong order. Using error detection codes, such as a checksum, the transport layer ensures the data is not corrupted by sending an acknowledgement message to the sender.  
  
Flow control. The sending device may transmit data at a faster rate than the memory capacity on the receiving device is able to process. In order to avoid having the receiving device overwhelmed with data, flow control manages the traffic so that it’s at an acceptable rate. It also addresses data flow when the receiver is not getting data fast enough.  
  
Congestion avoidance. The transport layer manages traffic and circumvents congestion by understanding where nodes or links are oversubscribed and then taking the proper steps to reduce the rate at which packets are sent, among other remedies.  
  
Multiplexing. Packet streams can come from unrelated applications and a variety of sources. This permits the use of different applications or services across a network, such as when a user opens different browsers on the same computer.