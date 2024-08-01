# 1.1 Applications
- Groups of people who interact with the Internet
	- Users
	- Those who create applications
	- Those who operate or manage networks
	- Those who design and build devices and protocols that collectively make up the internet. 
- Classes of applications of the internet
	- Web
		- Webpages
		- Static images, links, text
	- Streaming of audio and video
		- Netflix, youtube.
		- The whole video file doesn't download at once.
	- Real-time Audio and video
		- Zoom, videoconferencing
		- even tighter constraints than streaming

# 1.2 Requirements
- Stakeholders and what they would list their requirements for a network
	- Application programmer
		- Services that their application needs
		- 
	- Network operator
		- Characteristics of a system that are easy to administer and manage
	- Network designer
		- Properties of a cost effective design
- Scale 
	- A system that is designed to support growth to an arbitrarily large size 
- Link 
	- a physical medium that directly connects 2 or more computers on a network
- nodes
	- Can be computers or other pieces of specialized hardware. 
	- pair of nodes are 'point to point'
	- more than 2 nodes are 'multiple-access'
- Types of networks
	- Direct Links
		- Point to Point
		- Multiple-access
	- Circuit switched
		- Telephone system
		- Optical networking
		- Nodes establish a dedicated circuit across a sequence of links and then allows. Then allows the source node to send a stream of bits across the circuit to the destination node
	- Packet Switched
		- Computer networks
		-  Use store and forward 
			- Each node receives complete packet, stores in internal memory & forwards complete packet to next node.
- Network definitions
	- nodes 
		- Switches are inside the network 
			- implement the network
			- primary function to store and forward packets
		- Hosts are outside the network
			- use the network
			- support users and run application programs
		- Router or Gateway
			- A node that is connected to two or more networks
			- same role as a switch where it forwards messages from one network to another. 
		- Address
			- must be assigned to each node on a network
			- a byte string that identifies a node
		- Routing 
			- The process of determining systematically how to forward messages toward the destination node based on its address
		- Unicast
			- A source node that sends a message to a single destination node
		- Multicast
			- A source node that wants to broadcast a message to all nodes on a network 
			- A source node that wants to broadcast a message to a subset nodes but not all of them.
	- Multiplexing
		- When a system resource is shared among multiple users
		- Synchronous Time-Division multiplexing / STDM
			- Dividing time into equal-sized quanta
			- In round robin fashion, giving each flow a chance to send its data over the physical link.
				- 
		- Frequency-division multiplexing / FDM
			- Transmitting each flow over the physical link at a different frequency
			- Similar way that the signals for different TV stations are transmitted at different frequencies over the airwaves
		- 











