**Presentation Layer- Layer 6**  
3 Things happen at the Presentation layer  
Formatting - Presenting the in a universal format  
If sending messages from a Mac to a Windows PC, both can understand the message  
because at somepoint the message has been formatted to a universal format  
Multimedia Formatting - JPG, GIF, MP3  
  
Compression - Removes redundancies from files  
allows files to be smaller as it is transported across the network  
so it doesn't take as long/ So it take as much space to transfer  
  
Encryption -  
Layer 6 - happens within the filing system  
using EFS and sending a file that is encrypted  
storing a file in encrypted format somewhere within the filing system  
happens in multiple layers of the OSI model  
layer 1 - hardware based encyption  
layer 3 - IPsec - secures traffic  
layer 4-7 - SSL and TLS - secures web traffic  
  
Only layer of the OSI model not to have protocols  
  
Formats data so it can be sent over a network, standardized or encrypted, or when received are formatting it so we can read it/put on computer and understand it  
Protocols - referring to presenting file types to the user , audio, visual, text etc  
   
The presentation layer is responsible for formatting and delivering information to the application for further processing or display. It relieves the application layer of concern regarding syntactical differences in data representation within the end-user systems.  
Encryption device operates at this level - Formats data  
   
Examples of these layers functioning within the Windows environment include the use of NetBIOS names for the Session layer and character code translation such as from ASCII to EDCDIC and back.  
   
For the most part these functionalities cannot be directly viewed within a Windows environment as most Windows network components are structured around the TCP/IP model and as such, these layers are included within the Application layer.