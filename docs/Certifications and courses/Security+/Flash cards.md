---
cards-deck: Sec+ gaps
---
## ISO 27001 #card
sets foundational standard for Information security Management Systems (ISMS)
## ISO 27002 #card 
defines Information security controls
## ISO 27701 #card 
defines privacy and extends ISO 27001 & 27002 standards to include detailed management or PII (personally identifiable Information)
## ISO 31000 #card 
defines risk over all of the below sets international standards for risk management
## MTBF #card 
Mean time between failure is the average time expected between outages
## RTO #card
Recovery time objectives  define the minimum objectives  required to get up and running to particular service leverl
## MTTR #card
Mean time to repair is the time required to repair a product or system after failure
## MTTF
mean time to failure
## EAP-TLS
Extensible Authentication Protocol - Tunneled Transport Layer Security allows the use of multiple authentication protocols transported inside of an encrypted TLS (transport layer security) tunnel. 
## PEAP
(Protected Extensible Authentication Protocol) encapsulate EAP within a TLS tunnel, but does not provide a method of encapsulating other authentication methods
## EAP-TTLS
Does not provide a mechanism for using multiple types within a TLS tunnel.
D. EAP-MSCHAPv2 - (EAP - Microsoft Challenge Handshake Authentication protocol v2) is a common implementation of PEAP
## Race Conditions
A race condition occurs when two processes occur at similar times, usually with unexpected results. 
## SED
Self-Encrypting Drive provides data protection of a storage device using full-disk encryption in the drive hardware
## CASB
Cloud Access Security Broker is a solution for administering and managing security policies in the cloud. 
## MAC
Mandatory Access Control is an access control system that assigns labels to objects in an operating system. MAC would not prevent external access to data on a laptop's stor/page drive.
## SOAR
Security, Orchestration, Automation, and Response describes a process for automating security activities. SOAR would not provide a mechanism for protecting data on a laptops storage drive.
## MDM
Mobile Device Manager provides a centralized management system for all mobile devices. From this central console, security administrators can set policies for many different types of mobile devices
## Containerization
mobile device containerization allows an organization to securely separate user data from company data on a mobile device. Implementing this strategy usually requires a mobile device manager (MDM), and containerization alone won't address all of the required security policies
## COPE
 a COPE / Corporately Owned and Personally Enabled is commonly purchased by the corporation and allows the use of the mobile device for both business and personal use.
## VDI
a Virtual Desktop Infrastructure separates the applications from the mobile device or device.
## Geofencing
Geofencing uses location information from GPS, 802.11 wireless and other methods to use an access control method. Could be used to prevent mobile device use from other countries, but you still need a MDM to implement the other requirements
## False negative
is a result that fails to detect an issue when one actually exists
## 802.1X
uses a centralized authentication server, and all users can use their normal credentials to authenticate to an 802.1X network
## WPA2-PSK 
PSK is the shared password that this network administration would like to avoid using in the future
## WPS
Wi-Fi protected setup connects users to a wireless network using a shared PIN or personal identification number
## WPA2-AES
WPA2 or Wi-Fi Protected Access 2 encryption with AES or Advances Encryption Standard is a common encryption method for wireless networks but it does not provide any centralized authentication functionality.
## DAC
Discretionary Access Control is used in many operating systems and this model allows the owner of the resource to control who has access.
## MAC
Manditory Access Control allows access based on the security level assigned to an object. Only users with the object's assigned security level or higher may access the resource.
## ABAC
Attribute Based Access Control combines many different parameters to determine if a user has access to a resource.
## RBAC
Role Based Access Control assign rights and permissions based on the role of a user in an operating sytsem. These roles are usually assigned by group
## Prepending 
Prepending adds information before a domain name in an attempt to fool the victim into visiting a website managed by the attacker.
## Disassociation 
Dissociation attacks are commonly associated with wireless networks. The disassociation attack is used to remove devices from the wireless network, and it does not commonly redirect clients to a different website.
## Buffer overflow
Buffer overflows are associated with application attacks and can cause applications to crash or act in unexpected ways.
## Hybrid model
A hybrid cloud model combines both private and public cloud infrastructures
## SaaS
Software as a Service is a cloud deployment model that provides on-demand software without any context about the software's location.
## Community model
A Community Cloud model allows multiple organizations to share the same cloud resources, regardless of the resources location.
## Containerization
Containerization can be used with mobile phones to partition user data and corporate data
## MAC filtering
Filtering by MAC (Media Access Control) address will limit which devices ca connect to the wireless network. If a device is filtered by MAC address, it will be able to see and access point but it will not be able to connect,
## SSID broadcast suppression
A suppressed SSID (Service Set Identifier) broadcast will hide the name from the list of available wireless networks. Properly configured client devices can still connect to the wireless network, even with the SSID suppression
## 802.1X authentication
With 802.1X authentication, users will be prompted for a username and password to gain access to the wireless network. Enabling 802.1X would not restirct properly configured devices. 
## Anti-spoofing
Anti-spoofing features are commonly used with routers to prevent communication from spoofed IP addresses. This issue in this question
## Privilege escalation
A Privilege escalation attack allows a user to exceed their normal rights and permissions
## Spoofing
Spoofing is when a device pretends to be a different device or pretends to be something they aren't 
## Replay attack
A Replay Attack captures information and then replays that information as the method of attack.
## Reconstitution  
The recovery after after a breach can be a phased approach that may take months to complete
## Lessons learned
Once the event is over, it's useful to revisit the process to learn and improve for next time. A post-incident meeting can help the incident response participants
discuss the phases of the incident that went well and which processes can
be improved for future events
## Isolation and containment
During an incident, it's useful to separate infected systems from the rest of the network
## Precursors
Log files and alerts can often warn you of potential problems
## Detection
The Detection phase occurs prior to the system administrator arriving and identifying the potential problem.
## DLP
DLP / Data Loss Prevention can identify and block PII / Personally Identifiable Information and other private details from being transferred across the network
## SIEM
A SIEM / Security Information and Event Management is a management system for log consolidation and reporting
## IPS
An IPS / Intrusion Prevention System can identify and block known vulnerabilities on the network.
## After-action report
An after-action report is commonly created after a disaster recovery drill to document which aspects of the plan worked of did not work
## Business impact analysis
A business impact analysis is usually created during the disaster recovery planning process. Once the disaster has occurred, it becomes much more difficult to complete and accurate impact analysis.
## Alternate business practice
An Alternate business practice is one of the steps in completing a disaster recovery exercise.
## DNS Sinkhole
A DNS (Domain name system) sinkhole can be used to redirect and identify devices that may attempt to communicate with an external command and control (C2) server. The DNS sinkhole will resolve an internal IP address adn can report on all devices that attempt to access the malicious domain. 
## Data Masking
Data Masking provides a way to hide data by substitution, shuffling, encryption and other methods
## DLP
DLP / Data Loss Prevention systems can identify and block private information from transferring between systems
## Remote Wipe
Most organizations will use a mobile device manager (MDM) to manage mobile phones and tablets. Using the MDM, specific security policies can be created for each mobile device, including the ability to remotely send a remote wipe command that will erase all data on a mobile device. 
## Dump file
A dump file contains the contents of system memory. 
## Web
Web server logs will document web pages that were accessed, but it doesn't show what information may be contained in the system RAM
## Packet 
A Packet Trace would provide information regarding network communication but it would not include any details regarding the contents of memory
##  DNS 
DNS (Domain Naming System) server logs can show which domain names were accessed by internal systems and this information can help identify systems that may be infected. 
## Boot order
POST/ Power on self test --> Secure --> Trust --> Measured
## Trusted Boot
The Trusted Boot portion of the startup process verifies the operating system kernel signature and starts the ELAM / Ealy Launch Anti-Malware
## Measured Boot
Measured Boot occurs after the Trusted Boot process and verifies that nothing on the computer has been changed by malicious software or other processes
## Secure Boot
Secure Boot is a UEFI BIOS boot feature that checks the digital signature of the bootloader. the Trusted boot process occurs after Secure boot has completed 
## POST 
POST / Power on self test  is a hardware check performed prior to booting an operating system.
## VDI
A VDI/Virtual Desktop Infrastructure would allow the field teams to access their applications from many different types of devices without the requirement of a mobile device management or concern about corporate data on devices
## COPE
COPE/Corporate Owned and Personally Enabled devices are purchased by the company but used as both a corporate device and a personal device. 
## BYOD
BYOD Bring Your Own Device means that the employee would choose the mobile platform. 
## Compensating 
A compensating security control doesn't prevent an attack, but it does restore from an attack using other means. 
## Preventative
A preventative control physically limits access to a device or area.
## Managerial
A managerial control sets a policy that is designed to control how people act.
## Detective 
A detective control may not prevent access but it can identify and record any intrusion attempts
## Physical control
A Physical control wold block access. Ex, a door lock or a security guard
## most volatile to least volatile
CPU registers, memory, temporary files, remote monitoring data
## Mitigation
Mitigation is a strategy that decreases the threat level
## Transference
Transference would move risk from one entity to another
## Acceptance
The acceptance of risk is a position where the owner understands the risk  and has decided to accept the portential results
## Risk Avoidance
With risk-avoidance, the owner of the risk decides to stop participating in a high-risk activity. This effectively avoids the risky acti8vityt and prevents any future issues.
## Integrity measurement
An integrity measurement is designed to check for the secure baseline of firewall settings, patch levels, operating system versions, and any other security components associated with the applicatoin.
## Sandbox
A sandbox is commonly used as a development environment. 
## QA / Quality Assurance 
QA / Quality Assurance testing is commonly used for finding bugs and verifying application functionality
## Job Rotation
Job rotation moves employees through different jobs roles as part of their normal work environment. A policy limits limits the potential for fraud and allows others to cover responsibilities if someone is out of the office. 
## Split knowledge
The use of split knowledge limits the information that any one person whould know.
## Least privilege
Least privilege is a security policy that limits therights and permissions of a user to only those tasks required for their job role. 
## Dual control
With Dual control, 2 persons must be present to perform a business function.
## Private key
With asymmetric encryption, the private key is used to decrypt information that has been encrypted with the public key. To ensure continued access to the encrypted data, the company must have a copy of each private key. 
## CA Key
A CA / Certificate authority key is commonly used to validate the digital signature from a trusted CA
## Session Key
Session keys are commonly used temporarily to provide confidentiality during a single session. Once the session is complete, the keys are discarded
## Public key
In asymmetric encryption, a public key is already available to everyone.
## Kerberos
Kerberos uses ticket-based system to provide SSO (Single Sign on). You only need to authenticate once with Kerberos to gain access to multiple resources. 
## TACACS+
TACACS+ (Terminal Access Controller Access-Control System) is a common authentication method, but does not provide any single sign-on functionality.
## LDAPS
LDAPS (Lightweight Directory Access Protocol secure) is a standard for accessing a network directory. Can provide an authentication method, but does not provide any single sign on functionality
## 802.1x
802.1x is a standard for port-based network access control (PNAC), but it does not inherently provide any single sign-on functionality.
## VLANs
VLANs / Virtual local Area Network will segment a network without requiring additional switches. The devices in each segmented VLAN can only communicate with other devices in the same VLAN.
## VPN
VPN / Virtual Private Network will encrypt all information between 2 networks or remote end-user communication, but not provide any segmentation. 
## Air gapped network
An air gap is a segmentation strategy that separates devices or networks by physically disconnedcting them from each other. An air gapped network would require separate physical switches on each side of the gap.
## Personal Firewalls
Personal Firewalls provide protection for individual devices
## VPN tunnels
VPN / Virtual Private Network
Usually send traffic unfiltered through the encrypted tunnel.
Non-split / Full Tunnels redirect all traffic through the encrypted tunnel. 
Split tunnel only sends a portion of the traffic through the encrypted tunnel.
## Faraday Cage
A Faraday cage is a mesh of conductive material that will cancel electromagnetic fields.
Does not prevent physical access to servers with out credentials
Does not provide any additional cooling features.
Does not provide any additional fire protection features
## Templates
Templates can be used to easily build the basic structure of an application instance. 
Templates are not used to identify or prevent the introduction of vulnerabilities
## Elasticity
Elasticity is important when scaling resources as the demand increases or decreases. 
Will not help with the identification of vulnerabilities.
## Master image
A master image is used to quickly copy a server for easy deployment. The image will need to be updated and maintained to prevent issues associated with unexpected vulnerabilities.
## Salting
adding random data, or salt, to a password when performing the hashing process will create a unique hash, even if other users have chosen the dame password.
## Obfuscation
Obfuscation is the process of making something difficult for humans to read or understand.
## Key Stretching
Key Stretching is a process that uses a key multiple times for additional protection against brute force attacks. 
## Digital signature
Digital signatures use a hash and asymmetric encryption to provide integrity of data and non repudiation of data. 
A certificate authority will digitally sign a certificate to add trust.
If you trust the certificate authority you can then trust the certificate.
## X.509
X.509 standard defines the structure of a certificate.
This standard format makes it easy for everyone to view the contents of a certificate. 
Does not provide any additional trust.
## Hash
A hash can help verify that the certificate has not been altered.
But it does not provide additional third part trust
## Symmetric encryption
Symmetric encryption has the same issue as asymmetric encryption. 
The information in a certificate commonly needs to be viewable by others. 
## Data custodian/steward
The Data custodian manages access rights and sets security controls to the data. Associates sensitivity labels to the data. Ensures compliance with any applicable laws and standards. Implements security controls
## Data processor
The data processor manages the operational use of the data, but not the rights and permissions to the information.
## Data Owner
The Data owner is usually a higher level exec who makes business decisions regarding the data
## Data Protection Officer
The data protection officer (DPO) is responsible for the organization's data privacy. The DPO commonly sets processes and procedures for maintaining the privacy of data
## Data Processor
The data processor is often a third-party that processes data on behalf of the data controller.
## Privacy officer 
The Privacy officer sets privacy policies and implements privacy processes and procedures
## PII
PII / Personally Identifiable Information is often associated with privacy and compliance concerns
## PHI
PHI / Protected Health Information would most likely be Healthcare data
## HSM
An HSM / Hardware Security module is a high end cryptographic hardware appliance that can securely storing and backing up cryptographic keys and certificates for all devices.
## TPM
A TPM / Trusted Platform Module is used on individual devices to provide cryptographic functions and securely store encryption keys. 
## SLE
SLE / Single Loss Expectancy describes the financial impact of a single event
## ALE
ALE / Annual Loss Expectancy is the financial loss over and entire 12 month period
## RTO
RTO / Recovery  Time Objectives define a set of objectives needed to restore a particular sevice level.
## ARO
ARO / Annualized Rate of Occurrence is the number of times an event will occur in a 12 month period
## SQL injection
SQL / Structured Query Language injection takes advantage of poor input validation to circumvent the application and perform queries directly to the database.
## CSRF
CSRF / Cross Site Request Forgery takes advantage of a third-party trust to a web application. 
## Buffer Overflow
A Buffer Overflow uses an application vulnerability to submit more information than an application can properly manage. 
## SSL Stripping
SSL Stripping allows an on-path attack to rewrite web site addresses to gain access to encrypted information
## RAT
RAT / Remote Access Trojan is malware that can control a computer using desktop sharing and other administrative functions. 
Once the RAT is installed, the attacker can control the desktop, capture screenshots, reboot the computer, and many other administrator functions.
## On-path / Man-in-the-middle
On-path / Man-in-the-middle attack commonly occurs without any knowledge to the parties involved, and there's usually no additional notification that an attack is underway.
## Worm
A worm is malware that can replicate itself between systems without any user intervention.
A spreadsheet that requires a user to click warning messages would not be categorized as a worm.
## Logic Bomb
A Logic Bomb is malware that installs and operates silently until a certain event occurs. Once the logic bomb has been triggered, the results usually involve loss of data or a disabled operating system
## PCI DSS
The PCI DSS / Payment Card Industry Data Security Standard specifies the minimum security requirements for storing and protecting credit card information. 
## GDPR
GDPR / General Data Protection Regulation is a European Union regulation that governs data protection and privacy for individuals in the EU.
## ISO 27001 
The ISO / International Organization for Standardization 27001 standard focuses on the requirements for an Information Security Management System (ISMS)
## CSA CCM 
The CSA CCM / Cloud Security Alliance Cloud Controls Matrix provides documents for implementing and managing cloud-specific security controls.
## Data encryption
Data encryption ensures that information can be securely transmitted from a source to a destination.

## Key Escrow
Key Escrow is commonly used as a method of storing decryption keys with a trusted third-party.
## Certificate Authority
Certificate Authorities are used as a method of trusting a certificate. If a certificate has been signed by a trusted CA, then the certificate owner can also be trusted.
## Perfect Forward Secrecy
Perfect forward secrecy uses temporary encryption keys that change between sessions. This constant switching of keys makes it more difficult for a third-party to decrypt the data later.
## Data in-transit, at-rest, in-use, 
- is the data moving from A to B across the network.
- is the data doing nothing other than sitting in persistent storage
- is the data currently in memory or being processed by a CPU on a device
## OSINT
OSINT/Open Source Intelligence describes the process of obtaining information from open sources, such as social media sites, corporate websites, online forums and other publicly available locations. 
## Partially known environment
A Partially known environment text describes how much information the attacker knows about the test. The attacker may have access to some information about the test  but not all information is disclosed
## Known environment
A known environment test is performed when the attacker has complete details about the victim's systems and infrastructure
## Passive Footprinting
Passive Footprinting is the process of gathering information from publicly available sites, such as social media or corporate websites
## Ping scan
A ping scan is a type of network scan that can identify devices connected to the network.
## Exfiltration
Exfiltration describes the theft of data by an attacker
## Active footprinting
Active footprinting would show some evidence of data gathering. For example performing a ping scan or DNS query wouldn't exploit a vulnerability but it would show that someone was haghering information. 
## Invoice Scam
Invoice scams attempt to take advantage of the miscommunication between different parts of the organization. Fake invoices are submitted by the attacker, and these invoices can sometime be incorrectly paid without going through the expected verification process.
## Spear phishing
Spear phishing is a directed attack that attempts to obtain private or personal information.
## Watering hole attack
A watering hole attack requires users to visit a central website or location. 
## Credential harvesting
Credential harvesting attempts to transfer password files and authentication information from other computers.
## VM escape
A VM/Virtual Machine escape is a vulnerability that allows communication between separate VMs.
## Containerization
Containerization is an application deployment architecture that uses a self-contained group of application code and dependencies. Many separate containers run on a single system.
## Service integration
Service integration and Management/SIAM allows the integration of many different service providers into a single management system. This simplifies the application management and deployment process when using separate cloud providers
## SDN
SDN/Software defined networking separates the controlplane of networkign devices from the data plane. This allows for more automation and dynamic changes to the infrastructure.
## DNS poisoning
An attacker that gains access to a DNS/Domain Name System server can modify the configuration files and redirect users to a different website. Anyone using a different DNS server may not see any problems with connectivity to the original site
## Bluejacking
Bluejacking allows a third-party to send unsolicited messages to another device using Bluetooth.
## Wireless Disassociation
Wireless Disassociation would cause users on a wireless network to constantly disconnect. 
## DDOS
DDOS/Distributed Denial of Service would attack a service from many different devices and cause the service to be unavailable
## Authentication
The process or proving who you say you are is authentication.
## Accounting
Accounting will document information regarding a users session, such as login time, data sent and received, files transferred and logout time.
## Authorization
The authorization process assigns users to resources. This process commonly occurs after the authentication process is complete.
## Federation
Federation provides a way to authenticate and authorize between two different organizations. 
## Orchestratrion
The process of automating the configuration, maintenance, and operation of an application instance is called orchestration. 
## Wireshark
Wireshark is a protocol analyzer, and it provide information about every frame that traverses the network. From a security perspective, the protocol decode can show the exploitation process and details about payloads used during exploit attempts.
## Netstat 
The netstat command can display connectivity information about a device. 
## Nmap
A Nmap scan is a useful tool for understanding the potential exploit vectors of a device. 
## Nessus
Nessus is a vulnerability scanner that can help identify potential exploit vectors
## FTPS
FTPS/File Transfer Protocol Secure provides mechanisms for transferring files using encrypted communication.
## SNMPv3 
SNMPv3/Simple Network Management Protocol version 3 uses encrypted communication to manage devices
## SRTP 
SRTP/Secure Real-Time Transport protocol is used for secure voice over IP and media communication across the network
## DNSSEC
DNSSEC/Domain Name System Secure Extensions are used on DNS servers to validate DNS responses using public key cryptography
## NAT
NAT / Network Address Translation  is used to modify the source or destination IP address or port number of a network traffic flow
## NAC 
NAC/Network access control is a broad term describing access control based on a health check or posture assessment. NAC will deny access to devices that don't meet the minimum security requirements
## Jump Server
A jump server is a highly secured device commonly used to access secure areas of another network. A technician would first connect to the jump server using ssh of a vpn tunnel and then "jump" from the jump server to other devices on the inside of the protected network. 
## WAF
WAF / Web application firewall is used to protect exploits against web-based applications
## Proxy
A proxy is used to make network or application requests on behalf of another person or device.
## MFA
MFA/Multi-factor Authentication.
Something you know - password, PIN
Something you have - smartphone, USB key, smart card
Something you are - fingerprint, facial recognition, voice print
## RADIUS
RADIUS / Remote Authentication Dial-In User Service is a common method of centralizing authentication for users. Instead of having separate local accounts on differnent devices, users can authenticate with account information that is maintained in a centralized database. 
## PAP
PAP/Password Authentication Protocol is an authentication method that can validate a username and password but PAP does not provide any mechanism for a centralized authentication database
## IPsec
IPsec is commonly used as an encrypted tunnel between sites or endpoints. It's useful for protecting data sent over the network. 
## MS-CHAP
MS-CHAP/ Microsoft Challenge-Handshake Authentication Protocol was commonly used in Microsoft PPTP/Point-to-point tunneling protocol but vulnerabilities related to the use of DES/Data Encryption Standard encryption make it relatively easy to brute force the NTLM hash used in MS-CHAP
##
# 1st pass - quickly answer what you know
# 2nd pass -  eliminate wrong answers
# 3rd pass -  only change for tangible reasons

















