---
cards-deck: Sec+ gaps
---
# Security + flash cards
## ISO 27001 #card
sets foundational standard for Information security Management Systems (ISMS)
## ISO 27002 #card 
defines Information security controls
## ISO 27701 #card 
defines privacy and extends ISO 27001 & 27002 standards to include detailed management or PII (personally identifiable Information). The ISO 27701 standard focuses on the implementation and maintenance of a privacy information management system (PIMS)
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
A race condition occurs when two processes occur at similar times, usually with unexpected results. It is a programming issue where a portion of the application is making changes that are not seen by other parts of the application
## SED
Self-Encrypting Drive provides data protection of a storage device using full-disk encryption in the drive hardware
## CASB
Cloud Access Security Broker is a solution for administering and managing security policies in the cloud. 
## MAC
Mandatory Access Control is an access control system that assigns labels to objects in an operating system. MAC would not prevent external access to data on a laptop's stor/page drive. Mandatory Access Control uses a series of security levels and assigns those levels to each object in the operating system. Users are assigned a security level, and they would only have access to objects that meet or are below that assigned level.

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
802.1x is a standard for authentication using AAA (Authentication, Authorization, Accounting) services. 802.1x is commonly used in conjunction with LDAP, RADIUS, TACACS+ or Kerberos or similar authentication services. Uses a centralized authentication server, and all users can use their normal credentials to authenticate to an 802.1X network
## WEP
WEP / Wireless Equivalent Privacy is an older wireless encryption algorithm that was ultimately found to have cryptographic vulnerabilities.
## WPA2-PSK 
PSK is the shared password that this network administration would like to avoid using in the future
## WPS
Wi-Fi protected setup connects users to a wireless network using a shared PIN or personal identification number. WPS Bad
## WPA2-AES
WPA2 or Wi-Fi Protected Access 2 encryption with AES or Advances Encryption Standard is a common encryption method for wireless networks but it does not provide any centralized authentication functionality.
## DAC
Discretionary Access Control is used in many operating systems and this model allows the owner of the resource to control who has access. It allows the owner of the object to assign access. If a user creates a spreadsheet the user can then assign users and groups to have a particular level of access to that spreadsheet. 
## MAC
Manditory Access Control allows access based on the security level assigned to an object. Only users with the object's assigned security level or higher may access the resource.
## ABAC
Attribute Based Access Control combines many different parameters to determine if a user has access to a resource.
## RBAC
Role Based Access Control assign rights and permissions based on the role of a user in an operating sytsem. These roles are usually assigned by group
## Role-based access control
Role-based access controls assign a user's permissions based on their role in the organization. Ex. a manager would have a different stet of rights and permissions that a team lead.
## Prepending 
Prepending adds information before a domain name in an attempt to fool the victim into visiting a website managed by the attacker.
## Disassociation 
Dissociation attacks are commonly associated with wireless networks. The disassociation attack is used to remove devices from the wireless network, and it does not commonly redirect clients to a different website.
## Buffer overflow
Buffer overflows allow and attacker to manipulate the contents of memory. are associated with application attacks and can cause applications to crash or act in unexpected ways.
## Hybrid model
A hybrid cloud model combines both private and public cloud infrastructures
## SaaS
Software as a Service is a cloud deployment model that provides on-demand software without any context about the software's location. SaaS model generally has no local application installation, no ongoing maintenance tasks, and no local infrastructure requirements. A third party provides the application and the support, and the user logs in, uses the service and logs out. 
## PaaS
PaaS / Platform as a service is a model that provides a building block of features, and requires the end user to customize their own application from the available modules. 
## Private application model
A private model requires that the end user purchase, install, and maintain their own application hardware and software.  
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
A Replay Attack captures information and then replays that information as the method of attack. To perform a replay attack, the attacker needs to capture the original non-encrypted content. If an application is not using encrypted communication, the data capture process is simple for the attacker
## Resource Exhaustion
Resource exhaustion can take many different forms, but those resource issues don't necessariuly require the network communication to be sent in the clear.
## Directory Traversal
Directory Traversal is commonly associated with moving around the file system of a server. Non-encrypted communication is not a prerequisite in a directory traversal attack
## Reconstitution  
The recovery after after a breach can be a phased approach that may take months to complete
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
## ACL
An ACL / Access Control List is a security control commonly implemented on routers to allow or restrict traffic flows through the network

## After-action report
An after-action report is commonly created after a disaster recovery drill to document which aspects of the plan worked of did not work
## Business impact analysis
A business impact analysis is usually created during the disaster recovery planning process. Once the disaster has occurred, it becomes much more difficult to complete and accurate impact analysis.
## Alternate business practice
An Alternate business practice is one of the steps in completing a disaster recovery exercise.
## DNS Sinkhole
A DNS (Domain name system) sinkhole can be used to redirect and identify devices that may attempt to communicate with an external command and control (C2) server. The DNS sinkhole will resolve an internal IP address adn can report on all devices that attempt to access the malicious domain. 
## Data Masking
Data Masking provides a way to hide data by substitution, shuffling, encryption and other methods. It hides some of the original data to protect sensitive information.
## Minimization
Data minimization is a guideline that limits the amount of collected information to necessary data. This guideline is part o many data privacyt regulations, including HIPAA and GDPR.
## Tokenization
Tokenization replaces sensitive data with a non-sensitive placeholder. Commonly used for NFC / Near-Field Communication payment systems.
## Anonymization
Anonymization changes data to remove or replace identifiable information. For example, an anonymized purchase history database might change the first and last names to random values but keep the purchase information intact
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
A Physical control would block access. Ex, a door lock, fences, bollards or a security guard
## Corrective 
A corrective control is designed to mitigate any potential damage.
## most volatile to least volatile
CPU registers, memory, temporary files, remote monitoring data
## Mitigation
Mitigation is a strategy that decreases the threat level. If the organization was to purchase additional backup facilities and update their backup processes to include offline backup storage, they would be mitigating the risk of a ransomware infection.
## Transference
Transference would move risk from one entity to another. Purchasing insurance to cover a risky activity is a common method of transferring risk from the organization to the insurance company.
## Acceptance
The acceptance of risk is a position where the owner understands the risk  and has decided to accept the potential results.
## Risk Avoidance
With risk-avoidance, the owner of the risk decides to stop participating in a high-risk activity. This effectively avoids the risky activity and prevents any future issues.
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
VPN / Virtual Private Network will encrypt all information between 2 networks or remote end-user communication. a VPN will not provide any segmentation or monitoring or threat identification.
## Air gapped network
An air gapped network removes all connectivity between components and ensures that there would be no possible communication path between the test network and the production network. An air gap is a segmentation strategy that separates devices or networks by physically disconnecting them from each other. An air gapped network would require separate physical switches on each side of the gap. 
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
Obfuscation is the process of making something difficult for humans to read or understand. It is the process of taking something that is normally understandable and making it very difficult to understand.

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
Symmetric encryption uses the same key for both encryption and decryption.
## Asymmetric encryption
Asymmetric encryption uses different keys for encryption and decryption.
## Out-of-band key exchange
Out-of-band key exchange is when keys are transferred between people or systems outside the normal network communication 
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
A TPM / Trusted Platform Module is used on individual devices to provide cryptographic functions and securely store encryption keys. It is hardware that is part of a computer's motherboard, and it's specifically designed to assist and protect with cryptographic functions. Full disk encryption (FDE) can use the burned-in TPM keys to verify that the local device hasn't changed and there are security features in the TPM that will prevent brute-force or dictionary attacks against the full disk encryption log in credentials
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
A Buffer Overflow uses an application vulnerability to submit more information than an application can properly manage. It takes advantage of an application vulnerability and can perform this overflow over both encrypted or non-encrypted channel.

## SSL Stripping
SSL Stripping allows an on-path attack to rewrite web site addresses to gain access to encrypted information
## RAT
RAT / Remote Administration Tool is malware that can control a computer using desktop sharing and other administrative functions. 
Once the RAT is installed, the attacker can control the desktop, capture screenshots, reboot the computer, and many other administrator functions.
It is often installed as a Trojan horse and used for malicious purposes. 
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
## Information sharing center 
The IT security community has a number of sharing centers for threat intelligence. 
## Vulnerability databases
Vulnerability databases usually contain information about vulnerable operating systems and applications. 
## Automated indicator sharing
Automated indicator sharing / AIS is a standard format and transfer mechanism for distributing security intelligence between different organizations.
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
## Phishing 
A phishing attack traditionally uses email in an effort to convince the victim to disclose private or sensitive information. 
## Spear phishing
Spear phishing is a directed attack that attempts to obtain private or personal information.
## Watering hole attack
A watering hole attack requires users to visit a central website or location. 
## Influence Campaign
Influence Campaigns are carefully crafted attacks that exploit social media and traditional media.
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
DDOS/Distributed Denial of Service would attack a service from many different devices and cause the service to be unavailable. A DDoS can easily exploit a memory leak. If unused memory is not properly released and eventually the leak uses all available memory. The system eventually crashes due to lack of resources.
## Rogue Access Point
A rogue access point is an unauthorized access point added by a user or attacker. The access point may not necessarily malicious but it does create a significant security concern and unauthorized access to the corporate network. 
## Domain hijack
A domain hijacking would be associated with unauthorized access to a domain name. 
## MAC flooding
MAC / Media Access Control flooding involves an attacker sending traffic with a different source MAC address to force out legitimate MAC addresses. The table fills up, the switch begins flooding traffic to all interfaces, Turns the switch into a hub where all traffic is transmitted to all interfaces where the attacker can easily capture all network traffic. 
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
SNMPv3/Simple Network Management Protocol version 3 uses encrypted communication to manage devices. SNMPv3 is used to manage servers and infrastructure devices. 
## SRTP 
SRTP/Secure Real-Time Transport protocol is used for secure voice over IP and media communication across the network
## DNSSEC
DNSSEC/Domain Name System Secure Extensions are used on DNS servers to validate DNS responses using public key cryptography
## NAT
NAT / Network Address Translation is used to modify the source or destination IP address or port number of a network traffic flow 
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
MS-CHAP/ Microsoft Challenge-Handshake Authentication Protocol was commonly used in Microsoft PPTP/Point-to-point tunneling protocol but vulnerabilities related to the use of DES/Data Encryption Standard encryption make it relatively easy to brute force the NTLM hash used in MS-CHAP. This security issue eliminate MS-CHAP for modern authentication
## Separation of Duties
A separation of duties policy ensures that multiple users are required to complete a single business process. 
## Offboarding 
The offboarding process describes the policies and procedures associated with someone leaving the organization of someone who is no longer an employee of the company.
## Insecure protocols
An insecure protocol will transmit information "in the clear", or without any type of encryption.
## Weak encryption
A weak encryption cipher will appea to protect data, but instead can be commonly circumvented to reveal plaintext.
## Improper Patch management 
Maintaining Systems to the latest patch version will protect against vulnerabilities and security issues. 
## Sideloading
If an OS has been circumvented using jailbreaking, then apps can be installed without using the device's app store.
## RAID 0
RAID Redundant Array of Independent Disks type 0 is a striped storage system with no parity, and a single drive failure does not maintain uptime or any redundancy of data.
## RAID 1
RAID / Redundant Array of Independent Disks type 1 maintains a mirror (exact duplicate) of data across multiple drives. If a single drive was to fail, the mirror would continue to operate with the redundant data. 
## RAID 5
RAID 5 provides redundancy through striping with parity. RAID 5 arrays would continue to operate through a single drive failure, the data is not replicated across drives. 
## RAID 10
RAID 10 or RAID 1+0 maintains mirrored drives that contain striped data. 
## NGFW
An NGFW / Next Generation Firewall is a .... It Will not provide any cloud based security policy monitoring
## DLP 
DLP / Data Loss Prevention can monitor data to prevent the transfer of sensitive information. It doesn't identify threats or force the transfer of encrypted data. They are designed to identify sensitive data transfers. If the DLP finds a data transfer with financial details, personal information or other private information the DLP can block the data transfer. 
## Improper Error Handling  
Error messages can sometimes provide additional information about a system.
## Weak cipher suite
A weak cipher suite implies that the cryptography used in a system may be circumvented or decrypted.
## NULL pointer dereference
A NULL pointer dereference is a programming issue that causes application crashes and a potential denial of service. 
## Supply Chain
A supply chain attack infects part of the product manufacturing process in an attempt to also infect everything further down the chain.
## Impersonation 
Impersonation attacks use misdirection and pretext to allow an attacker to pretend they are someone else. 
## UPS
UPS / Uninterruptable power supply can provide backup power when the main power source is unavailable
## Dual power supply
Dual power supplies can maintain uptime when power surges cause physical damage to one of the power supplies in a system.
## NIC teaming
NIC / Network Interface Card teaming can be used for redundant network paths from a server, but it won't help with power related issues.
## Port aggregation 
Port aggregation  is used to increase network bandwidth between switches or devices
## Load balancing
Load balancers provide a way to manage busy services by increasing the number of available servers and balancing the load between them.
## CSR Certificate Signing Request
A CSR / Certificate Signing Request is used during the key creation process. The public key is sent to the CA to be signed as part of the CSR
## Hierarchical CA
A hierarchical CA design will create intermediate CAs to distribute the certificate management load and minimize the impact if a CA certificate needs to be revoked
## ESP
The ESP / Encapsulation Security Payload protocol encrypts the data that traverses the VPN
## AH 
The AH / Authentication Header is used to hash the packet data for additional data integrity
## Diffie-Hellman
Diffie-Hellman is an algorithm used for two devices to create identical shared keys without transferring those keys across the network.
## ECC
Elliptic Curve Cryptography uses smaller keys than non-ECC encryption and has smaller storage and transmission requirements. These characteristics make it an efficient option for mobile devices.
## SHA-2
SHA-2 / Secure Hashing Algorithm is a hashing algorithm and does not provide any data encryption
## tracert
tracert / traceroute provides a summary of hops between two devices. 
## dig
dig / Domain Information Groper can be used to perform a reverse-lookup of the the IPv4 address and determine the IP address block owner that may be responsible for traffic.
## arp
arp / Address Resolution Protocol command shows a mapping of IP addresses to local MAC addresses
## ping 
the ping command can be used to determine if a device may be connected to the network.
## ipconfig
the ipconfig command shows the IP address configuration of a local device
## netcat
netcat reads or writes information to the network. 
## Metasploit
Metasploit is an exploitation framework that can use known vulnerabilities to gain access to remote systems.
## FTK Imager 
FTK imager is a third-party storage drive imaging tool and it can support many different drive types and encryption methods.
## Autopsy
Autopsy is a forensics tool that can view and recover data from storage devices.
## SLA
A SLA / Service Level Agreement is a contract that specifies the minimum terms for provided services. It's common to include uptime, response times, and other service metrics in an SLA.
## Chain of custody
A chain of custody is a documented record of the evidence. The chain of custody also documents the interactions of every person who comes into contact with the evidence. 
## | ports secure | insecure |
| **insecure** | **secure**       | **secure** |
| ------------ | ---------------- | ---------- |
| FTP 20, 21   | SFTP 22          | FTPS       |
| TELNET 23    | SSH 22           |            |
| SMTP 25      | *SMTPS 465 587*  |            |
| DNS 53       | DNSSEC 853       |            |
| HTTP 80      | HTTPS 443        |            |
| DHCP 67 68   |                  |            |
| POP 110      | *Secure POP 995* |            |
| NNTP 119     |                  |            |
| NTP 123      | NTPsec           |            |
| SMB 139 445  |                  |            |
| IMAP 143     | *SecureIMAP 993* |            |
| LDAP 389     | LDAPS 636 3269   | SASL       |
|              | SRTP             |            |
| SNMP 161     | SNMPv3           |            |
|              |                  |            |
| **insecure** | **secure**       | **secure** |
| FTP          | SFTP             | FTPS       |
| TELNET       | SSH              |            |
| SMTP         | *SMTPS*          |            |
| DNS          | DNSSEC           |            |
| HTTP         | HTTPS            |            |
| DHCP         |                  |            |
| POP          | *Secure POP*     |            |
| NNTP         |                  |            |
| NTP          | NTPsec           |            |
| SMB          |                  |            |
| IMAP         | *SecureIMAP*     |            |
| LDAP         | LDAPS            | SASL       |
|              | SRTP             |            |
| SNMP         | SNMPv3           |            |
|              |                  |            |
| **insecure** | **secure**       | **secure** |
| 20, 21       | 22               | FTPS       |
| 23           | 22               |            |
| 25           | *465 587*        |            |
| 53           | 853              |            |
| 80           | 443              |            |
| 67 68        |                  |            |
| 110          | *995*            |            |
| 119          |                  |            |
| 123          | 4460             |            |
| 139 445      |                  |            |
| 143          | *993*            |            |
| 389          | 636 3269         | SASL       |
|              | SRTP             |            |
| 161          | 161              |            |
## Diffusion
Diffusion is an encryption concept where changing one character of the input will cause many characters to change in the output.
## Confusion
Confusion is a concept associated with data encryption where the encrypted data is drastically different than the plain text.
## Diamond Model
The diamond model was created by the United States intelligence community as a way to standardize the attack reporting and the analysis of the intrusions.
## MITRE ATT&CK framework
MITRE provides the ATT&CK framework as a knowledgebase of attack types, techniques and mitigation options
## NIST RMF
The NIST (National Institute of Standards and Technology) RMF (Risk Management framework) is a guide to help understand, manage  and rate the risks found in an organization. 
## File Integrity Check
A file integrity Check (Tripwire, System File Checker) can be used to monitor and alert if there are any changes to a file. 
## HIPS
HIPS / Host-based Intrusion Prevention System would help identify any security vulnerabilities. May contain information about recent traffic flows to systems outside of the corporate network. HIPS would not commonly alert on the modification of a specific file. 
## Embedded system
An embedded system usually does not provide access to the OS and may not even provide a method of upgrading the system firmware.
## End of life 
A device at it's end of life is no longer supported by the vendor.
## Pulping
Pulping places papers into a large washing tank to remove the ink, and the paper is broken down into pulp and recycled. The information on the paper is not recoverable after pulping
## Degaussing 
Degaussing removes the electromagnetic field of storage media and electronics
## Host-based firewall logs
Host-based firewall will allow or disallow incoming or outgoing application traffic. 
## UTM 
A UTM / Unified Threat management appliance is commonly located in the core of the network. It would have a web security gateway, URL filter, content inspection, Malware inspection, spam filter, CSU, DSU, Router, Switch, Firewall, IDS, IPS, Bandwidth Shaper, and VPN endpoint.
## NetFlow logs
NetFlow information can provide a summary of network traffic, application usage and details of network conversations. The NetFlow logs will show all conversations from this device to any others in the network. 
## Email Header
An email header contains information of email servers used to transfer the message and security signatures to verify the sender. 
## Incident response Process
Preparation, Identification, Containment, Eradication, Recovery, Lessons learned
## Preparation
Communication methods, Incident handling hardware and software, IR resources, Incident mitigation software, and policies needed for incident handling
## Identification 
Detect and determine the nature of the incident. Gather and analyze data to confirm the incident
## Containment
Short term containment. Immediately stop the spread of the incident- isolate affected systems. 
## Eradication
Identify the root cause of the incident. Remove malware, close vulnerabilities, and eliminate the threat
## Recovery
Restore and validate system functionality. Monitor systems to ensure they return to normal operations without further incidents. 
## Lessons learned
Once the event is over, it's useful to revisit the process to learn and improve for next time. A post-incident meeting can help the incident response participants
discuss the phases of the incident that went well and which processes can
be improved for future events
## Disaster Recovery Plan
A disaster recovery plan is a comprehensive set of processes to to follow for large-scale outages that affect the organization.  Natural disasters, technology failures, and human-created disasters would be reasons to implement a disaster recovery plan
## Stakeholder management
Stakeholder management describers the relationship that IT has with their customers. Although stakeholder management is an important ongoing process, the priority after a major event is to start the disaster recovery process
## Communication plan
A communication plan is a list of everyone who needs to be contacted during an incident. The communication plan will be important documentation after a disaster recovery process has started.
## Retention policies
Retention policies specify the type and amount of data that must be backed up  and stored. These policies are often self-imposed or part of a larger set of rules and regulations
## Rootkit
A rootkit traditionally modifies core system files and becomes effectively invisible to the rest of the operating system. The modification of system files and specialized kernal-level drivers are common rootkit techniques
## Bot
A bot is relatively active malware that can usually be seen in a process list and by examining network communication. Botnet participants can often be identified using traditional anti-malware software
## Ransomware
Ransomware makes itself quite visible on your system, and it usually presents warning messages and information on how to remove the ransomware from the system
## Keylogger
A keylogger is a utility that captures keyboard and mouse input and sends that information to another device. This usually means that the keylogger has a visible component in the list of processes and traffic that can be seen on the network

# 1st pass - quickly answer what you know
# 2nd pass -  eliminate wrong answers
# 3rd pass -  only change for tangible reasons
























