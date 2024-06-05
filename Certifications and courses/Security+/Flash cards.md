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
Mean time between failure
## RTO #card
Recovery time objectives
## MTTR #card
Mean time to restore
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
could be used to prevent mobile device use from other countries, but you still need a MDM to implement the other requirements
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
Role Based Access Control assign rights and permissions based on the role of a user. These roles are usually assigned by group

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







