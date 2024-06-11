**Active Directory (AD)** is a database, which can be used to centrally manage a Microsoft Windows network, users, groups, servers, clients, computers, printers, hardware, shared files and folders and other objects and resouces. 
**Active Directory (AD)** is a directory service that uses the Lightweight Directory Access Protocol (LDAP).
**Lightweight Directory Access Protocol (LDAP)** is an open and crossplatform directory services protocol that is used by most directory services.
**AD Object** can be a container object such as a folder or a leaf such as a file
**AD Domain** is organized around a collection of objects. A domain can share policy and use an AD database
**A tree** is organized around multiple AD domains. Domains in a tree share network configuration
**A forest** is organized around a group of trees that have the same database. Trees in a forest have different namespace
### **Organizational Units (OUs)**
are AD contaienrs that allow you to place users, printer, groups, computers and other objects. OUs can be nested inside of each other. You can use OUs to represent an organization's organizational chart. *A good reason to use OUs is to be able to assign a group policy to the OU and all users and computers that are members of that OU will get that policy.*

**Group Policies** in Active Directory can be set at the site, domain, and organizational level of Active Directory as well as on a local machine. 
_Group policies_ are applied at the site first
_Domain policies_ are applied second
_Organizational Unit (OU) policies_ are applied third
_Local Machine policies_ are applied last
If you set a group policy at the domain level, every thing below the domain will get the Group policy first
	_Best practice_ is to not set domain level group policies but to set organizational unit level group policies. Microsoft has setup a hierarchy in active directory when applying group policies. Applied in this order 
* _Local policies_ are Configured on the actual computer itself
* _Site policies_ are Configured in Active Directory, You can configure a site which sid a representation of a physical location
* _Domain policies_ are configured in Active Directory and applies to all objects in the domain assigned
* _Organizational Unit (OU) policies_ are configured in Active Directory and applies to all objects in the Organizational Unit

The beauty of group policies is the ability to have greater contrl over the security of your network as a system administrator. 

Here are some ways to configure group policies in Active directory
* Password Policies can be set to establish password length, complexity and other requirements
* Systems Management can apply standardized, universal settings accross all new users with just a few clicks
* Health Checking can be used to deploy software updates/patches to ensure your systems are up to date against the latest vulnerabilities
