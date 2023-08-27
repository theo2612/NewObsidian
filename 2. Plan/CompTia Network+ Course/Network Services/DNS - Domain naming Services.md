DNS - Domain Naming Services  
port 53  
  
DNS -  
Provides name resolution from FQDN/Fully Qualified Domain Name to IP address  
Hosts file also provides name resolution but is static  
Database uses records of various types to provide/store information  
  
DNS/Domain Naming Services Record Types  
A(Host) - Provides IP to FQDN/Fully Qualified Domain Name resolution  
AAAA Provides IPv6 to FQDN/Fully Qualified Domain Name resolution  
PTR - Pointer provides resolution from FQDN to IP address  
SoA- Start of Authority provides address of server authoritative for the zone. Usually the first DNS server that has name resolution for that zone  
NS - Lists name servers for the zone  
SRV - Service records list the critical network services and their IP addresses  
ex. If your host needs to know where a domain controller is asks DNS.  
DMS uses the service record and says ‘A LDAP server’ and here is the IP address for it or a Kerberos key distribution server or a global catalog server or a mail server.  
So the service records have all the services in which servers are running them.  
CNAME - (Alias) giving servers and alternative name on the back end  
MX - (Mail) indicates where the mail servers are  
  
DNS resolution-  
![[1 1.png]]
  
  
DHCP - Dynamic Host Configuration Protocol ?  
  
  
IPAM - IP Address Managament ?