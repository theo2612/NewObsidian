- `$ ip link show ens192`
	- status of interface
	- MAC address of interface

Junos OS switch 
- check the MAC table and confirm the number of hosts per VLAN
- `show ethernet-switching table`
	- shows hosts
	- vlans
	- mac addresses 
	- interfaces

- clear the MAC addresses for the Guest VLAN from the MAC table 
	- `clear ethernet-switching table interface ge-0/0/4.0`

- To see interface properties on a Junos device use the show command
	- `show interfaces ge-0/0/0`