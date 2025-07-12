##### Initial Mode: User EXEC Mode
- Switch>

##### Privileged EXEC mode
- Switch> `enable`
- Switch#
- S1# `wr`
	- wr is shorthand for `write memory`, which saves the running config to NVRAM so it persists after reboot

##### Global Configuration Mode
- Switch# `configure terminal` or `conf t`
- Switch(config)# `hostname S1` 
	- changes hostname of switch
- S1(config)# `enable password password`
	- enables password for all lines
- S1(config)# `enable secret class`
	- creates password for global configuration mode
- S1(config)# `service password-encryption`
	- encrypts plaintext passwords
- S1(config)# `banner motd "Your mom"`
	- creates or changes message of the day

##### Line configuration Mode
- S1(config)# `line console 0`
	- configures the console line (physical access via cable)
- S1(config-line)# `password cisco`
	- sets the password for console line 0
- S1(config-line)# `login`
	- enables password checking at login
- S1(config-line)# `exit`
	- exits back to Global Config

##### Configure Switch Management Interface
- S1# `configure terminal` or `conf t`
- Enter configuration commands, one per line. End with CNTL/Z
- S1(config)# `interface vlan 1`
- S1(config-if)# `ip address ###.###.###.### ###.###.###.###`
	- ip address and subnet mask
- S1(config-if)# `no shutdown`
	- changes switch state to up
- %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan1, changed state to up
- S1(config-if)# 
- S1(config-if)# exit
- S1# wr




















