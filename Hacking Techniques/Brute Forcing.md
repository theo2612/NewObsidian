# Remote Access services
- SSH 
	- Secure Shell
	- initially used in Unix-like systems for remote login
	- provides the user with a command line interface (CLI) that can be used to execute commands
- RDP
	- Remote Desktop Protocol
	- also known as Remote Desktop Connection (RDC)
	- provides a Graphical User Interface to access a MS Windows system
	-  user can see their desktop and use the keyboard and mouse as if they were sitting at the computer
- VNC
	- Virtual Network Computing
	- provides access to a graphical interface which allows the user to view the desktop and optionally control the mouse and keyboard
	- Available for any system with graphical interface- MS Windows, Linux, macOS, Android, RaspberryPi

# Rockyou wordlist
- contains over 14 million unique passwords
- contains breached passwords
- location /usr/share/wordlists/rockyou.txt

# THC Hydra
-  supports many protocols, including SSH, VNC, FTP, POP3, IMAP, SMTP, and all methods related to HTTP
- usage
```bash
~$ hydra -l username -P wordlist.txt server service
```
- -l username
	- -l should precede *username* /the login name of the target. 
	- omit this if the service does not use a username
- -P wordlist.txt
	- -P precedes the *wordlist.txt* file, which contains the list of passwords you want to try with the provided username
- *server* is the hostname or IP address of the target server 
- *service* is the service in which you are trying to launch a dictionary attack
- examples
	- below will use *mark* as the username as it iterates over the provided passwords against the SSH server
	- written 2 ways
```bash
hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.98.238 ssh

hydra -l mark -P /usr/share/wordlists/rockyou.txt ssh://10.10.98.238
```
- Other protocols
	- you can replace ssh with another protocol name, such as rdp, vnc, ftp, pop3 
- other arguements
	- -v or -vV
		- for Verbose
		- makes Hydra show the username and password combinations being tried 
		- convenient to see the progress
	- -d 
		- for debugging
		- provides more detailed info about what's happening
		- if hydra tries to connect to a  closed port and timing out , -d will reveal immediately