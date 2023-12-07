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

## 3 digit passcode cracking on panel
- Numeric key pad on website

|            |
|---|---|---|---|
| 0  | 1  | 2  | 3  |
| 4  | 5  | 6  | 7  |
| 8  | 9  | A  | B  |
| C  | D  | E  | F  |

- numeric key pad shows 16 characters 
- 0-9 and A-F
- Using Crunch to prepare a list of all the possible password combinations. 
```bash
crunch 3 3 0123456789ABCDEF -o 3 digits.txt
```
- `3` the first number is the minimum length of the generated password
- `3` the second number is the maximum length of the generated password
- `0123456789ABCDEF` is the character set to use to generate the passwords
- `-o 3digits.txt` saves the output to the `3digits.txt` file

- Using hydra to automate the attack we need a few items from the panel's webpage
	- The method is `post`
	- The URL is `http://10.10.7.159:8000/login.php`
	- The PIN code value is sent with the name `pin'
```html
body class="bg-thm text-white">
  <div class="flex items-center justify-center min-h-screen w-full max-w-xl mx-auto">
    <form method="post" action="login.php" class="grid grid-cols-3 max-w-lg mx-auto bg-thm-900 p-4 font-mono">
      <input type="hidden" name="pin" />
```
- The main login page is http://10.10.7.159:8000/pin.php
- receives input from the user and sends it to /login.php
- using the name `pin`.
- Crafted hydra command
```bash
hydra -l '' -P 3digits.txt -f -v 10.10.7.159 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000`
```
The command above will try one password after another in the `3digits.txt` file. It specifies the following:

- `-l ''` indicates that the login name is blank as the security lock only requires a password
- `-P 3digits.txt` specifies the password file to use
- `-f` stops Hydra after finding a working password
- `-v` provides verbose output and is helpful for catching errors
- `10.10.7.159` is the IP address of the target
- `http-post-form` specifies the HTTP method to use
- `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
    - `/login.php` is the page where the PIN code is submitted
    - `pin=^PASS^` will replace `^PASS^` with values from the password list
    - `Access denied` indicates that invalid passwords will lead to a page that contains the text “Access denied”
- `-s 8000` indicates the port number on the target
















