When it comes to hacking, knowledge is power. The more knowledge you have about a target system or network, the more options you have available. This makes it imperative that proper enumeration is carried out before any exploitation attempts are made.  
Say we have been given an IP (or multiple IP addresses) to perform a security audit on. Before we do anything else, we need to get an idea of the “landscape” we are attacking. What this means is that we need to establish which services are running on the targets. For example, perhaps one of them is running a webserver, and another is acting as a Windows Active Directory Domain Controller. The first stage in establishing this “map” of the landscape is something called port scanning. When a computer runs a network service, it opens a networking construct called a “port” to receive the connection.  Ports are necessary for making multiple network requests or having multiple services available. For example, when you load several webpages at once in a web browser, the program must have some way of determining which tab is loading which web page. This is done by establishing connections to the remote webservers using different ports on your local machine. Equally, if you want a server to be able to run more than one service (for example, perhaps you want your webserver to run both HTTP and HTTPS versions of the site), then you need some way to direct the traffic to the appropriate service. Once again, ports are the solution to this. Network connections are made between two ports – an open port listening on the server and a randomly selected port on your own computer. For example, when you connect to a web page, your computer may open port 49534 to connect to the server’s port 443.  
![image](https://i.imgur.com/3XAfRpI.png)  
As in the previous example, the diagram shows what happens when you connect to numerous websites at the same time. Your computer opens up a different, high-numbered port (at random), which it uses for all its communications with the remote server.  
Every computer has a total of 65535 available ports; however, many of these are registered as standard ports. For example, a HTTP Webservice can nearly always be found on port 80 of the server. A HTTPS Webservice can be found on port 443. Windows NETBIOS can be found on port 139 and SMB can be found on port 445. It is important to note; however, that especially in a CTF setting, it is not unheard of for even these standard ports to be altered, making it even more imperative that we perform appropriate enumeration on the target.  
If we do not know which of these ports a server has open, then we do not have a hope of successfully attacking the target; thus, it is crucial that we begin any attack with a port scan. This can be accomplished in a variety of ways – usually using a tool called nmap, which is the focus of this room. Nmap can be used to perform many different kinds of port scan – the most common of these will be introduced in upcoming tasks; however, the basic theory is this: nmap will connect to each port of the target in turn. Depending on how the port responds, it can be determined as being open, closed, or filtered (usually by a firewall). Once we know which ports are open, we can then look at enumerating which services are running on each port – either manually, or more commonly using nmap.  
So, why nmap? The short answer is that it's currently the industry standard for a reason: no other port scanning tool comes close to matching its functionality (although some newcomers are now matching it for speed). It is an extremely powerful tool – made even more powerful by its scripting engine which can be used to scan for vulnerabilities, and in some cases even perform the exploit directly! Once again, this will be covered more in upcoming tasks.  
For now, it is important that you understand: what port scanning is; why it is necessary; and that nmap is the tool of choice for any kind of initial enumeration.  
  
What is the first switch listed in the help menu for a 'Syn Scan' (more on this later!)?  
$ -sS  
  
Which switch would you use for a "UDP scan"?  
$ -sU  
  
If you wanted to detect which operating system the target is running on, which switch would you use?  
$ -O  
  
Nmap provides a switch to detect the version of the services running on the target. What is this switch?  
$ -sV  
  
The default output provided by nmap often does not provide enough information for a pentester. How would you increase the verbosity?  
$ -v  
  
Verbosity level one is good, but verbosity level two is better! How would you set the verbosity level to two?  
(**Note**: it's highly advisable to always use _at least_ this option)  
$ -vv  
  
We should always save the output of our scans -- this means that we only need to run the scan once (reducing network traffic and thus chance of detection), and gives us a reference to use when writing reports for clients.  
What switch would you use to save the nmap results in three major formats?  
$ -oA  
  
What switch would you use to save the nmap results in a "normal" format?  
$ -oN  
  
A very useful output format: how would you save results in a "grepable" format?  
$ -oG  
  
Sometimes the results we're getting just aren't enough. If we don't care about how loud we are, we can enable "aggressive" mode. This is a shorthand switch that activates service detection, operating system detection, a traceroute and common script scanning.  
How would you activate this setting?  
$ -A  
  
Nmap offers five levels of "timing" template. These are essentially used to increase the speed your scan runs at. Be careful though: higher speeds are noisier, and can incur errors!  
How would you set the timing template to level 5?  
$ -T5  
  
We can also choose which port(s) to scan.  
How would you tell nmap to only scan port 80?  
$ -p 80  
  
How would you tell nmap to scan ports 1000-1500?  
$ -p 1000-1500  
  
A very useful option that should not be ignored:  
How would you tell nmap to scan _all_ ports?  
$ -p-  
  
How would you activate a script from the nmap scripting library (lots more on this later!)?  
$ --script  
  
How would you activate all of the scripts in the "vuln" category?  
$ --script=vuln