The logical follow-up to the ping command is 'traceroute'. Traceroute can be used to map the path your request takes as it heads to the target machine.  
  
The internet is made up of many, many different servers and end-points, all networked up to each other. This means that, in order to get to the content you actually want, you first need to go through a bunch of other servers. Traceroute allows you to see each of these connections -- it allows you to see every intermediate step between your computer and the resource that you requested. The basic syntax for traceroute on [[Linux]] is this: `traceroute <destination>`  
By default, the [[Windows]] traceroute utility (`tracert`) operates using the same ICMP protocol that ping utilises, and the Unix equivalent operates over UDP. This can be altered with switches in both instances.  
![image]([[https]]://muirlandoracle.co.uk/wp-content/uploads/2020/03/image-15.png)  
You can see that it took 13 hops to get from my router (`_gateway`) to the Google server at 216.58.205.46  
Now it's your turn. As with before, all questions about switches can be answered with the man page for traceroute  
(`man traceroute`).