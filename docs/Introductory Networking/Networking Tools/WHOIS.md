Domain Names -- the unsung saviours of the internet.  
Can you imagine how it would feel to remember the IP address of every website you want to visit? Horrible thought.  
Fortunately, we've got domains.  
We'll talk a little bit more about how this works in the next task, but for now suffice to know that a domain translates into an IP address so that we don't need to remember it (e.g. you can type [[tryhackme]].com, rather than the [[TryHackMe]] IP address). Domains are leased out by companies called Domain Registrars. If you want a domain, you go and register with a registrar, then lease the domain for a certain length of time.   
Enter Whois.  
Whois essentially allows you to query who a domain name is registered to. In Europe personal details are redacted; however, elsewhere you can potentially get a great deal of information from a whois search.  
There is a [web version]([[https]]://www.whois.com/whois/) of the whois tool if you're particularly adverse to the command line. Either way, let's get started!  
_(Note: You may need to install whois before using it. On Debian based systems this can be done with_ `sudo apt update && sudo apt-get install whois`_)_  
Whois lookups are very easy to perform. Just use `whois <domain>` to get a list of available information about the domain registration:  
![image]([[https]]://muirlandoracle.co.uk/wp-content/uploads/2020/03/image-16.png)  
This is comparatively a very small amount of information as can often be found. Notice that we've got the domain name, the company that registered the domain, the last renewal, and when it's next due, and a bunch of information about nameservers (which we'll look at in the next task).