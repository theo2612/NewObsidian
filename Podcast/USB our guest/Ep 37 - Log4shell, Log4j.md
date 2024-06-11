37 Log4shell, Log4j exploit or Log4what, is that a new crossfit trend?

TryHackMe’s Solar, exploiting log4j [https://tryhackme.com/room/solar](https://tryhackme.com/room/solar) 

The Log4J Vulnerability Will Haunt the Internet for Years [https://www.wired.com/story/log4j-log4shell/](https://www.wired.com/story/log4j-log4shell/) 

Huntress Log4Shell Vulnerability Tester [https://log4shell.huntress.com/](https://log4shell.huntress.com/) 

Apache logging services [https://logging.apache.org/](https://logging.apache.org/)

The Apache Software Foundation [https://www.apache.org/](https://www.apache.org/) 

USB our Guest - Episode 22 Updates - [https://anchor.fm/usbog/episodes/Software-Updates-emgnsh](https://anchor.fm/usbog/episodes/Software-Updates-emgnsh)

Log4j Attack surface - [https://github.com/YfryTchsGD/Log4jAttackSurface](https://github.com/YfryTchsGD/Log4jAttackSurface)

Log4j - Apache Log4j Security Vulnerabilities - [https://logging.apache.org/log4j/2.x/security.html](https://logging.apache.org/log4j/2.x/security.html)

JDBC Appender [https://logging.apache.org/log4j/2.x/manual/appenders.html#JDBCAppender](https://logging.apache.org/log4j/2.x/manual/appenders.html#JDBCAppender) 

Apache Log4j Security Vulnerabilities [https://logging.apache.org/log4j/2.x/security.html](https://logging.apache.org/log4j/2.x/security.html)

What is JDBC? [https://www.ibm.com/docs/en/informix-servers/12.10?topic=started-what-is-jdbc](https://www.ibm.com/docs/en/informix-servers/12.10?topic=started-what-is-jdbc) 

Lesson: Overview of JNDI [https://docs.oracle.com/javase/tutorial/jndi/overview/index.html](https://docs.oracle.com/javase/tutorial/jndi/overview/index.html)

W3Schools - Addressing [https://www.w3.org/Addressing/URL/uri-spec.html](https://www.w3.org/Addressing/URL/uri-spec.html) 

Amazon Affiliate link - [https://amzn.to/3rpF5KI](https://amzn.to/3rpF5KI) 

  

Hello and welcome back to USB our Guest Cyber Security tips. I’m Theo, here to help you break down cyber security news and hacks and how they affect you. Today’s episode covers the vulnerability affecting Java logging package, Log4j. This episode took a little longer to make  than expected due to its complexity. This episode will be a little longer and a bit technical but will not be a deep dive. I am not an expert in this exploit, but I’m including tons of links in the show notes with what I feel are excellent resources on the Log4j. Also, a break from the norm,  I will start and end the episode with what I feel you as a user should be doing to keep your laptop or desktop safe. 

What should you do? Make sure updates or patches for your desktop and laptop as well as programs and applications on them are applied as developers release them.  I did an entire episode on updates, I’ll put a link in the show notes or scroll up or down to get to it.

Now, let’s jump in. 

  

So, the 50,000ft view is this- Log4j is a Java based logging utility that is part of the Apache Logging services and a project of the Apache Software foundation. According to the Apache Log4j Vulnerabilities page - Apache Log4j versions 2.0-beta7 through 2.17.0 are vulnerable to a Remote Code Execution (RCE) attack where an attacker with permission to modify the logging configuration file can construct a malicious configuration using a JDBC Appender with a data source referencing JNDI URI which can execute remote code

  

Ok so that was a mouthful already, what did all that mean? Here is a break down 

Logging refers to files that contain timestamped data of events that occur in an operating system of software

Log4j is the Logging package for Java

Java is computer programming language

Apache Logging Services create and maintain the Log4j utility

Apache Software Foundation is the organization that supports many open source software projects like Apache logging services

Remote Code Execution (RCE) is just what it sounds like. It allows an attacker to remotely execute malicious code from their computer to another that they may not have legitimate access to. 

The JDBC Appender writes log events to a relational database table using standard JDBC. JDBC or Java Database connectivity is the JavaSoft specification of a standard application programming interface that allows Java programs to access database management systems

JNDI or Java Naming and Directory Interface is an application programming interface (API) that provides naming and directory functionality to applications written using the Java programming language

URI or Universal Resource identifier is a member of this universal set of names in registered name spaces and addresses referring to registered protocols or name spaces.

  

So, that was a lot. Long and short, This logging utility is used in known and unknown places by a lot of vendors and will be around for a while. List of the attack surfaces is a link in the show notes

  

 IMO opinion the best resource I came across for understanding log4j was a TryHackMe room created by John Hammond. John writes 

“Please use the information you learn in this room to better the security landscape. Test systems you own, apply patches and mitigations where appropriate, and help the whole industry recover. This is a very current and real-world threat -- whether you are a penetration tester, red teamer, incident responder, security analyst, blue team member, or what have you -- this exercise is to help you and the world understand and gain awareness on this widespread vulnerability. It should not be used for exploitative gain or self-serving financial incentive (I'm looking at you, beg bounty hunters)

Additionally, please bear in mind that the developers of the log4j package work on the open source project as a labor of love and passion. They are volunteer developers that maintain their project in their spare time. There should be absolutely no bashing, shame, or malice towards those individuals. As with all things, please further your knowledge so you can be a pedestal and pillar for the information security community. Educate, share, and help.”

  
  
  

End - So, again, What should you do to protect yourself? Make sure updates or patches for your desktop and laptop as well as programs and applications on them are applied as developers release them. 

How do they do this? Many apps or programs can be set to update themselves. If they don’t, typically, the app will indicate in a menu or a pop-up that an update is ready to be installed. 

  

That’s all for today’s episode. If you have a topic you would like me to cover drop me a line at anchor.fm/usbog or email me at [usbourguest@gmail.com](mailto:usbourguest@gmail.com).   If I've helped you in any way please consider telling friends or family about the podcast. Or rate and review the podcast on whatever platform you use to listen. Also, quick ask, If you use Amazon please consider shopping through my Amazon affiliates link in the show notes. You get your stuff and I get a tiny commission.

 Thank you for listening and have a great day.
