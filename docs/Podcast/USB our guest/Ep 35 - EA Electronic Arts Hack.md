35. EA / Electronic Arts Hack

Hackers Steal Wealth of Data from Game Giant EA - [https://www.vice.com/en/article/wx5xpx/hackers-steal-data-electronic-arts-ea-fifa-source-code](https://www.vice.com/en/article/wx5xpx/hackers-steal-data-electronic-arts-ea-fifa-source-code) 

  

Hackers leak full EA data after failed extortion attempt

[https://therecord.media/hackers-leak-full-ea-data-after-failed-extortion-attempt/](https://therecord.media/hackers-leak-full-ea-data-after-failed-extortion-attempt/) 

  

How Hackers Used Slack to Break into EA Games

[https://www.vice.com/en/article/7kvkqb/how-ea-games-was-hacked-slack](https://www.vice.com/en/article/7kvkqb/how-ea-games-was-hacked-slack) 

  

EA ignored domain vulnerabilities for months despite warnings and breaches

[https://www.zdnet.com/article/ea-ignored-domain-vulnerabilities-for-months-despite-warnings-and-breaches/](https://www.zdnet.com/article/ea-ignored-domain-vulnerabilities-for-months-despite-warnings-and-breaches/) 

  

Hackers selling access to FIFA matchmaking servers and other games after EA attack 

[https://www.zdnet.com/article/hackers-selling-access-to-fifa-matchmaking-servers-and-other-games-after-ea-attack/](https://www.zdnet.com/article/hackers-selling-access-to-fifa-matchmaking-servers-and-other-games-after-ea-attack/) 

  

How Hackers Used Slack to Break into EA Games

[https://www.vice.com/en/article/7kvkqb/how-ea-games-was-hacked-slack](https://www.vice.com/en/article/7kvkqb/how-ea-games-was-hacked-slack) 

  

Hello and welcome back to USB our Guest Cyber Security tips. I’m Theo, here to help you break down cyber security topics and hacks. First off I want to send a sincere thank you to everyone who listens to my Podcast. It recently surpassed 2000 listens and honestly I couldn’t be happier. Considering I get to talk about what I truly have a passion for and hopefully I’m helping people protect themselves from a breach. Thank you. That being said, Today’s episode is about the EA or Electronic Arts hack. I have links to the articles referenced in the show notes. This episode is a little longer since there is a lot of ground to cover and a lot of technical jargon to dig through but hang in there. 

First off - The Breach 

Around June 6th, The bad guys claimed to have accessed and stolen data, totaling 780 GB, from Electronic Arts such as; source code for FIFA 21, code for it’s matchmaking server, source code for the Frostbite engine used to power Battlefield, software development kits, and bundles of code. 

From ‘The Record’ Recorded Future’s blog, The hackers claimed to have gained access to the data by using purchased Authentication cookies for $10 of an EA employee off the dark web. Then they used the auth cookies to mimic an already-logged in EA employee’s account and access EA’s Slack channel. 

Then, Vice reports, the malicious actors fooled an EA IT support agent and requested a multifactor authentication token, granting them access to the internal network.

To Summarize, the bad guys used a small but powerful piece of data, an auth cookie, to present themselves as an employee to trick an IT employee into handing over a MFA token, which allowed them access to the network. This a crude summary but what I want to stress is how the bad guys pieced together small stolen info to break into EA. 

ZDNet reports that Isreali cybersecurity firm Cyberpion informed EA of domains that could be subject to takeovers through misconfiguration. EA has at least 6 domains vulnerable to takeover listed in the article. 

The Record also reports that the bad guys dumped the data on an underground cybercrime forum on July 26th and sold stolen files to a 3rd party buyer after a failed attempt at extorting money from EA. 

ZDNet also reports that Hackers are selling access to FIFA matchmaking servers and other EA games. 

EA calls the haul that the bad guys stole, a “limited amount of game source code” and “No player data was accessed...we have no reason to believe there is any risk to player privacy”. Just to be safe, If you have a EA account, I would change your password.

  

So, there is a lot to unpack here. Here’s some definitions. 

How much data is 780GB? Well it’s ¾ of a 1 terrrabyte  Western digital backup drive or about 98 - 8GB Thumb Drives

Source code is any collection of code, using a programming language, for example C#, Python or Ruby to create applications or games.

FIFA is the Federation Internationale de Football Association - Soccer or football’s World governing body

Matchmaking - Many games have a pvp or player vs player mode where people can play against each other. To make this mode more fair and enjoyable, developers use matchmaking to match players with similar stats and ability. 

Frostbite engine - A Game engine is a software framework that is primarily designed for the development of video games. Frostbite is a game engine that is exclusive to Electronic Arts. 

Software development kits (SDK) - a SDK is a set of tools provided by the manufacturer of  hardware, an Operating system, or programming language that software developers use to create applications for those devices, OS’s or programming languages.

Authentication cookies - a token that is stored on the client/your device and the server/the app or website you are using to manage the connection. In this case they saved the login details of the of an employee

Slack - A messaging app primarily used by employees of businesses to communicate. 

Multifactor Authentication Token is an additional step in the form of a random number that generates regularly and is required for access of an account after a username and password has been provided. Usually sent to a separate device.

  

Thoughts

 Interestingly, the bad guys either decided not to encrypt data and steal Personal Identifiable information or couldn’t access it. It seems that without that kind of leverage, companies feel better about declining demands from the bad guys. Especially if they have backups or in EA’s position, an online marketplace where their games can be downloaded legally.

As for the domains, why not just take them down and wipe the DNS records? The domains may be in use publicly or privately or they may be holding on to them to sell in the future. At any rate, EA may need to review security practices. At the time of recording only one of the domains in the ZDNet article was accessible via a browser.

  

IMO, we are starting to see the beginnings of tiny leaks of data coming back to haunt us. An Auth cookie is a powerful but small piece to the internet. If a bad guy obtains access to it they can access an account on your network and the network itself with a little bit of social engineering.

Another  thing  to consider is with access to FIFA source code, SDKs, and matchmaking servers the bad guys can essentially run an online “FIFA” server with malicious intentions. The download of the malicious “FIFA” or accessing a malicious matchmaking server could include a backdoor to your device that the bad guys could use to install ransomware, cryptominers or other malicious code. Did I say malicious enough?

What can you do as a consumer? Only Buy from legit game merchants. Offering malicious games is a business just like any other business. Best way to shut them down is by not using their service or downloading their software. Nothing is free. You pay for it with your data or by giving the bad guys access to your device.

That's all for today's episode. If you have a topic you would like me to cover drop me a line at anchor.fm/usbog or email me at usbourguest@gmail.com. If I've helped you in any way please consider telling friends or family about the podcast. Or rate and review the podcast on whatever platform you use to listen. Thank you for listening and have a great day.