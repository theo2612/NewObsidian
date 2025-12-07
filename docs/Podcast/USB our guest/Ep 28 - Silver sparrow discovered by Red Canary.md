28 Silver Sparrow discovered by Red Canary

  

 RedCanary's silver sparrow discovery - [[[https]]://redcanary.com/blog/clipping-silver-sparrows-wings/]([[https]]://redcanary.com/blog/clipping-silver-sparrows-wings/) 

 Computer world - [[[https]]://www.computerworld.com/article/3609611/30k-macs-infected-with-silver-sparrow-virus-m1-mac-ssd-health.html]([[https]]://www.computerworld.com/article/3609611/30k-macs-infected-with-silver-sparrow-virus-m1-mac-ssd-health.html)

 MITRE|ATT&CK - LaunchAgents - [[[https]]://attack.mitre.org/techniques/T1543/001/]([[https]]://attack.mitre.org/techniques/T1543/001/)

 CyberWire- Silver Sparrow targets Macs - [[[https]]://thecyberwire.com/newsletters/week-that-was/5/8]([[https]]://thecyberwire.com/newsletters/week-that-was/5/8) 

 USB our Guest - Episode 22 Updates - [[[https]]://anchor.fm/usbog/episodes/Software-Updates-emgnsh]([[https]]://anchor.fm/usbog/episodes/Software-Updates-emgnsh)

 Welcome back to USB our Guest, Cyber Security Tips. Today’s episode covers Red Canary’s discovery of the Silver Sparrow malware strain. Red Canary? Silver Sparrow? So, quick note, you did not just stumble into a bird watching podcast. Because neither of those do not sound like a cyber security threat, Let’s break this down.

From their website, Red Canary is a Cyber Security company that provides analytics, reporting, automation and detection services. Include official red canary blurb. Detect is just what Red Canary did. A pair of their engineers found a strain of macOS “payload-less” malware using a combination of a LaunchAgent to establish persistence, JavaScript for execution and binary compiled for Apple’s new chip, M1 ARM64 architecture. 

So look, there is a lot going on there and full disclosure, I’m not an Apple PC user, so I had to do a bit of research. Here are a couple definitions . 

LaunchAgent - scripts or code that automatically run to manage system processes 

Pay-load - what the malware was designed to do

JavaScript - Programming Language

Binary compiled for M1- Code was specifically designed for M1

  

What does all this mean? Essentially, the bad guys have developed payload-less malware that uses the LaunchAgent framework that automatically runs, created using JavaScript code that is specifically designed for Apple’s new M1 chip. 

The good News is that Apple is usually quick to take action and stay on top of situations like this. They have already revoked the 2 developer’s certificates so if you have been infected by Silver Sparrow malware, it will not run if tried to install. 

Concerning news is that future variants could just need to be signed by a new developer to be launched

Bad news as read from the RedCanary write up; link is in the show notes  - “the ultimate goal of this malware is a mystery. We have no way of knowing with certainty what payload would be distributed by the malware, if a payload has already been delivered and removed, or if the adversary has a future timeline for distribution. Based on data shared with us by Malwarebytes, the nearly 30,000 affected hosts have not downloaded what would be the next or final payload.

Finally, the purpose of the Mach-O binary included inside the PKG files is also a mystery. Based on the data from script execution, the binary would only run if a victim intentionally sought it out and launched it. The messages we observed of “Hello, World!” or “You did it!” could indicate the threat is under development in a proof-of-concept stage or that the adversary just needed an application bundle to make the package look legitimate.”

So, how do you protect yourself? Use antivirus software with real-time scanning from a trusted MAC developer and Keep your system updated. Apple will continue to work on keeping your device secure so download and install updates as soon as they are available. 

Making the case for updates, again. In case you missed it, I did a whole episode on this. Just scroll up or down to episode 22 - Software Updates and I’ll put a link in the showe notes. 

That's all for today's episode. If you have a topic you would like me to cover drop me a line at anchor.fm/usbog or email me at usbourguest@gmail.com. If I've helped you in any way please consider telling friends or family about the podcast. Or rate and review the podcast on whatever platform you use to listen. Thank you for listening and have a great day.