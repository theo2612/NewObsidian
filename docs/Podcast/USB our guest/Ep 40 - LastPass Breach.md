[LastPass - Notice of Recent Security Incident]([[https]]://blog.lastpass.com/2022/08/notice-of-recent-security-incident/)
[Explore how LastPass keeps you safe during a security event or potential hack]([[https]]://www.lastpass.com/security/what-if-lastpass-gets-hacked)
[LastPass - Zero knowledge ]([[https]]://www.lastpass.com/security/zero-knowledge-security)
[Forbes - LastPass Hacked: Password Manager With 25 Million Users Confirms Breach]([[https]]://www.forbes.com/sites/daveywinder/2022/08/25/lastpass-hacked-password-manager-with-25-million-users-confirms-breach/?sh=4c25e8b87d5a)
[Dark Reading - LastPass Suffers Data breach, Source Code Stolen]([[https]]://www.darkreading.com/cloud/lastpass-data-breach-source-code-stolen)
[Bleeping Computer - LastPass says hackers had internal access for four days]([[https]]://www.bleepingcomputer.com/news/security/lastpass-says-hackers-had-internal-access-for-four-days/)

Hello and welcome back to USB our Guest Cyber Security tips. I’m Theo, here to help you break down cyber security news and hacks and how they affect you. 

Today's episode covers the recent LastPass Breach, or as they put it from their last blog, a"Security Incident".  I've added links to the show notes that include LastPass's blog on the incident as well as other reports on the breach. This episode is organized as follows. I'll breakdown their blog post paragraph by paragraph, peppering in reports on the breach and end with suggestions to better protect yourself. 
That being said let's jump in. 

What happened?
From LastPass' blog “Two weeks ago, we detected some unusual activity within portions of the LastPass development environment. After initiating an immediate investigation, we have seen no evidence that this incident involved any access to customer data or encrypted password vaults.” 
Unusual activity like what? No details have been shared on exactly what unusual activity was detected. If last pass has an intrusion detection It could have been high network activity while the bad guys made off with the source code as will be mentioned in the next section.
What is a development environment? It's where new code and projects are created before being tested and released to the public and into their live product, that you use if you are a LastPass user. 
Why is that worriesome? The bad guys can now duplicate LastPass's environment to pracitce their attacks on. They don't have to worry about being stealthy. They can make as much noise or generate as much traffic as they want on thier own systems and practice being covert later. They can also duplicate LastPass' website for user name / password or credential stealing.
The last line that states "we have seen no evidence that this incident involved any access to customer data" is commonplace now while disclosing breachs. They have not stated that they know 100% that the bad guys have not accessed customer data but at the same time are not asking users to reset passwords. 
Tangent here - LastPass uses something they call Zero-Knowledge. This means that no one has access to your master password or the data stored in your vault, except you. Not even LastPass. The LastPass service also uses End-point Encryption and it happens exclusively at the device level before syncing to LastPass for safe storage, so only users can decrypt their data. 

“We have determined that an unauthorized party gained access to portions of the LastPass development environment through a single compromised developer account and took portions of source code and some proprietary LastPass technical information. Our products and services are operating normally."
How was it compromised? According to Bleeping computer, Lastpass' CEO Karim Troubba states "the threat actor was able to impersonate the developer after he "had successfully authenticated using multi-factor authentication."" No other information has been given on just how they authenicated and with what factor.
So What’s a developer account? In comparison a user account will provide access to the LastPass service, where a developer account gives you access to the LastPass software that runs the service. Good news here, Bleeping Computer reports that only the Build Release team can can push code from Development into Production, and even then, Toubba states that the process involves code review, testing and validation stages. 
Source code? Source Code is the code that runs LastPass service. 

"In response to the incident, we have deployed containment and mitigation measures, and engaged a leading cybersecurity and forensics firm. While our investigation is ongoing, we have achieved a state of containment, implemented additional enhanced security measures, and see no further evidence of unauthorized activity.  "
Containment and Mitigation? From Toubba's blog post on LastPass "LastPass Development environment is physically separated from, and has not direct connectivity to LastPass' Production environment. "
What cybersecurity and forensics firm? Last Pass hired Mandiant to investigate the breach. Mandiant has been hired in the past by Sony after their 2014 breach, and more recently by T-mobile after their breach last year.

"Based on what we have learned and implemented, we are evaluating further mitigation techniques to strengthen our environment. We have included a brief FAQ below of what we anticipate will be the most pressing initial questions and concerns from you. We will continue to update you with the transparency you deserve." (edited)
In my opinion, aside from the initial 2 week breach notification delay as reported on LastPass' blog, this has been a decently transparent disclosure of a breach. Maybe that's because LastPass' architecture is set up to better mitigate a breach, not to hope one doesn't occur. LastPass has notified customers when they detected "unusual activity", were upfront about what the bad guys stole and what you should do as a user. 


#  Suggestions
* Go back and listen to episode 4 on Password Managers. 
* If you use LastPass as a password manager, and Although they haven't suggested it, I would consider changing your master password.
* YubiKey - these little devices are the "something you have" part of Multifactor authentication and integrate with LastPass


That's all for today's episode. If you have a topic you would like me to cover drop me a line at anchor.fm/usbog, email me at usbourguest@gmail.com or visit me on twitch at twitch.tv/b7h30. If I've helped you in any way please consider telling friends or family about the podcast. Or rate and review the podcast on whatever platform you use to listen. Thank you for listening, stop reusing passwords and have a great day.






