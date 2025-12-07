29 Microsoft Exchange Server hack

Krebs on Security - At Least 30,000 U.S. Organizations Newly Hacked Via Holes in Microsoft’s Email Software - [[[https]]://krebsonsecurity.com/2021/03/at-least-30000-u-s-organizations-newly-hacked-via-holes-in-microsofts-email-software/]([[https]]://krebsonsecurity.com/2021/03/at-least-30000-u-s-organizations-newly-hacked-via-holes-in-microsofts-email-software/) 

ZD Net - Everything you need to know about the Microsoft Exchange Server hack - [[[https]]://www.zdnet.com/article/everything-you-need-to-know-about-microsoft-exchange-server-hack/]([[https]]://www.zdnet.com/article/everything-you-need-to-know-about-microsoft-exchange-server-hack/) 

Microsoft’s Github with tools for mitigation - [[[https]]://github.com/microsoft/CSS-Exchange/tree/main/Security]([[https]]://github.com/microsoft/CSS-Exchange/tree/main/Security) 

ZD Net

Microsoft blog with patch update - [[[https]]://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/]([[https]]://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/) 

Krebs on Security - A Basic Timeline of the Exchange Mass Hack [[[https]]://krebsonsecurity.com/2021/03/a-basic-timeline-of-the-exchange-mass-hack/]([[https]]://krebsonsecurity.com/2021/03/a-basic-timeline-of-the-exchange-mass-hack/) 

USB our Guest - Software Updates

[[[https]]://anchor.fm/usbog/episodes/Software-Updates-emgnsh]([[https]]://anchor.fm/usbog/episodes/Software-Updates-emgnsh) 

  

Hello and welcome back to USB our Guest Cyber Security tips. Today’s episode covers the Microsoft Server Exchange Hack. I have a few links to articles in the show notes. The articles from ZDnet article and The KrebsOnSecurity will give you a quick informative guide to the hack. The second ZDnet article has a link to Microsoft’s GitHub account where they have published a script that can check the security status of Exchange Servers. The other links helps fill in the gaps with a deep dive. 

 So disclaimer here, this is a fairly technical hack. The purpose of this episode is to give you a high level overview of the hack, a timeline, who is responsible and what to do? 

What is the hack? Multiple vulnerabilities in Microsoft Exchange Servers were found by the bad guys. They used these vulnerabilities to create an attack chain that can lead to Remote Code Execution or RCE, server hijacking, backdoors, data theft, and additional malware deployment. 

Timeline pulled from Krebs on Security - This timeline is not to cast additional blame but to highlight just how complicated finding and patching vulnerabilities is and how quickly things escalate. 

 Jan. 5: DEVCORE alerts Microsoft of its findings.

-   Jan. 6: Volexity spots attacks that use unknown vulnerabilities in Exchange.
    
-   Jan. 27: Dubex alerts Microsoft about attacks on a new Exchange flaw.
    
-   Feb. 2: Volexity warns Microsoft about active attacks on previously unknown Exchange vulnerabilities.
    
-   Feb. 8: Microsoft tells Dubex it has “escalated” its report internally.
    
-   Feb. 18: Microsoft confirms with DEVCORE a target date of Mar. 9 (tomorrow) for publishing security updates for the Exchange flaws. 
    
-   Feb. 26-27: Targeted exploitation gradually turns into a global mass-scan; attackers start rapidly backdooring vulnerable servers.
    
-   Mar. 2: A week earlier than previously planned, Microsoft [releases updates to plug 4 zero-day flaws in Exchange]([[https]]://krebsonsecurity.com/2021/03/microsoft-chinese-cyberspies-used-4-exchange-server-flaws-to-plunder-emails/).
    
-   Mar. 3: Tens of thousands of Exchange servers compromised worldwide, with thousands more servers getting freshly hacked each hour.
    
-   Mar. 5: KrebsOnSecurity [breaks the news]([[https]]://krebsonsecurity.com/2021/03/at-least-30000-u-s-organizations-newly-hacked-via-holes-in-microsofts-email-software/) that at least 30,000 organizations in the U.S. — and hundreds of thousands worldwide — now have backdoors installed.
    
-   Mar. 9: Microsoft says 100,000 of 400,000 Exchange servers globally remain unpatched.
    
-   Mar. 9: Microsoft “[Patch Tuesday]([[https]]://krebsonsecurity.com/2021/03/microsoft-patch-tuesday-march-2021-edition/),” (the original publish date for the Exchange updates); Redmond patches 82 security holes in [[Windows]] and other software, including a zero-day vulnerability in its web browser software.
    
-   Mar. 12: Microsoft [says]([[https]]://twitter.com/briankrebs/status/1370565978153684994) there are still 82,000 unpatched Exchange servers exposed. “Groups trying to take advantage of this vulnerability are attempting to implant ransomware and other malware that could interrupt business continuity.”
    

Who is responsible for the known attacks? Halfnium, who is a state sponsored advanced persistent threat (APT) group from China. While Hafnium Hails from China, they also use VPN’s located in the US to disguise their location.  But is it just Hafnium? NO. Once a Zero day has been found by bad guys and patches are released, it becomes a race by other bad guys to exploit the vulnerability. 

What do you do? If you haven’t done so, First  use the link in the show notes to the Microsoft Security Response Center and  apply the security fixes asap. Second, use Microsoft’s Github with tools for mitigation link in the show notes also. The script has three operations it performs

-   Mitigates against current known attacks
    
-   Scan the Exchange Server using the [Microsoft Safety Scanner]([[https]]://docs.microsoft.com/en-us/[[windows]]/security/threat-protection/intelligence/safety-scanner-download)
    
-   Attempt to remediate compromises detected by the Microsoft Safety Scanner.
    

Yet another reason to patch or update systems or programs as soon as they are available. I did an entire episode on updates, I’ll put another link in the show notes or scroll up or down to get to it. 

 That's all for today's episode. If you have a topic you would like me to cover drop me a line at anchor.fm/usbog or email me at usbourguest@gmail.com. If I've helped you in any way please consider telling friends or family about the podcast. Or rate and review the podcast on whatever platform you use to listen. Thank you for listening and have a great day.