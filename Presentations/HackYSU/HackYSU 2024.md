- XZ hack
	- Asking audience, what happened. then explaining what I know.
	- Where does the xz library do and live?
		- Linux
		- Compress and decompress the xz and lzma file formats
			- By default compresses to xz
			- In most cases, xz achieves higher compression rates than gzip and bzip2
			- Decompression speed is higher than bzip but lower than gzip
			- xz very useful because lzma considered legacy 
	- IMO the social engineering aspect and malicious code are equally fascinating
	- High level malicious code overview
		- library
		- versions
		- obfuscation of the malicious code
		- backdoor
			- how it works
			- 
		- ifunc - So you need to know what ifunc is here to really understand what is going on - let’s say you write some code that processes a lot of data like XZ, and the standard code path is slow because you’re doing lots of work on the CPU. Maybe a newer processor can do something like matrix operations, so you rewrite the code so that it runs super fast but now it doesn’t work on older systems. The ifunc feature lets the system automatically select the appropriate version based on the capabilities. The attacker here used that to hide the code in oss-fuzz.
	- review social engineering 
		- IMO, 2 scenarios - We can speculate but will never know
			- 1. jia was an actual non-malicious contributor that had their account compromised.
			- 2. jia is a state sponsored malicious contributor/organization that played the longest game that I've seen. By establishing trust and well timed email thread responses that eventually convinced the original maintainer to pass control to the attacker. 
			- Pig butchering
	- [ARS technica - What we know about the xz Utils backdoor that almost infected the world](https://arstechnica.com/security/2024/04/what-we-know-about-the-xz-utils-backdoor-that-almost-infected-the-world/)
	- [Evan Boehs - Everything I know about the XZ backdoor](https://boehs.org/node/everything-i-know-about-the-xz-backdoor)
	- [Security Now TL:DR](https://www.youtube.com/watch?v=zZC-mrSpyEA&t=4391s) XZ outbreak
	- [Andres Freund](https://www.openwall.com/lists/oss-security/2024/03/29/4) Backdoor in upstream xz/liblzma leading to ssh server compromise
	- [GynVael.coldwind](https://gynvael.coldwind.pl/?lang=en&id=782#stage2-ext) explain like I'm 5 - xz/libzma: Bash-stage Obfuscation Explained
	- [Russ Cox- research!rsc](https://research.swtch.com/xz-timeline) Timeline of the xz open source attack
	- [Rob Mensching - A Microcosm of the interactions in Open Source projects](https://robmensching.com/blog/posts/2024/03/30/a-microcosm-of-the-interactions-in-open-source-projects/) maintainer possibly social engineered 
	- fr0gger_ twitter timeline https://twitter.com/fr0gger_/status/1774342248437813525/photo/1
	- creators blog https://tukaani.org/xz-backdoor/

---
# External Penetration Testing Methodology
## 
## Brad Theodore 
### Penetration Tester

note: Hi! BT, PT, Welcome to External Penetration Testing Methodology

--

Full presentation on my Github
https://github.com/theo2612​
![[hacking 4 arms.gif]]
