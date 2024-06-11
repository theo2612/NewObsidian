## RIS Red Teaming
Task - Steal ConnectWise credentials through phishing attack and log in using those credentials

---
## Key Accomplishments and What is done
- OSINT gathering
- Buying and setting up Domain @ namecheap.com and created subdomain
	- typsquatting - myconnectvvise.net, na.myconnectvvise.net
- Buy/setup Virtual Private Server at kamatera.com @ 83.229.115.238
	- Tunnel in from any command line with ssh -L 3333:127.0.0.1:3333 root@83.229.115.238 to access GoPhish GUI
- Creating legit mailserver - spf, dmarc w/ coreDNS, dkim w/ opendkim
- Docker containers with CoreDNS, Apache2, and GoPhish
- GoPhish 
	- ConnectWise phishing emails and spoofed landing pages 
	- ![[Pasted image 20231115180035.png]]
	- ![[Pasted image 20231115173605.png]]
## Key Accomplishments and What is done
- EvilGinx installed on VPS
	- Robust proxy and reverse proxy framework
	- Has the ability to sit between the user and service - User is none the wiser
	- Passes and steals username/password/MFA token as the information is sent to user and service 
	- GitHub POC - I've stole creds and session cookie but haven't been able to use to login - phishlet development
	- ![[Pasted image 20231112173343.png]]

---
## Road Blocks
- GoPhish running on Kali or local machine - Needs to run on a public ip to serve webpages 
- Emails being sent to Microsoft Quarantine
	- Tried to warm ip by sending emails to people to mark as safe and dig out of spam
- SpamHaus has blacklisted my IP 
	- Now *removed from blacklist* but may happen again
	- Outlook uses SpamHaus to identify malicious domains and ips
	- My emails were getting blocked and not even getting quarantine
	- They are now getting through to gmail 
- VPS provider has notified me of the SpamHaus blacklisting
	- Requested that I stop the malicious activity
	- I notified them that the server is for ethical phishing with explicit permission from the client
	- No response yet and I can still access my VPS

---
## Next Steps
- Continue to Warm IP
- Launch attack with what I have?
	- GoPhish to Phish users to steal username/password but not MFA
	- Sometimes the first emails that I send to a domain slip through but then get quarantined
	- Not sure how blacklisting will affect this. They may or may not get through.
- Continue to develop with EvilGinx
	- Phishlet for Connectwise
	- Developing phishlets takes time.
	- Each one is unique to the login page and is equally complex
	- I've been approved and given access to BreakDev professional private discord server of Kuba Gretzkey, creator of EvilGinx
	- I've purchased this and started this week [EvilGinx mastery course](https://academy.breakdev.org/view/courses/evilginx-mastery/1542370-default-section/6032721-thank-you)
- Recreate the infrastructure on AWS
	- Use Ansible or some other automation to spin up quickly and launch campaigns
	- AWS [Penetration Testing - Test the AWS environment against defined security standards](https://aws.amazon.com/security/penetration-testing/)
- Run CeWL on RIS website