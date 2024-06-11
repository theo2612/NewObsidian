############################
### Categorizing Domains ###
############################

### These are sites to be used for domain categorization ###

 *  Bluecoat/Symantec - https://sitereview.bluecoat.com/sitereview.jsp
 *  McAfee - https://www.trustedsource.org
 *  Palo Alto Wildfire - https://urlfiltering.paloaltonetworks.com/query/
 *  Websense - https://csi.forcepoint.com & https://www.websense.com/content/SiteLookup.aspx  (needs registration)
 *  Fortiguard - http://www.fortiguard.com/iprep
 *  IBM X-force - https://exchange.xforce.ibmcloud.com/url/
 *  F-Secure SENSE - https://www.f-secure.com/en/web/labs_global/submit-a-sample
 *  Checkpoint - https://www.checkpoint.com/urlcat/main.htm (needs registration)
 *  Squid - https://www.urlfilterdb.com/suggestentries/add_url.html
 *  Cisco Talos - https://talosintelligence.com/reputation_center/  (needs registration)
 *  TrendMicro Smart Protection - https://global.sitesafety.trendmicro.com

### Steps to prepare a domain for categorization ###

1. Login to your Domain's Registrar
2. Set an "A" record on the parent domain to point to a legitimate website, preferrably one that aligns with your domain.
   Ex:  (our domain) ec2-amazonaws.net  -->  (legitimate domain) amazonaws.com
3. After setting the "A" record, let it sit for 5-7 days
4. Now go to the domain categorization links and type in our parent domain
5. Set the categorization on it. If you're mirroring it to a similar domain, use the same exact categorization label.
6. Do NOT remove the "A" record on the parent domain that was set earlier. When they query the parent domain, we want it to still be directed at a legitimate website.
7. Some domain categorization sites may send an email to verify you are in control of the domain. If so, setup an email inbox to catch any responses so you can confirm you are the owner.
8. Once categorization has been applied/submitted, check back in 5-14 days to allow it to be processed.