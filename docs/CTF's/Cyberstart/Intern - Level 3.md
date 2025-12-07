CO1 0x1badb007  
These are the two codes ROXy sent us, which we think can be combined in some way to generate a secret code. See what you do with it. We believe the code should start with the same 0x prefix.  
0xB105F00D 0xAAA8400A  
Calculate XOR - [[[http]]://xor.pw/#]([[http]]://xor.pw/#)  
  
CO2 wUMB01Ni2Ik6fJV0a7nC  
bypass a security gateway to a warehouse we believe holds clues to the whereabouts of a gang we are in hot pursuit of. The thing is, the gateway was created by someone who loves doing everything super fast! That means you only get 0.1 seconds to answer the question asked by the gateway. Can you find a way around it?  
Tip: Bypass the calculator lock to get the flag.  
Hint: Try watching the source code as you are spinning a new set of numbers. What changes when the spin is happening and then when the calculator gets locked?  
F12 >  
change <div id="calc-status" class="status status-**locked**">Locked! Out of time.</div>  
to  
<div id="calc-status" class="status status-**unlocked**">Locked! Out of time.</div>  
and  
<form class="form" id="calc-form" action="">  
to  
<form class="form" id="calc-form" action="/flashfast/answer">  
then  
Calculate the 2 numbers  
Submit answer  
  
C03 postD4ta_w1zard  
We're hot on the heels of catching this cyber gang but the closer we get the more damage they try to inflict onto the Barcelona tourism industry! This time, they've hacked into a large international bank's mobile application. Customers of the bank are complaining they can't see their current balance. Intern, help customers retrieve their balances so they can continue to spend their money during their well-earned holidays!  
  
view Source for Balances, Transactions, Payments  
change display: none to display: inline-block  
Shows - unable to retrieve balances  
  
view Console  
POSTs for get balances throws 404 Not Found error  
  
view Debugger  
function displayBalancePage  
‘error’ , ‘block'  
  
view Network  
notice get-balances requests throw 404's  
right click get-balances 404  
remove get-balances from url and resend.  
notice links at bottom of response  
get-accounts instead of get-balances  
right click another get-balances 404  
replace get-balances with get-accounts and resend  
view response - flag postD4ta_w1zard  
  
C04 wh1te_Ro$E  
The main tourism website for Barcelona has been hacked. They've devised a program that changes the content of the website based on a timer. You can imagine the confusion this has been causing the sites visitors! Can you figure out how we can get the secret code to stop this program from running?  
**Tip:** The characters at the 5 URLs change quickly, but computers can be far quicker than humans, especially when getting data!  
Hint: With a little code you could probably get the contents from those 5 URLs as strings and join them together. I wonder what you need to do with the validation URL?  
  
[[[https]]://pastebin.com/raw/pq5gJbYg]([[https]]://pastebin.com/raw/pq5gJbYg)  
var base_url = "[[https]]://roambarcelona.com" var verify = "verify=Na2Q%2BeqhSP5hTRLDwpTNoA%3D%3D" var p1 = await fetch(`${base_url}/clock-pt1?${verify}`).then(response => response.text()); var p2 = await fetch(`${base_url}/clock-pt2?${verify}`).then(response => response.text()); var p3 = await fetch(`${base_url}/clock-pt3?${verify}`).then(response => response.text()); var p4 = await fetch(`${base_url}/clock-pt4?${verify}`).then(response => response.text()); var p5 = await fetch(`${base_url}/clock-pt5?${verify}`).then(response => response.text()); var answer = p1+p2+p3+p4+p5; var flag = await fetch(`${base_url}/get-flag?${verify}&string=${answer}`).then(response => response.text()); console.log(flag);  
  
paste script into console on validation console.