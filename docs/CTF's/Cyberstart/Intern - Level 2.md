CO1 QQEvoQNYr8MDO3fhyZfz  
copy hex from flag on login screen x74\x68\x65\x20\x36\x31\x30\x65\x6e\x43\x30\x64\x65\x20\x73\x65\x72\x76\x65\x72\x2e\x20\x54\x68\x65\x20\x73\x65\x72\x76\x65\x72\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x69\x73\x20\x34\x66\x31\x62\x32\x35\x32\x30\x35\x35\x20\x2d\x20\x67\x72\x65\x61\x74\x20\x64\x65\x63\x6f\x64\  
cyberchef - from hex recipe - the 610enC0de server. The server password is 4f1b252055 - great decod  
login to server for the flag  
  
CO2 6oYNd8BExVv4DZnZSSPO  
Hint - Take a look in the source code to get a better idea of how the lock works. Maybe we can try running some of the functions with our own input...  
F12 -  
// Remind users of the number of degrees to use to unlock  
console.log("Set new degrees to unlock all circles between -81 and -4");  
var turnCircle = function(num, deg) {  
Console> turnCircle("one", -81)  
Console> turnCircle("two", -40)  
Console> turnCircle("three", -4)  
  
CO3 YjVQ6KFBVCzwtW3e2iLD  
right click on Forum, Inspect element - Takes us directly to it  
data-sd='my-chat'  
Cycling maps link = [http://my-routes/trafficdisruptors.com/312324494](http://my-routes/trafficdisruptors.com/312324494)  
change to [http://my-chat/trafficdisruptors.com/312324494](http://my-chat/trafficdisruptors.com/312324494)  
  
CO4 eWGG6k3OWzpHg9aR3Ewl  
F12 or right click on email address field, inspect element  
script with function -- doLogin contains if (submittedEmail !== email) || submittedPassword !== password) which can be assumed that the email and password must be hidden in code in order to compare.  
On Console tab use console.log(email) and console.log(password) to have the Web Development tools give them to you.
