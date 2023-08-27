wget  
use to download files from web via HTTP  
provide wget the address of the resource  
$ wget [https://www.address.com/file](https://www.address.com/file)  
  
SCP SSH  
scp = secure copy  
unlike cp, scp transfers files between 2 computers using ssh protocol to provide authentication and encryption  
assuming SOURCE and DESTINATION, SCP allows  
copy files and directories  
from current system to remote system  
from remote system to current system  
  
scp  
scp ubuntu@192.168.1.30:/home/ubuntu/documents.txt notes.txt  
# user @ ip:file location new name on our system  
  
Serving files from your host  
Ubuntu comes pre-packaged with python3 that comes with a module called “HTTPServer"  
this module turns you computer into a quick webserver that you can use to serve files.  
they can then be downloaded by another machine using curl and wget  
$ python3 -m http.server  
#starts the module  
  
$ wget [http://127.0.0.1:8000/file](http://127.0.0.1:8000/file)  
#retrieves file from 127.0.0.1  
  
$ curl -vv [http://securitylive.com](http://securitylive.com)  
#retrives request and response headers and cipher headers with full verbosity.  
  
-d  
#sends the request as a post  
  
-H  
#send additional headers: -H =Host