[[[SSH]] [[port forwarding]] on [[Linux]]]([[https]]://linuxhint.com/[[ssh]]-port-forwarding-[[linux]]/)

```powershell
ssh -L 8080:10.10.43.83:80 boost@192.168.0.50 -fN
```

The syntax is LOCAL_PORT:TARGET_IP:TARGET_PORT
What the [[SSH]] command is doing is: Make a connection to my local port 8080 to the ip machine on port 80 (where the web server is running). Your skilstak machine can see the ip because it's using the vpn. So now your host machine can see the THM machine's webserver on port 8080
-fN flags. f is for backgrounding the shell, N tells [[ssh]] that it doesn't need to run any command

