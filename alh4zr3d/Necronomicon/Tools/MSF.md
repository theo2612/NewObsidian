- Metasploit
	- Banners
		- MLP
			- `export APRILFOOLSPONIES=1 && msfconsole`
		- Cow
			- `export GOCOW=1 && msfconsole`
		- Halloween
			- `export THISISHALLOWEEN=1 && msfconsole`
		- Open banners without env variable
			- `APRILFOOLSPONIES=true msfconsole`
			- `THISISHALLOWEEN=true msfconsole`
			- `GOCOW=true msfconsole`
- Port Forwarding
	```BASH
	(in established Meterpreter session) background
	use post/multi/manage/autoroute
	set SESSION 1
	set SUBNET 10.200.x.0
	run
	use auxiliary/server/socks4a
	run
	configure proxychains4 (change proxy type and port)
	proxychains4 <command>
	```