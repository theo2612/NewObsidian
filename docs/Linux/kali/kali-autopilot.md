From Kali Linux & Friends Discord

---
Hey @everyone! We have just went live with our 2023.3 release! Some key mentions here include updates to our internal infrastructure and Kali Autopilot. To find out the full list of changes, visit the blog post! <https://www.kali.org/blog/kali-linux-2023-3-release/>

As is tradition now with new releases, we will be having a Discord voice chat to discuss the newest release and answer any questions you all might have. This call will happen on <t:1693411200:f> or <t:1693411200:R>. Click the link below to stay informed when it happens! 
https://discord.com/events/838895421291102289/1143926391423901747
---

Update and upgrade instructions - 
From [kali website - updating Kali](https://www.kali.org/docs/general-use/updating-kali/)
- To update Kali, first ensure that `/etc/apt/sources.list` is properly populated:
```bash
kali@kali:~$ cat /etc/apt/sources.list
# See https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/
deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware

# Additional line for source packages
# deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
kali@kali:~$
```
- After that we can run the following commands which will [upgrade us to the latest Kali version](https://www.kali.org/docs/general-use/updating-kali/):
```bash
kali@kali:~$ sudo apt update
kali@kali:~$
kali@kali:~$ sudo apt full-upgrade -y
kali@kali:~$
```

I did not get Kali-Autopilot in my update and upgrade so I searched for it and found a manual install instructions on [Kali website](https://www.kali.org/tools/kali-autopilot/)
```bash
kali@kali:~$ sudo apt install kali-autopilot

kali@kali:~$ kali-autpilot
```


