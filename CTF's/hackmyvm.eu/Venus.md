```html
Host: venus.hackmyvm.eu
Port: 5000
User: hacker
Pass: havefun!
```

# MISSION 0x01#
User sophia has saved her password in a hidden file in this folder. Find it and log in as sophia. 
```bash
ls -aslp
cat 
```
Y1o645M3mR84ejc

# MISSION 0x02 #
The user angela has saved her password in a file but she does not remember where ... she only remembers that the file was called whereismypazz.txt
```bash
find / -name whereismypazz.txt
```
oh5p9gAABugHBje

# MISSION 0x03 #
The password of the user emma is in line 4069 of the file findme.txt
```bash
cat -n findme.txt | grep 4069
```
fIvltaGaq0OUH8O

# MISSION 0x04 #
User mia has left her password in the file -.
```bash
cat ./-
```
iKXIYg0pyEH2Hos

# MISSION 0x05 #
It seems that the user camila has left her password inside a folder called hereiam
```bash
find / -type d -name hereiam 2>/dev/null
```
F67aDmCAAgOOaOc

# MISSION 0x06 #
The user luna has left her password in a file inside the muack folder.
```bash
find . -type f 2>/dev/null
```
j3vkuoKQwvbhkMc

# MISSION 0x07 #
The user eleanor has left her password in a file that occupies 6969 bytes.
```bash
find / -type f -size 6969c 2>/dev/null
```
UNDchvln6Bmtu7b

# MISSION 0x08 #
The user victoria has left her password in a file in which the owner is the user violin.
```bash
find / -user violin 2>/dev/null
```
pz8OqvJBFxH0cSj

# MISSION 0x09 #
The user isla has left her password in a zip file.
```bash
unzip -p passw0rd.zip
```
D3XTob0FUImsoBb

# MISSION 0x10 #
The password of the user violet is in the line that begins with a9HFX (these 5 characters are not part of her password.).
```bash
cat passy | grep "^a9HFX"
```
WKINVzNQLKLDVAc








