* `man` - show manual information about a command
* `sudo` - do it as root (superuser)
* `apt` - use interactively only (use `apt-get` in scripts)
* `sudo apt update` - update all the sources for packages
* `sudo apt upgrade` - upgrade *all* packages to latest version
* `apt search ^neo` - search for all package starting with `neo`
* `sudo apt install neofetch` - install `neofetch` and dependencies
* `sudo apt remove neofetch` - remove `neofetch`
* `sudo apt autoremove` - automatically remove unused packages
* `ls` - list the files in the (current) directory
* `ls -al` - list all the files including hidden (begin with `.`)
* `hostname` - display name of host computer
* `pwd` - print working directory
* `cd foo` - change into the `foo` directory
* `cd`, `cd ~` - change back to the home directory
* `cd ..` - change into the relative parent directory
* `cd ../..` - change into the relative parent of the parent directory
* `cd -` - change to previous directory
* `cd /` change to the root directory

* `ip a` - show all IP addresses (`ipconfig /all`, on [[Windows]])
* `clear` - clears the screen
* `which ssh` - display full path to [[ssh]] program
* `type ssh` - display what type of thing it is
* `who` - display who is logged in an how
* `id` - display user and group names and ids for self
* `w` - display logger version of who is logged in
* `whoami` - print effective user name/ID
* `users` - short name of all logged in users
* `last` - summary of last logged in users
* `exit` - exit the current program or login or shell
* `| less` or `| more` - see scrolled output in terminal (`q` to quit)
* `<Ctrl>-c` - interrupt whatever (exit)
* `<Ctrl>-d` - send "end of data/file"
* `sudo apt install openssh-server` - install [[ssh]] server (if not)
* `vboxmanage startvm <VMNAME> --type headless` - start vm headless
* `vboxmanage list runningvms` - list running vms
* `vboxmanage list vms` - list all vms
* `vboxmanage controlvm <VMNAME> poweroff` - power off headless vm
* `vim` - basic vim [[https]]://rwx.gg/visurvive
* `nano` - just so you understand nano editor is a thing

* `ip -c a` - lookup IP addresses
* `set -o noclobber` - stop from blowing away files
* `mv foo other` - change file/directory `foo` name to `other` (or move)
* `mv -i foo other` - change file name but protect against overwrites
* `cp foo other` - copy file/directory `foo` name to `other` (or move)
* `cp -ar foo other` - copy all `foo` to `other` keeping timestamp
* `scp foo target:` - copy foo from host to remote target home dir (def)
* `ls -ld` (or with `.`) - look directory permission on current directory
* `stat foo` - see all the details about the `foo` inode
* `chmod +x foo` - make foo file executable by user, group, other
* `chmod o-r foo` - make foo unreadable by other
* `chown rando foo` - change ownership of `foo` to `rando`
* `chown -R jill:jill olddir` - recursively change ownership/group
* `sudo su -` - effectively login as root without logging out
* `sudo su - foo` effectively login as `foo`
* `stat -c '%a'` - to see octal permissions
* `cd -` - change into previous directory
* `echo foo` - write foo to standard output
* `cat foo` - write content of foo file to standard output
* `which foo` - print the full file path to the executable foo
* `ls -l $(which sudo)` - list perms for `sudo` command
* `sudo adduser foo` - interactively add a user named `foo` (not RedHat)
* `sudo deluser foo` - interactively delete a user named `foo` (not RedHat)
* `sudo passwd foo` - change the password for `foo`
* `passwd` - change own password
* `touch` - create new text file or update last modified time stat
* `rmdir foo` - remove an *empty* `foo` directory
* `rm -rf foo ` - remove directory or file foo and everything in it
* `grep jill /etc/passwd` - list only line containing `jill`
* `file foo` - tell type of inode

* `find . ` - sort of the same as `ls -l1`
* `find . -ls` - sort of the same as `ls -l1`
* `find . -name '???'` - find files/dirs with three letter name
* `find . -path '.git'` - find files/dirs with `.git` anywhere in path
* `head -5 foo` - show top five lines of `foo` file
* `tail -5 foo` - show bottom five lines of `foo` file
* `tac foo` - reverse lines of `foo` file
* `wc -l` - print count of lines
* `nl` - add line numbers to output
* `tee /tmp/foo` - both writes to a file `foo` and to stdout
* `>` - (over) write to file
* `>>` - append to file
* `|` - connect stdout to stdin
* `<` - send file to stdin
* `lolcat` - colorize things
* `cowsay` - fun way to show output

- `ssh-keygen -f key -N ''` - generates a 'key' and 'key.pub' for [[ssh]] connections. key.pub is supplied to what you want to connect to. Then connect to remote system over [[ssh]] with `ssh -i key username@ip.ip.ip.ip`
