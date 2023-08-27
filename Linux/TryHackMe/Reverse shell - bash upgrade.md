"stabilize your shell" for easier ability in typing commands, you can use the usual upgrade trick (assuming you are running in a **`bash`** shell. If you are running within **`zsh`**, you will need to have started your **`netcat`** listener within a **`bash`** subshell... it should be easy enough to re-exploit):  
  
  
(on the reverse shell) **`python3 -c "import pty; pty.spawn('/bin/bash')"`**  
(press on your keyboard) **`Ctrl+Z`**  
(press on your keyboard) **`Enter`**  
(on your local host) **`stty raw -echo`**  
(on your local host) **`fg`** (you will not see your keystrokes -- trust yourself and hit **`Enter`**)  
(press on your keyboard) **`Enter`**  
(press on your keyboard) **`Enter`**  
(on the reverse shell) **`export TERM=xterm`**