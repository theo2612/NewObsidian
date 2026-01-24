ping 127.0.0.1 -n 30
net stop waptservice
"C:\Program Files (x86)\wapt\wapt-get.exe" update 
"C:\Program Files (x86)\wapt\wapt-get.exe" install base_software
net start waptservice