Packages and Software Repos  
  
$ /etc/apt  
#installed packages live here  
  
$ add-apt-repository  
#command used to add community repositories  
  
$ wget -O- [https://download.sublimetext.com/sublimehq-pub.gpg](https://download.sublimetext.com/sublimehq-pub.gpg) | gpg --dearmor | sudo tee /usr/share/keyrings/sublime-archive-keyring.gpg