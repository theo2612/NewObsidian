# Command line upgrade
[ohmyposh]([[https]]://ohmyposh.dev/docs/installation/[[linux]])

# Hacking tools
- [[nmap]], [[john]], aircrack-ng, [[hydra]], [[sqlmap]], [[nikto]]
```bash
sudo apt update && sudo apt install nmap john aircrack-ng hydra sqlmap nikto
```
- Metasploit - [Getting Started](https://www.metasploit.com/get-started)
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

# Boot image
place under the first line of the .bashrc file
```bash
# ~/.bashrc: executed by bash(1) for non-login shells.

echo ""
echo "                   ...++++++++..."
echo "                ######+++++++++++++."
echo "              ##++++++##++###########"
echo "            ##++++++++++##+++++++++++##"
echo "           ##+++++++++++##++++++++++++##"
echo "          ##++++++++++++##+++++++++++++##"
echo "         ##++++++++++++##+++++++++++++++##"
echo "       +##+++++++++++###+++++++++++++++++====."
echo "      .##+++++++++++##+##+++++++++++          \\"
echo "     .+##++++++++++##+++##++++++               #"
echo "     .+##+++++++++##+++++##+           ..+###-##"
echo "     ++########++##++++++          .+##########"
echo "    #-+##+++++## ##++           .+###.#==#..###"
echo "   . ##++++++++###            .+###..#    #.-##"
echo "  ##                    .+++++##--.---#==#--#"
echo "   ###+-..... .   ..-#####+#.-###----------#"
echo "    ##################++.##-----###-------#"
echo "      #++++##---++##.----##----+-###----#"
echo "         #++##-----##-----##--.----###-"
echo "            +##-----##------##----#"
echo "              ###----##------##+"
echo ""
```

