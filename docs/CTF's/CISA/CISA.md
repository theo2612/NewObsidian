[[https]]://icsjwgctf.com
RevShells
43bF8AwRwEfDKef

## Security Foundations
### Digital Certificates and Keys - 1
*What is the Common name (CN) of the issuer of the SSL cert for [[https]]://cisa.gov ?*
below CN = DigiCert Global Root CA

```bash
openssl s_client -connect [www.cisa.gov](https://www.cisa.gov/):443 -showcerts

CONNECTED(00000003)
depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
verify return:1
depth=1 C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
verify return:1
depth=0 C = US, ST = District of Columbia, L = Washington, O = Department of Homeland Security, CN = www3.dhs.gov
verify return:1
```
flag: DigiCert Global Root CA

### Digital Certificates and Keys - 2
*What is the sha1 hash of the executable whose digital signature contains the CN (Common Name) "VMware, Inc"?*
* Download the 10 files from Security Practices Challenge
* view properties of each and look for "VMware, Inc"
* file2 
* Upload file2 to VirusTotal for hash
	* 011b0bc97b5f4d732279e41ee05920dad1273c2927e64d3118ca051e15292549
* save in linux /tmp - bottom left of file explorer
* run hash through sha1sum
```bash
sha1sum file2
7a5c643bd504cebb9949eb714cebb302c833225c  file2
```
flag: 7a5c643bd504cebb9949eb714cebb302c833225c

### Digital Certificates & Keys - 3
*What is the name of the file that was **not** signed with one of these 4 certificates from the vendor?**
* download firmware updates and certificate
* save in linux /tmp - bottom left of file explorer
* use gpg linux sign tool to inspect Certificates and firmware updates
* Certificates 
```bash
gpg --import development.gpg.asc
gpg: /home/theo/.gnupg/trustdb.gpg: trustdb created
gpg: key 589A19D9B57C52A6: public key "Ever Grande Materials Development <development@evergrandematerials.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1

gpg --verify firmware_update_qsrbk.asc
gpg: Signature made Mon 10 Jan 2022 08:12:29 PM EST
gpg:                using RSA key 2B77E14CFA9FA3811EB9F3B3589A19D9B57C52A6
gpg:                issuer "development@evergrandematerials.com"
gpg: Can\'t check signature: No public key

gpg --verify firmware_update_tkhhl.asc
gpg: Signature made Mon 10 Jan 2022 08:12:25 PM EST
gpg:                using RSA key 5044842BA390B20C504B597CECC1D2294A2D86F9
gpg:                issuer "malicious@bad.com"
gpg: Can\'t check signature: No public key

```
flag: firmware_update_tkhhl.asc

### Digital Certificates & Keys - 4
*Using the public key for [security@evergrandematerials.com](mailto:security@evergrandematerials.com) from the previous challenge, please encrypt a small text file containing the phrase "Decrypt Me" and send it to our verification server.
The encrypted file can be sent to our verification server via an application such as netcat: `nc challenges.icsjwgctf.com 8010 < encrypted_file`
If our verification server is able to successfully decrypt our file and it contains the magic phrase, it will respond back with the flag for this challenge.*

create a text file named DecryptMe
```bash
nano DecryptMe

"Decrypt Me"
```
Encrypt text file with gpg using public key for security@evergrandematerials.com. 
```bash
gpg -e -R A2E18432686FF524 DecryptMe.txt
gpg: B24A3925A00802AF: There is no assurance this key belongs to the named user

sub  rsa3072/B24A3925A00802AF 2022-01-10 Ever Grande Materials <security@evergrandematerials.com>
 Primary key fingerprint: BA11 16A5 8288 EFA7 4319  AFB0 A2E1 8432 686F F524
      Subkey fingerprint: D464 0746 B083 A0A0 AA95  3A5C B24A 3925 A008 02AF

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
File 'DecryptMe.txt.gpg' exists. Overwrite? (y/N) y

nc challenges.icsjwgctf.com 8010 < DecryptMe.txt.gpg
Flag: public-klefki-private-klefki
```
flag: public-klefki-private-klefki

### Introduction to Malcolm - 1
*What is the cause of the exception for the Modbus read/write multiple registers function?
Hint: _Modbus Dashboard_*
Flag format: Exception. Example: **READ_WRITE_FAILED**
* Open Malcom
	* access Dashboard - Modbus
* Change timeframe to April 21st*
* Filter by function READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION
* Cause is right next to it GATEWAY_PATH_UNAVAILABLE
* flag: GATEWAY_PATH_UNAVAILABLE

### Introduction to Malcolm - 2
*What is the most common MITRE ATT&CK tactic detected by [capa](https://github.com/mandiant/capa) in executable files transferred in the network traffic?*
* Open Malcom
	* Access Dashboard - Signatures
* Change timeframe to April 21st*
* Filter by clicking on Capa Signature results in Engines
* view top Signature im Signature ID's
	* Discovery::File and Directory Discovery
flag: Discovery

### Introduction to Malcolm - 3
*What is the serial number of the Allen-Bradley 1766-L32BWAA Programmable Logic Controller (PLC)?*
Hint: Look under the ICS/IoT Protocols in Malcolm's Dashboards
 Open Malcom
	* Access Dashboard - ICS/IoT Security Overview
* Change timeframe to April 21st
* search in field "\*Allen-Bradley  1766-L32BWAA"
* scroll to the bottom in ICS/IoT Logs
* select any log
* under field -  *zeek.cip_identity.serial_number*0x40657763
flag:0x40657763

### Introduction to Malcolm - 4
*What is the user agent string used to download the Java class object in the Log4j exploit detected by Malcolm? Hint: _Notices Dashboard_*
* Open Malcolm
	* Access Dashboard - Notices
* Change timeframe to April 21st
* filter by Notice - Log4J_Java_class_Download
* select log 
	* zeek.notice.sub user_agent='Java/1.8.0_102', CONTENT-TYPE='application/java-vm', host='203.0.113.217:8000'*
flag: Java/1.8.0_102

### Introduction to Malcolm - 5
*What is the underlying MIME type of the transferred file(s) Malcolm detected as being XOR-obfuscated?*
Hint: _Files Dashboard_
* Open Malcolm
	* Access Dashboard - Notices
* Change time frame to April 21st
* search by XOR
* filter Files - Souce by XOR
* select log
	* file.mime_type - application/x-dosexec 
flag: application/x-dosexec

### Rustboro IT - IT Incident Response - 9
*You may be able to retrieve the private SSH key by looking at the data the IT RAT exfiltrated over DNS. Once you find the SSH key, you can use it to access the remote server.
Remote Server: \`rustboro_dev@challenges.icsjwgctf.com`  
Port: \`2022\`
Please figure out what sensitive information was stored on the server.*






















































