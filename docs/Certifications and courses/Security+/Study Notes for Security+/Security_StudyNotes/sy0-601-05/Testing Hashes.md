downloaded [[burp]] community from [[https]]://portswigger.net/[[burp]]/releases/professional-community-2023-10-3-7
![[Pasted image 20231207103505.png]]
- in [[windows]] - go to your downloads
	- right click in the window where the downloaded file is
	- select open cmd terminal in that folder
	- run certutil
	```bash
	C:\Users\Owner\Downloads>certutil -hashfile burpsuite_community_windows-x64_v2023_10_3_7.exe SHA256
	SHA256 hash of burpsuite_community_windows-x64_v2023_10_3_7.exe:
	df34a0a1dc7d689577aa3850add0e47417d0bada6586c484446c5fa615a53111
	CertUtil: -hashfile command completed successfully.
	```
	- compare the hash from the provider and the hash that generated from cmd line
	- if they match the file provided matches what you downloaded
- Also, see below 
	- I tested the wrong version and they didn't match
	- I tested the correct version and didn't include the specific HASH
	- I tested the correct version and included the specific HASH 
	```bash
C:\Users\Owner\Downloads>certutil -hashfile burpsuite_community_windows-x64_v2023_9_4.exe SHA256
SHA256 hash of burpsuite_community_windows-x64_v2023_9_4.exe:
f5fad71eb8603dac3f3a00c293a50bba39079df3ee08f273d4b9cdcf64f6d83b
CertUtil: -hashfile command completed successfully.

C:\Users\Owner\Downloads>certutil -hashfile burpsuite_community_windows-x64_v2023_10_3_7.exe
SHA1 hash of burpsuite_community_windows-x64_v2023_10_3_7.exe:
e184088a2933e71c4a58cbb9eb235050c04aa79c
CertUtil: -hashfile command completed successfully.

C:\Users\Owner\Downloads>certutil -hashfile burpsuite_community_windows-x64_v2023_10_3_7.exe SHA256
SHA256 hash of burpsuite_community_windows-x64_v2023_10_3_7.exe:
df34a0a1dc7d689577aa3850add0e47417d0bada6586c484446c5fa615a53111
CertUtil: -hashfile command completed successfully.
```