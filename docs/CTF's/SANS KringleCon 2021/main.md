exiftool  
exiftool extracts metadata info from files  
$ exiftool . | grep “Jack Frost”  
yields a result but not specifically where  
$ exiftool .  
and scrolled for Jack Frost  
found in ./2021-12.21.docx  
  
Caramel Santiago  
just flipped through each city  
read the clues and updated to the database  
at the end caramel Santaigo was the elf  
  
Grepping for gold  
- What port does 34.76.1.22 have open? 62078  
- What port does 34.77.207.226 have open? 8080  
$ cat bigscan.gnmap | grep <stuff I want to find>  
$ grep 34.76.1.22 bigscan.gnmap  
This looks for "34.76.1.22" in the bigscan.gnmap file and shows us every place where it shows up. In the results, we see:  
62078/open/tcp//iphone-sync///  
This tells us port TCP 62078 was found open by [[nmap]].  
$ grep 34.77.207.226 bigscan.gnmap  
Like the previous challenge, this searches the [[nmap]] output file for a specific IP address. In the output, we see TCP port 8080 is open:  
8080/open/tcp//[[http]]-proxy///  
  
- How many hosts appear "Up" in the scan? 26054  
$ sort bigscan.gnmap | grep "Status: Up" -c  
$ cat bigscan.gnmap | grep "Status: Up" -c  
$ grep Up bigscan.gnmap | wc -l  
Running the grep part of the command returns every line with "Up" in it, and wc counts the bytes, characters, words, and lines that come out of grep. Using "-l" only shows lines.  
  
- How many hosts have a web port open? (Let's just use TCP ports 80, 443, and 8080) 14372  
$ grep -E "(80|443|8080)/open" bigscan.gnmap | wc -l  
Using "-E" tells grep we"re giving it a regular expression (regex). In this case, that regex says, "I want lines that have 8080/open, 443/open, or 80/open."  
If you want to be MORE correct, you might use "(\s8080|\s443|\s80)/open" to ensure you don't snag ports like 50080, but there weren't any in this file.  
  
- How many hosts with status Up have no (detected) open TCP ports? 402  
$ grep -E "(Status: Up)" -c bigscan.gnmap  
26054  
$ grep -E "(open)" -c bigscan.gnmap  
25652  
echo $((`grep Up bigscan.gnmap | wc -l` - `grep Ports bigscan.gnmap | wc -l`))  
Our solution is a little fancy, but the crux is this: use one grep|wc command to count how many hosts are "Up", and use another to count how many have "Ports" open.  
  
- What's the greatest number of TCP ports any one host has open?