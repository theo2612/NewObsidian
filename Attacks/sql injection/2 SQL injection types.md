**In-Band (Classic)** 
- When Attacker uses the same communication channel to launch the attack and gather the results of the attack
- Retrieved data is presented directly in the app web page
	- *Error-based* -  
		- forces the database to generate an error, giving the attacker info to refine their injection
		- Ex. Input vvww.random.com/app.php?id='
		- Output - You have an error in you SQL syntax, check the manual that corresponds to your MySQL server version
			- from this we know- the app is using MySQL
	- *Union-based* -
		- 