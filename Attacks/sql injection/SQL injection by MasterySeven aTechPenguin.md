# SQL injection step by step guide
A SQL injection vulnerability is a vulnerability that arises due to improper sensitization of data inserted into a SQL query resulting in a change in the query. This vulnerability can lead to manipulation/deletion / exposing of data from the database, you can think of things such as usernames and password.

A simple step by step plan for finding / exploiting SQL injections looks like:
- [[#Fuzz / Find SQL injections]]
- [[#Verify it's a SQL injection]]
- [[#Find out what database is used by using db specific syntax]]
- [[#Try to add a select query by either using a union or a sub query]]
- [[#Retrieving data from the query]]
- [[#Read out the tables that exist]]
- [[#Read out the columns]]
- [[#profit]]

in this document we will try to clarify the steps above, and make it so that anyone can exploit a simple SQL injection, if you have trouble understanding SQL injection you might want to take a look at how SQL works before attempting to understand how to exploit it.
- this document is used as additional information for the portswigger labs, we do recommend reading all the text provided by the lab, and use this document in combination with the provided text to solve every lab.

### Step 1
## Fuzz / Find SQL injections

A SQL Injection vulnerability arises due to improper or lack of sanitation of input, the characters that traditionally should be sanitized are `'`  `"`  `\` `\x00` `\r` `\n` `\x1a`. 
So sending any of these characters might break the SQL statement and result in either an error page, or a difference in response indicating that there might be a SQL injection. some pages however don't change upon receiving an error in the query for these we need to fuzz with payloads that cause an observable change such as a sleep or a DNS request.
For all beginner exercises we will only fuzz with the `'` character, but it's good to keep in mind there are other characters that can break the query.

## Step 2
# Verify it's a SQL injection

After finding what you think is a SQL vulnerability you can verify it's a SQL injection by fixing the query (breaking them wit the character and making them valid again), as a beginner there  are 2 main ways to do this: 1 commenting out the rest of the query and 2 concatenating an empty value. note that commenting out the query deletes everything in the query after the input ends and can completely change the query, concatenation tries to not change the query and works by "fixing" the syntax take the following query:

```SQL
SELECT * from users WHERE input='input' order by 1
```
imagine replacing the input with the escape character `'` followed by a comment `-- -`
resulting in the following query:
```SQL
SELECT * from users WHERE input=''-- -' order by 1
```
Notice that the order by part is removed from the query
whilst when "fixing" the query with an append `||`  followed by the escape character `'` it would look like this:
```SQL
SELECT * from users WHERE input=''||'' order by 1
```
and the SQL after the input is still executed.

#### some additional notes
- there are different characters used for comments and append based on the targeted database.
	- `||` is used in PostgreSQL for appending
	- `+` is used by MSSQL
	- ` ` is used by MYSQL
	some of these are used by multiple types of databases, try to find the one that works for you, a good cheat-sheet db specify syntax can be found at  https://portswigger.net/web-security/sql-injection/cheat-sheet
- remember that you send your requests trough burp and things like HTML encoding can apply before being passed to the database so a `+` character can be transformed to a space

### STEP 3
## Find out what database is used by using db specific syntax
After you got a working query with an injection you want to start figuring out what database is used, you might already have an idea on what is used due to the previous step, but in case you don't you can further fingerprint the type of database by using database specific syntax. You can lookup what syntax is supported by what database in the docs, the cheat-sheet provided for the labs by portswigger also contains all information you need.
https://portswigger.net/web-security/sql-injection/cheat-sheet
https://book.hacktricks.xyz/pentesting-web/sql-injection#identifying-back-end

### STEP 4
## Try to add a select query by either using a union or a sub query
For the next step you are going to insert a additional select query in the resulting query, this can generally be done in 1 of 2 ways: 1 by using the `UNION` statement you can unify the results of a query with multiple queries, 2 by using a sub-query. the goal of the query should be to select a static value such as `1` or `'a'`, the advantage of a `UNION` query is that they are fairly straightforward to execute, unfortunately though this is not always possible. And an advantage of the sub-query is they are more versatile and don't require some additional steps the `UNION` one needs. 

#### UNION
An `UNION` based query requires more information in order to get it working since you combine the 2 queries they need to return the same amount of columns, and the columns should be of the same type , you can figure out how many columns are returned either using the `order by` statement or try to select the exact amount of columns returned.
an `order by` statement will crash once you provide a number higher than the total columns the original query returns, whilst an `SELECT null,null ...` will crash as long as the number of columns isn't the exact same.

After verifying how many fields it returns you will need to identify the type data a column can contain by trying a number (`1` or a character `'a'`) 
and now you have a working query injected that can return simple static data

#### Sub queries 
a sub query is often confusing to beginners since it can't be used everywhere in the context of a SQL statement, we will explain sub queries in a `WHERE`  clause but not it can be done in multiple ways, consult the docs for the specific language to find out where and how to use sub-queries.
now imagine a simple query, like this 

```SQL
SELECT * from users WHERE input='data' order by 1
```
after going trough the previous steps our last injection looks like
`' || '`
or 
`'-- -`
we might be able to transform the query by injecting `input' AND 1=(SELECT 1) -- -` to something like this 

```SQL
SELECT * from users WHERE input='input' AND 1=(SELECT 1) -- - order by 1
```
here we introduced a simple sub query which is used in a `WHERE` statement, and since 1=1 returns true the query works the same as:

```SQL
SELECT * from users WHERE input='input'
```

now you got a sub-query working

### Step 5
## Retrieving data from the query
Most of the time the most difficult thing to do for beginners is to retrieve data back from the query and it's vital to carefully craft your attack in order to do this, if you think you are at this step and can't seem to continue make sure all previous steps worked before continuing 
now in order to retrieve data we need to be able to create a discrepancy in the response, this is normally done in the wild by using the same discrepancy you used in identifying the SQL injection during step 1, unfortunately for the portswigger labs you normally skip the fuzzing part(step 1) and now you need to find a way to retrieve data, we can split this step in 2 for the portswigger labs.
#### Get a different response
the first of the 2 sub steps is get a different in response, this can be directly returning the results of a query, in which case you can go to the next step, causing a delay in the SQL server response (sleep) and observing it, causing an error page, returning a different status code or causing an DNS or some other out of band request to be made to your server, please consult the cheat-sheet on how to do this since there are many different ways to do so.

#### Example
the next step is to make the application return a different response based on the output of a simple query, we will use a conditional error in our example: so lets take our last injection:
```SQL
SELECT * from users WHERE input='input' AND 1=(SELECT 1) -- - order by 1
```
we have the query, now lets say this is a postgress database, we will use the conditional error from the cheat-sheet
`1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`
this is basically a sub query with an if statement inserted into it, resulting injection will look like:
`input' AND 1=(SELECT CASE WHEN (1=1) THEN 1/(SELECT 0) ELSE NULL END) -- - `
from 
`input' AND 1=(SELECT 1) -- -`

this will give an error when the condition (`1=1` in example) returns is true 
#### Return a character
Now that we have a difference in response based on a simple condition we can try to retrieve a single character:

lets try this out with a simple select query first so replace the `1=1` with a simple sub query:
`1=(SELECT 1)`
now if this select query returns 1 it will evaluate to true otherwise it will evaluate to false, lets change this from the number 1 to a character `'a'` so we will get `'a'=(select 'a')`
since a query normally returns more than 1 character lets make it return a simple string such as testabc like such `'a'=(select 'testabc')` , the problem here is that we only know what it contains if we can guess the exact output in the `'a' 

since this is inefficient we can limit the amount of guesses we need to do to a single character, we can do this by using the `SUBSTRING` function,this function can return a part of a string, based on the index and  of the firs character, the character have an equivalent one based on the database, once again look at the cheat-sheet in order to find out the correct syntax/function.
since this might all seem very confusing it is best shown by some examples
`'a' =(SUBSTRING('admin',1,1))` evaluates to TRUE since the first character of admin is `a`
`'a' =(SUBSTRING('admin',1,2))` evaluates to FALSE since the first 2 characters of admin are `ad`
`'d' =(SUBSTRING('admin',2,1))` evaluates to TRUE since the second character of admin is `d`
as you can see we can brute-force a string now character by character
so all that's left to do is change the string to a sub-query as such
`'a' =(SUBSTRING((SELECT 'admin'),1,1))`
now we can read data from our custom query (`SELECT 'admin'`) 1 character at a time
all that's left to do now is reading the data we want
full payload example
`input' AND 1=(SELECT CASE WHEN ('a' =(SUBSTRING((SELECT 'admin'),1,1))) THEN 1/(SELECT 0) ELSE NULL END) -- - `

##### note
the sub-query can only return 1 result at a time
### Step 6
## Read out the tables that exist
Since you can now read data from the database to find the data we want we start with looking at what tables exist:
and since database normally contains a table that describes all the tables that exist, we can read out the tables the database contains, by selecting all table_names
```SQL
SELECT table_name FROM information_schema.tables
```
the specific query needed to return all table names that exist may differ based on the type of database you target, consult the cheat-sheet in order to find the correct syntax

### step 7
### Read out the columns
After you chose a table to read from it's time to find out what columns this table contains, you can do this with a query like this
```SQL
	SELECT column_name FROM information_schema.columns WHERE table_name = 'test'
```
for specific syntax look at the cheat-sheet

### step 8
## profit
you should now have all information needed to read out any data you want from the database.