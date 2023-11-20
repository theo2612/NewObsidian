Practitioner - SQL injection

## How to detect SQL injection vulnerabilities
Detect SQL injection manually by using a systematic set of tests against every entry point in the application. 
To do this, you would typically submit
- Use single quote to detect errors and other anomalies
`'`
- Use SQL-specific syntax that evaluates to the base/original value of the entry point, and to a different value, and look for systematic differences in the application responses
- Use Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the applications responses
- Use payloads to design to trigger an out-of-band network interaction when executed within a SQL query and monitor any resulting interaction

## SQL injection in different parts of the query
- Most SQL injection vulnerabilities occur within the `WHERE` clause of a `SELECT` query
- SQL injection vulnerabilities can occur at any location within the query
	- `UPDATE` statements, within the updated values or the `WHERE` clause
	- `INSERT` statements, within the inserted values
	-  `SELECT` statements, within the table of column name
	- `SELECT` statements, within the `ORDER BY` clause

## Retrieving hidden data
- Imagine a shopping web app that displays products in categories
- When the user clicks on the Gifts category, their browser requests the following URL
```html
https://insecure-website.com/products?category=Gifts
```
- The application makes a SQL query to retrieve product details from the datebase
```SQL
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
- This SQL query asks the database to return:
	- all details
	- from the `product` table
	- where the `category` is `Gifts`
	- and `released` is `1`
- The restriction `released = 1` is being used to hide unreleased products. 
- We could assume for unreleased products, `released = 0`

-The application doesn't implement any defenses against SQL injection attacks. so the following attack can be constructed
```html
https://insecure-website.com/products?category=Gifts'--
```
- results in this SQL query
```SQL
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
- Crucially, note that `--` is a comment indicator in SQL
- The rest of the query is interpreted as a comment, effectively removing it
- In this example the query no longer includes `AND released = 1`
- Resulting in all products being displayed, including those not yet released

- A similar attack to cause the application to display all the products in any category, including categories that they don't know about.
```html
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```
- This results in the SQL query
```SQL
`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`
```
- The modified query returns all the items where either the `category` is `Gifts` or 1 is equal to 1
## Warning
Take care when injecting the condition `OR 1=1` into a SQL query. Even if it appears to be harmless in the context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an `UPDATE` or `DELETE` statement, for example, it can result in an accidental loss of data.

## Subverting application logic
- On a Web page or WebApp that lets users log in with a username and password
- If a user submits the username `weiner` and the password `bluecheese`, the application checks the credentials by performing the following SQL query
```SQL
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```
- If the query returns the details of a user, then the login is successful, otherwise it is rejected.
- In this case, and attacker can log in as any user without the need for a password
- Can be done using the SQL comment sequence `--` to remove the password check from the `WHERE` clause of the query.
- For example, submitting the username `adminstrator'--` and a blank password results in the following query
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
- This query returns the user whose 'username' is  `administrator` and successfully logs the attacker in as that user

## SQL injection UNION attacks
- When an application is vulnerable to SQL injection, and the results of the query are returned within the applications responses, you can use the `UNION`  keyword to retrieve data from other tables within the database.
- The `UNION` keyword enables you to execute one or more additional `SELECT` queries and append the results to the original query. for example
```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
- This SQL query returns a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and  `d` in `table2`

- For a `UNION` query to work, two key requirements must be met
	- The individual queries must return the same number of columns 
	- The data types in each column must be compatible between individual queries
- To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. involves discovering 
	- How many columns are being returned  from the original query
	- Which columns returned from the original query are of a suitable data type to hold the results from the injected query
## Determining the number of columns required
- When performing a SQL injection UNION attack, here are 2 effective methods to determine how many columns are being returned the original query

- **Method 1**
	- injecting a series of `ORDER BY` clauses
	- incrementing the specified column index until an error occurs
	- ex. if the injection point is a quoted string whithin the `WHERE` clause of the original query, you would submit
```SQL
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```
- This series of payloads modifies the original query to order the results by different columns in the result set.
- The column in an `ORDER BY` clause can be specified by its index, so you don't need to know the names of the columns
- When the specified column index exceeds the number of actual columns in the result set, the database returns an error, like
`The ORDER BY position number 3 is out of range of the number of items in the select list`
- The application might return the database error in it's HTTP response, but it may also issue a generic error response
- It may simply return no results at all
- As long as you can detect some difference in the response, you can infer how many columns are being returned from the query

 - **Method 2**
	- Involves submitting a series of `UNION SELECT` payloads specifying a different number of null values
```SQL
'UNION+SELECT+NULL--
'UNION+SELECT+NULL,NULL--
'UNION+SELECT+NULL,NULL,NULL--
```
- If the number of nulls does not match the number of columns, the database returns and error, like
`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
- `NULL` is used as the values returned from the injected `SELECT` query because the data types in each column must be compatible between the original and the injected queries
- `NULL` is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct
- Like with the `ORDER BY` technique, the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results.
- When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column.
- The effect on the HTTP response depends on the applications's code. 
- If you are lucky, you will see som additional content within the response, like and extra rows on a HTML table. Otherwise , tne nuyll values might trigger a different error, like NullPointerException
- Worst case, the response might look the same as a response caused by an incorrect number of nulls. This would make this method ineffective
- **Database-specific**
	- On Oracle, every `SELECT` query must use the `FROM` keyword and specify a valid table. 
	- There is a built-in table on Oracle called dual which can be used for this purpose. Injected queries would need to look like the following
	- `'UNION SELECT NULL FROM DUAL--`
	- The payloads described use the double-dash comment sequence `--` to comment out the remainder of the original query following the injection point
	- On MySQL the double-dash sequence must be followed by a space. Alternatively, the hash character can be used to identify a comment
[SQL injection Cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## Finding columns with a useful data type
- A SQL injection UNION attack enables you to retrieve the results from an injected query.
- Interesting data that you want to retrieve is normally in string form
- This means you need to find one or more columns in the original query results whose data type is, or is compatible with, string data
- After you determine the number of required columns, you can probe each column to test whether it can hold string data.
- To test, submit a series of `UNION SELECT` payloads that place a string value into each column in turn, for example
```SQL
'UNION SELECT 'a',NULL,NULL,NULL--
'UNION SELECT NULL,'a',NULL,NULL--
'UNION SELECT NULL,NULL,'a',NULL--
'UNION SELECT NULL,NULL,NULL,'a'--
```
- If the column data is not compatible with string data, the injected query will cause a database error such as 
- `Conversion failed when converting the varchar 'a' to data type int.`
- If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data 
## Using a SQL injection UNION attack to retrieve interesting data
- After determining the number of columns returned by the original query and found which columns can hold string data, next step is to retrieve data
- Suppose the following
	- The original query returns 2 columns, both of which can hold string data
	- The injection point is a quoted string within the `WHERE` clause
	- The database contains a table called `users` with the columns `username` and `password`
- In this example, you can retrieve the contents of the `users` table by submitting the input
`'UNION SELECT username, password FROM users--`
- In order to perform this attack, you need to know that there is a table called `users` with 2 columns called `username` and `password`
- without this info, you would have to guess the names of the tables and columns
- All modern databases provide ways to examine the databases structure, and determine what tables and columns they contain

## Retrieving multiple values within a single column
- The previous example may only return a single column
- Retrieving multiple values together within a single column is possible by concatenating the values together.
- Including a separator will let you distinguish the combined values. Oracle example below.
` 'UNION SELECT username || '~' || password FROM users--`
- double pipe `||` is string concatenation on Oracle
- This query concatenates together the values `username` and  `password` fields, separated by the `'~'`. and results in the following.
```html
... 
administrator~s3cure 
wiener~peter 
carlos~montoya 
...
```
- Different databases use different syntax to perform string concatenation 










