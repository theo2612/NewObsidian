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












