# SELECT

```sql
select * from users;
```
- Select all * data from the table "users"

```sql
select username, password from users;
```
- returns the columns username and password from the table "users"

```sql
select * from users LIMIT 1;
```
- returns  1 full row from the table 'users'

```sql
select * from users LIMIT 1,1;
select * from users LIMIT 2,1;
```
- first number tell the database how many results to skip
- second number tells the database how many rows to return
- LIMIT 1,1 forces the query to skip the first result
- LIMIT 2,1 forces the query to skip the first two results

```sql
select * from users where username='admin';
```
- Only returns the rows where the username is equal to admin

```sql
select * from users where username != 'admin';
```
- Only returns the rows where the username is NOT equal to admin

```sql
select * from users where username='admin' or username='jon';
```
- Only returns the rows where the username is either equal to admin or jon

```sql
select * from users where username='admin' and password='p4ssword';
```
- return the rows where the username is admin and password is p4ssword

```sql 
select * from users where username like 'a%';
```
- returns any rows with username beginning with the letter a

```sql
select * from users where username like '%n';
```
- Returns any rows with username ending with the letter n

```sql
select * from users where username like '%mi%';
```
- Returns any rows with a username containing the characters mi within it

# UNION
```sql
SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
```
- Gathers results from the customers and suppliers tables and puts them in one result set

# INSERT
```sql
insert into users (username, password) values ('bob', 'password')';
```
- insert command to insert a data into data base 
- (username, password) provides the columns we are providing data for
- (bob, password) provides the data for those columns
# UPDATE
```sql
update users SET username='root', password='pass123' where username='admin';
```
- update tells the database to update one or more of the data within a table
- specify the table to update using "update %tablename%" SET. Then select field/s to update, comma-separated like 'username='root',password='pass123'
- then specify which rows to update using the where clause "where username='admin'""
# DELETE
```sql
delete from users where username='martin';
```
- deletes table and/or rows specified similar to Select
- delete from the table 'users' and from the column 'username' where the username is martin

```sql
delete from users;
```
- no where clause being used deletes all the data in the table




