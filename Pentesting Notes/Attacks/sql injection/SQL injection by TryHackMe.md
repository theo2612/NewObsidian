

```html
https://website.thm/blog?id=1
```
- Vulnerable example This web address blog entry comes from the id parameter 

```SQL 
SELECT * from blog where id=1 and private=0 LIMIT 1;
```
- The web app may use an SQL statement that looks like the above
- Return all from the table 'blog' where the id is 1 and the private column is 0 or able to be viewed by the public and limits the results to only one match

```http
https://website.thm/blog?id=2'--
```
- Assume the above is locked as private
- adding '-- would produce the following SQL statement
```SQL
SELECT * from blog where id=2;-- and private=0 LIMIT 1;
```
- Semicolon in URL ends the the end of the SQL statement
- 2 dashes cause everything afterward to be treated as as comment
- And then runs the following
```sql
SELECT * from blog where id=2;--
```
- This returns the article with an id of 2, set to public or not
- 





