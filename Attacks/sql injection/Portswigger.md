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



