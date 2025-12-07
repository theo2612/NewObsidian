[[https]]://pwn.college/cse365-f2023/talking-web
# URI - syntax
```http
<scheme>:<authority>/<path>?<query>#<fragment>
```
# Examples
```http
foo://example.com:8042/over/there?test=bar#nose
ftp://ftp.ietf.org/rfc/rfc1808.txt
mailto:doupe@asu.edu
https://example.com/test/example:1.html?/adam
```

URI - Reserved Characters
``: / ? # [ ] @ ! $ & ' ( ) * + , ; =``

URI - Percent Encoding
- Must be used to encode anything that is not of the following
- Alpha [a - zA - Z]
- Digit [0 - 9]
``- . _ ~``
- Encode a byte outside the range with percent sign (%) followed by hexadecimal representation of byte
- man ascii for ascii table
- & -> %26
- % -> %25
- ``<space>`` -> %20
- fixing previous example
```html
https://example.com/test/example:1.html?/adam
https://example.com/text/example%3A1.html?%2Fadam
```

URI - Absolute vs Relative
- URI can specify the absolute location of the resource
	- `http://example.com/text/help.html`
- Or the URI can specify a location relative to the current resource
	- Relative to the current network-path (scheme)
		- `example.com/example/demo.html`
	- Relative to the current directory
		- `/test/help.html`
	- Relative to the current authority and path
		- `../../people.html`
- Context is important in all cases
	- `http://localhost:8080/test`

# Hypertext Transport Protocol
- Protocol for how a web client can request a resource from a web server
- Based on TCP, uses port 80 by default
- Version 1.0
	- Defined in RFC 1945 (May 1996)
- Version 1.1
	- Defined in RFC 2616 (June 1999)
- Version 2.0
	- Based on SPDY, Defined

# HTTP - Overview
- Server
	- Listens for incoming TCP connections
- Client
	- Opens TCP connection to the server
	- Sends request to the server
- Server
	- Reads request
	- Sends response

# Requests
- An HTTP request consists of
	- method
	- resource (derived from the URI)
	- protocol version
	- client information
	- body (optional)
- Syntax
	- The method that the client wants applied to the resource
	- Common Methods
		- GET - Request transfer of the entity referred to by the URI
		- POST - Ask the server to process the included body as "data" associated with the resource identified by the URI
		- PUT - Request that the enclosed entity be stored under the supplied URI
		- HEAD - Identical to GET except server **must not** return a body
- Example
	- Start line, followed by headers, followed by body
		- Each line separated by CRLF
	- Headers separated by body via empty line (just CRLF)
	GET / HTTP/1.1
	User-Agent: curl/7.37.1
	Host: \www.google.com
	Accept: \*/*

# Responses
- An HTTP response consists of
	- protocol version
	- status code
	- short reason
	- headers
	- body
- Syntax
	- Status line, followed by headers, followed by body
		- Each line separated by CRLF
	- Headers separated by body via empty line (just CRLF)
	- Almost the same overall structure as request
- Status Codes
	- 1## - Informational: request received, continuing to process
	- 2## - Successful: request received, understood, and accepted
	- 3## - Redirection: user agent needs to take further action to fulfill the request
	- 4## - Client error: request cannot be fulfilled or error in request
	- 5## - Server error: the server is aware that it has erred or is incapable of performing the request

# Maintaining State
- HTTP is a stateless protocol
- However, to write a web application we would like maintain state and link requests together
- The goal is to create a "session" so that the web application can link requests to the same user
	- Allows Authentication
	- Rich, full applications
- Three ways this can be achieved
	- Embedding information in URLs
	- Using hidden fields in forms
	- Using cookies

- Embedding information in Cookies
	- Cookies are state information that is passed by a web server and user agent
		- Server initiates the start of a session by asking the user agent to store a cookie
		- Server of user agent can terminate the session
	- Cookies are name-value pairs (separated by "=")
	- Server includes the "Set-Cookie" header field in a HTTP response
		- `Set-Cookie: USER=foo;`
	- User agent will then send the cookie back to the server using the "Cookie" header on further requests to the server
		- `Cookie: USER=foo;
	- Server can ask for multiple cookies to be stored on the client, using multiple `Set-Cookie` headers
		- `Set-Cookie: USER=foo;`
		- `Set-Cookie: lang=en=us;`
	-  Server can send several attributes on the cookie, the attributes are included in the Set-Cookie header line, after the cookie itself, separated by `;`
		- `Path`
			- Specifies the path of the URI of the web server that the cookies are valid
		- `Domain`
			- Specifies the subdomains that the cookie is valid
		- `Expires` or `Max-Age`
			- Used to define the lifetime of the cookie, of how long the cookie should be valid
	- The server can request the deletion of cookies by setting the `expires` cookie attribute to a date in the past
		- User agent should then delete cookie with that name
		- `Set-Cookie: USER=foo; expires=Thu, 1-Jan-2015 16:11:12 GMT;`
	- User agent is responsible for following the server's policies
		- Expiring Cookies
		- Restricting cookies to the proper domains and paths
	- However, user agent is free to delete cookies at any time
		- Space and storage restrictions
		- User decides to clear cookies












