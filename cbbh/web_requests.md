# Web Requests Notes

## Breakdown of an URL

- scheme - the http(s):// - telling the system what type of protocol is being used to request information
- user info - admin:password@ - the user information, specifically the user and password to login
- Host - inlanefreight.com - the domain name of the application
- Port - :80 - the port the request is requested on
- Path - /index.php - the URI pointing to the filename on the application
- Query String - ?login=true - the arguments on the application being used, in this case showing that the login variable is set to true
- Fragments - #status - helps point where on the file to be on the webpage, this case on the status fragment

## HTTP Flow
1. request goes, a DNS server is requested to resolve the domain name to an IP
2. DNS server sends back the IP
3. the request is made against the IP and the URI
4. the server responds with that information

## Tools

### curl commands
```
req
curl inlanefreight.com
download file
curl -O inlanefreight.com/index.html
help
curl -h
```

## HTTPS 

### Flow
1. req to application on port 80
2. redirect, 301
3. connect with port 443, https, client hello
4. server hello, with server key exchange
5. client key exchange, with encrypted handshake
6. server encrypted handshake finalized
7. connection is established and request to URI is provided

### curl for HTTPS
```
curl -k https://inlanefreight.com
```

## HTTP Requests and Responses








## Cheat Sheet
| Command | Description |
|:--------|:------------|
| curl -h | cURL help menu |
| curl inlanefreight.com|Basic GET request|
