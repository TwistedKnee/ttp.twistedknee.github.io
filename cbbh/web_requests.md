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

```
curl inlanefreight.com -v
```

Access DevTools
[CTRL+SHIFT+I] or simply click [F12]




## Cheat Sheet
| Command | Description |
|:--------|:------------|
| curl -h | cURL help menu |
| curl inlanefreight.com|Basic GET request|
|curl -s -O inlanefreight.com/index.html|Download file|
| curl -k https://inlanefreight.com 	|Skip HTTPS (SSL) certificate validation|
| curl inlanefreight.com -v 	|Print full HTTP request/response details|
| curl -I https://www.inlanefreight.com 	|Send HEAD request (only prints response headers)|
| curl -i https://www.inlanefreight.com 	|Print response headers and response body|
| curl https://www.inlanefreight.com -A 'Mozilla/5.0' 	|Set User-Agent header|
| curl -u admin:admin http://<SERVER_IP>:<PORT>/ 	|Set HTTP basic authorization credentials|
| curl http://admin:admin@<SERVER_IP>:<PORT>/ 	|Pass HTTP basic authorization credentials in the URL|
| curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/ 	|Set request header||
| curl 'http://<SERVER_IP>:<PORT>/search.php?search=le' 	|Pass GET parameters|
| curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/ 	|Send POST request with POST data|
| curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/ 	|Set request cookies|
| curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php 	|Send POST request with JSON data|

### APIs
|Command | Description|
|:--------|:------------|
|curl http://<SERVER_IP>:<PORT>/api.php/city/london 	|Read entry|
| curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq 	|Read all entries|
| curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json' 	|Create (add) entry|
| curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json' |	Update (modify) entry|
| curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City |	Delete entry|

### Browser DevTools
|Command | Description|
|:--------|:------------|
| [CTRL+SHIFT+I] or [F12] 	|Show devtools|
| [CTRL+SHIFT+E] 	|Show Network tab|
| [CTRL+SHIFT+K] 	|Show Console tab|
